use crate::{
    keyring, ClientMessage, FramedConnection, Identity, Receiver, Result, Sender, ServerMessage,
};
use futures::StreamExt;
use slog::{debug, error, info, o, Discard, Drain, Level, Logger};
use sodiumoxide::crypto::{box_, secretbox};
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::select;
use tokio::sync::mpsc;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum Event {
    Connected,
    ChatMessage {
        chat_name: Option<String>,
        recipients: Option<Vec<String>>,
        message: String,
    },
    ContactFound {
        contact: keyring::Contact,
        chat_name: Option<String>,
    },
    Error(String),
}

pub struct ClientConnector<T: AsyncRead + AsyncWrite + std::marker::Unpin> {
    identity: keyring::Identity,
    name: String,
    peers: HashMap<String, (box_::PublicKey, Option<keyring::Contact>)>,
    event_sender: Sender<Event>,
    connector_receiver: Receiver<Event>,
    connector_sender: Sender<Event>,
    event_receiver: Receiver<Event>,
    pub connection: Option<FramedConnection<T>>,
    server_key: Option<secretbox::Key>,
    log: Logger,
}

impl<T: AsyncRead + AsyncWrite + std::marker::Unpin> ClientConnector<T> {
    pub fn new(identity: &keyring::Identity, name: &str, log: Option<Logger>) -> Self {
        let (mut event_sender, connector_receiver) = mpsc::unbounded_channel();
        let (connector_sender, mut event_receiver) = mpsc::unbounded_channel();
        let mut log = match log {
            Some(logger) => logger,
            None => Logger::root(Discard, o!()),
        };
        log = log.new(o!("name" => name.to_string()));
        Self {
            identity: identity.clone(),
            name: name.into(),
            peers: HashMap::new(),
            event_sender,
            connector_receiver,
            connector_sender,
            event_receiver,
            connection: None,
            server_key: None,
            log,
        }
    }

    pub async fn connect(&mut self, stream: T, keyring: &keyring::KeyRing) -> Result<()> {
        self.connection = Some(FramedConnection::new(stream));
        self.send_identity().await?;
        // Next messages should be Peers, followed by a ChatInvite
        loop {
            debug!(self.log, "Waiting for Peers message...");
            match self.next_message().await {
                // Handle the Peers message
                Some(Ok(ServerMessage::Peers(peers))) => {
                    debug!(self.log, "Got Peers message, peers = {:?}", peers);
                    if peers.is_empty() {
                        debug!(self.log, "Generating server key");
                        self.server_key = Some(secretbox::gen_key());
                    } else {
                        for peer in peers {
                            debug!(self.log, "Adding peer {}", peer.name);
                            self.add_peer(keyring, &peer)?;
                        }
                    }
                    break;
                }
                _ => {
                    // TODO: Log(?) and ignore any other message
                    unimplemented!()
                }
            }
        }

        Ok(())
    }

    pub async fn wait_for_server_key(&mut self) -> Result<()> {
        if self.server_key.is_some() {
            Err("Already have server key")?;
        }

        debug!(self.log, "Waiting for ChatInvite message...");
        loop {
            let message = self.next_message().await;
            debug!(self.log, "Got {:?}", message);
            match message {
                // Handle the ChatInvite
                Some(Ok(ServerMessage::ClientMessage {
                    sender,
                    recipients: _,
                    message,
                    nonce,
                })) => {
                    // Try to decrypt the outer wrapper using my secret key
                    // TODO: Make this a function
                    let client_message_opt = match sender {
                        Some(sender) => {
                            debug!(self.log, "Looking up sender {}", sender);
                            match self.peers.get(&sender) {
                                Some((key, Some(contact))) => {
                                    debug!(self.log, "Sender is {:?}", contact);
                                    match box_::open(
                                        &message,
                                        &box_::Nonce::from_slice(&nonce).unwrap(),
                                        &key,
                                        &self.identity.secret_key,
                                    ) {
                                        Ok(decrypted) => {
                                            Some(rmp_serde::from_read_ref(&decrypted)?)
                                        }
                                        Err(_) => {
                                            // TODO: Not sure what to do here. Log?
                                            self.connector_sender.send(Event::Error(
                                                "Error decrypting message".into(),
                                            ))?;
                                            None
                                        }
                                    }
                                }
                                // If we can't find the sender in our peers list, or if they're not in our contacts,
                                // we can't authenticate the message
                                _ => None,
                            }
                        }
                        None => None,
                    };
                    debug!(
                        self.log,
                        "Unwrapped client message is {:?}", client_message_opt
                    );
                    if let Some(client_message) = client_message_opt {
                        match client_message {
                            ClientMessage::ChatInvite {
                                name,
                                participants: _,
                                key,
                            } => match name {
                                None => {
                                    match self.server_key {
                                        Some(_) => {
                                            // TODO: What do we do if we already have a key?
                                            panic!("We already have a key");
                                        }
                                        None => self.server_key = Some(key),
                                    }
                                }
                                _ => unimplemented!(),
                            },
                            _ => unimplemented!(), // TODO: Unexpected message type
                        }
                    }
                }
                _ => unimplemented!(),
            }
        }
    }

    pub async fn recv_event(&mut self) -> Option<Event> {
        self.event_receiver.recv().await
    }

    pub async fn send_event(&mut self, event: Event) -> Result<()> {
        Ok(self.event_sender.send(event)?)
    }

    pub async fn send_identity(&mut self) -> Result<()> {
        debug!(self.log, "Sending identity to server");
        Ok(self
            .send_message(ServerMessage::identity(
                &self.name.clone(),
                &self.identity.public_key,
            ))
            .await?)
    }

    pub async fn send_chat_invite(
        &mut self,
        public_key: &box_::PublicKey,
        recipient: &str,
    ) -> Result<()> {
        debug!(self.log, "Sending chat invite");
        match self.server_key {
            Some(ref server_key) => {
                let server_key = server_key.clone();
                Ok(self
                    .send_message(ServerMessage::new_chat_invite(
                        Some(self.name.clone()),
                        None,
                        public_key,
                        &self.identity.secret_key,
                        Some(vec![recipient.into()]),
                        &server_key,
                    )?)
                    .await?)
            }
            None => Err("Don't have server key yet")?,
        }
    }

    pub async fn send_message(&mut self, message: ServerMessage) -> Result<()> {
        match &mut self.connection {
            Some(connection) => Ok(connection.send(message).await?),
            None => Err("Must call connect first")?,
        }
    }

    pub async fn next_message(&mut self) -> Option<Result<ServerMessage>> {
        match &mut self.connection {
            Some(connection) => connection.next().await.map(|r| r.map_err(|e| e)),
            None => Some(Err("Must call connect first".into())),
        }
    }

    pub async fn handle_events(
        mut self,
        keyring: &keyring::KeyRing,
        mut event_sender: Sender<Event>,
        mut event_receiver: Receiver<Event>,
    ) -> Result<()> {
        // Event loop
        loop {
            select! {
                // Read from network
                message_opt = self.next_message() => {
                    match message_opt {
                        Some(result) => self.handle_network_message(
                            keyring,
                            &mut event_sender,
                            result?
                        ).await?,
                        None => break,
                    }
                },

                // Read events from client
                event = event_receiver.next() => match event {
                    Some(Event::ChatMessage { chat_name, recipients, message }) => unimplemented!(),
                    Some(Event::ContactFound { contact, chat_name }) => unimplemented!(),
                    Some(_) => unimplemented!(),
                    None => break,
                }

            }
        }

        Ok(())
    }

    fn add_peer(&mut self, keyring: &keyring::KeyRing, identity: &Identity) -> Result<()> {
        let contact = keyring
            .find_contact(&identity.public_key)
            .map(|c| c.clone());
        if let Some(ref contact) = contact {
            self.event_sender.send(Event::ContactFound {
                contact: contact.clone(),
                chat_name: None,
            })?;
        }
        self.peers
            .insert(identity.name.clone(), (identity.public_key, contact));
        Ok(())
    }

    async fn handle_network_message(
        &mut self,
        keyring: &keyring::KeyRing,
        event_sender: &mut Sender<Event>,
        message: ServerMessage,
    ) -> Result<()> {
        match message {
            ServerMessage::Identity(_) => panic!("Unexpected Identity message"),
            ServerMessage::ClientMessage {
                sender,
                recipients: _,
                message,
                nonce,
            } => match self.server_key {
                Some(ref server_key) => {
                    let nonce = match secretbox::Nonce::from_slice(&nonce) {
                        Some(nonce) => nonce,
                        None => Err("Error converting nonce from bytes in message")?,
                    };
                    match secretbox::open(&message, &nonce, server_key) {
                        Ok(plaintext) => {
                            println!(
                                "from {}: {}",
                                sender.unwrap_or("unknown sender".into()),
                                std::str::from_utf8(&plaintext)?
                            );
                            Ok(())
                        }
                        Err(_) => Err(format!("Error decrypting message"))?,
                    }
                }
                None => Err("Unable to decrypt ClientMessage: no server key")?,
            },
            ServerMessage::Peers(peer_list) => {
                for peer in peer_list {
                    self.add_peer(keyring, &peer)?;
                }
                Ok(())
            }
            ServerMessage::PeerJoined(identity) => Ok(self.add_peer(keyring, &identity)?),
            ServerMessage::PeerDisconnected(name) => {
                self.peers.remove(&name);
                Ok(())
            }
            ServerMessage::IdentityTaken { name } => {
                println!("Name {} is taken, please use a different one", name);
                Ok(())
            }
            ServerMessage::ErrorMessage(error) => {
                println!("error: {}", error);
                Ok(())
            }
            something => panic!("Unexpected message: {:?}", something),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use std::path::Path;
    use tokio::net::{UnixListener, UnixStream};
    use tokio_serde::formats::SymmetricalMessagePack;

    // Connect a client to a Unix socket
    async fn connect<P: AsRef<Path>>(path: P, name: &str) -> Result<ClientConnector<UnixStream>> {
        loop {
            match UnixStream::connect(&path).await {
                Ok(stream) => {
                    let keyring = keyring::KeyRing::default();
                    let mut client_connector =
                        ClientConnector::new(&keyring::Identity::new(name), name, None);
                    client_connector.connect(stream, &keyring).await?;
                    return Ok(client_connector);
                }
                Err(error) => std::thread::sleep(std::time::Duration::from_secs(1)),
            }
        }
    }

    async fn server_loop(path: String, sender: Sender<ServerMessage>) -> Result<()> {
        let listener = UnixListener::bind(path)?;
        let (stream, _) = listener.accept().await?;
        let mut framed = tokio_serde::SymmetricallyFramed::new(
            tokio_util::codec::Framed::new(stream, tokio_util::codec::BytesCodec::new()),
            SymmetricalMessagePack::<ServerMessage>::default(),
        );
        loop {
            match framed.next().await {
                Some(msg) => sender.send(msg?),
                None => return Ok(()),
            };
        }
    }

    // #[tokio::test]
    async fn something() -> Result<()> {
        let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(6).collect();
        let path: String = "/tmp/.socket_".to_owned() + &rand_string;
        // Make sure the file isn't there
        std::fs::remove_file(path.clone());
        let (mut sender, receiver) = mpsc::unbounded_channel();
        let client_connector = connect(path.clone(), "foo").await?;
        tokio::task::spawn(server_loop(path, sender));
        Ok(())
    }
}

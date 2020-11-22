use crate::{
    keyring, ClientMessage, FramedConnection, Identity, Receiver, Result, Sender, ServerMessage,
};
use futures::StreamExt;
use slog::{debug, error, o, Discard, Logger};
use sodiumoxide::crypto::{box_, secretbox};
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::select;
use tokio::sync::mpsc;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Peer {
    identity: Identity,
    contact: Option<keyring::Contact>,
}

impl Peer {
    fn new(identity: Identity, contact: Option<keyring::Contact>) -> Self {
        Self { identity, contact }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum Event {
    Connected,
    ChatMessage {
        chat_name: Option<String>,
        recipients: Option<Vec<String>>,
        message: String,
    },
    PeerList(Vec<Peer>),
    ContactFound {
        contact: keyring::Contact,
        chat_name: Option<String>,
    },
    Error(String),
}

pub struct ClientConnector<T: AsyncRead + AsyncWrite + std::marker::Unpin> {
    identity: keyring::Identity,
    name: String,
    peers: HashMap<String, Peer>,
    event_sender: Sender<Event>,
    connector_receiver: Receiver<Event>,
    connector_sender: Sender<Event>,
    event_receiver: Option<Receiver<Event>>,
    pub connection: Option<FramedConnection<T>>,
    chat_keys: HashMap<Option<String>, secretbox::Key>,
    log: Logger,
}

impl<T: AsyncRead + AsyncWrite + std::marker::Unpin> ClientConnector<T> {
    pub fn new(identity: &keyring::Identity, name: &str, log: Option<Logger>) -> Self {
        let (event_sender, connector_receiver) = mpsc::unbounded_channel();
        let (connector_sender, event_receiver) = mpsc::unbounded_channel();
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
            event_receiver: Some(event_receiver),
            connection: None,
            chat_keys: HashMap::new(),
            log,
        }
    }

    pub async fn connect(&mut self, stream: T) -> Result<()> {
        self.connection = Some(FramedConnection::new(stream));
        // self.send_identity().await?;

        Ok(())
    }

    pub async fn wait_for_peers_message(&mut self, keyring: &keyring::KeyRing) -> Result<()> {
        loop {
            debug!(self.log, "Waiting for Peers message...");
            match self.next_message().await {
                // Handle the Peers message
                Some(Ok(ServerMessage::Peers(peers))) => {
                    debug!(self.log, "Got Peers message, peers = {:?}", peers);
                    if peers.is_empty() {
                        debug!(self.log, "Generating server key");
                        self.chat_keys.insert(None, secretbox::gen_key());
                    } else {
                        for peer in peers {
                            debug!(self.log, "Adding peer {}", peer.name);
                            self.add_peer(keyring, &peer)?;
                        }
                    }
                    let peer_list =
                        Event::PeerList(self.peers.values().map(|p| p.clone()).collect());
                    debug!(self.log, "Sending PeerList event: {:?}", peer_list);
                    self.event_sender.send(peer_list)?;
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

    fn server_key(&self) -> Option<&secretbox::Key> {
        self.chat_keys.get(&None)
    }

    async fn decrypt_chat_invite(
        &self,
        sender: &str,
        message: &[u8],
        nonce: &box_::Nonce,
    ) -> Option<ClientMessage> {
        debug!(self.log, "Looking up sender {}", sender);
        match self.peers.get(sender) {
            Some(peer) => {
                debug!(self.log, "Sender is {:?}", peer.contact);
                match box_::open(
                    &message,
                    nonce,
                    &peer.identity.public_key,
                    &self.identity.secret_key,
                ) {
                    Ok(decrypted) => match rmp_serde::from_read_ref(&decrypted) {
                        Ok(message) => Some(message),
                        Err(error) => {
                            error!(self.log, "Error decoding message: {}", error);
                            None
                        }
                    },
                    Err(_) => {
                        error!(self.log, "Error decrypting message");
                        None
                    }
                }
            }
            // If we can't find the sender in our peers list, or if they're not in our contacts,
            // we can't authenticate the message
            _ => None,
        }
    }

    pub async fn wait_for_server_key(&mut self) -> Result<()> {
        if self.server_key().is_some() {
            Err("Already have server key")?;
        }

        debug!(self.log, "Waiting for ChatInvite message...");
        loop {
            let message = self.next_message().await;
            debug!(self.log, "Got {:?}", message);
            match message {
                // Handle the ChatInvite
                Some(Ok(ServerMessage::ChatInvite {
                    sender,
                    recipient: _,
                    message,
                    nonce,
                })) => {
                    // Try to decrypt the outer wrapper using my secret key
                    // TODO: Make this a function
                    let client_message_opt = match sender {
                        Some(sender) => self.decrypt_chat_invite(&sender, &message, &nonce).await,
                        None => None,
                    };
                    debug!(
                        self.log,
                        "Unwrapped client message is {:?}", client_message_opt
                    );
                    if let Some(client_message) = client_message_opt {
                        match client_message {
                            ClientMessage::ChatInvite { name, key } => match name {
                                None => {
                                    match self.server_key() {
                                        Some(_) => {
                                            // TODO: What do we do if we already have a key?
                                            panic!("We already have a key");
                                        }
                                        None => {
                                            self.chat_keys.insert(None, key);
                                            break;
                                        }
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

        Ok(())
    }

    pub async fn recv_event(&mut self) -> Option<Event> {
        self.connector_receiver.recv().await
    }

    pub fn send_event(&mut self, event: Event) -> Result<()> {
        Ok(self.connector_sender.send(event)?)
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
        chat_name: Option<String>,
    ) -> Result<()> {
        debug!(self.log, "Sending chat invite");
        match self.chat_keys.get(&chat_name) {
            Some(chat_key) => {
                let chat_key = chat_key.clone();
                Ok(self
                    .send_message(ServerMessage::new_chat_invite(
                        None,
                        public_key,
                        &self.identity.secret_key,
                        recipient,
                        &chat_key,
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

    pub async fn handle_events(mut self, keyring: &keyring::KeyRing) -> Result<()> {
        let mut event_receiver = self.event_receiver.take().unwrap();
        // Event loop
        loop {
            select! {
                // Read from network
                message_opt = self.next_message() => {
                    match message_opt {
                        Some(result) => self.handle_network_message(
                            keyring,
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
        self.peers
            .insert(identity.name.clone(), Peer::new(identity.clone(), contact));
        Ok(())
    }

    async fn handle_network_message(
        &mut self,
        keyring: &keyring::KeyRing,
        message: ServerMessage,
    ) -> Result<()> {
        match message {
            ServerMessage::Identity(_) => panic!("Unexpected Identity message"),
            ServerMessage::ClientMessage {
                sender,
                recipients: _,
                message,
                nonce,
            } => match self.server_key() {
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
    use futures::SinkExt;
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use slog::{debug, o, Drain, Logger};
    use std::path::Path;
    use tokio::net::{UnixListener, UnixStream};
    use tokio_serde::formats::SymmetricalMessagePack;

    fn get_logger() -> Logger {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();

        slog::Logger::root(drain, o!())
    }

    // Connect a client to a Unix socket
    async fn connect<P: AsRef<Path>>(
        path: P,
        name: &str,
        log: Logger,
    ) -> Result<ClientConnector<UnixStream>> {
        loop {
            debug!(log, "Connecting to unix path");
            match UnixStream::connect(&path).await {
                Ok(stream) => {
                    let mut client_connector =
                        ClientConnector::new(&keyring::Identity::new(name), name, Some(log));
                    client_connector.connect(stream).await?;
                    return Ok(client_connector);
                }
                Err(error) => {
                    debug!(log, "UnixStream::connect got error: {:?}", error);
                    std::thread::sleep(std::time::Duration::from_secs(1));
                }
            }
        }
    }

    async fn server_loop(
        path: String,
        sender: Sender<ServerMessage>,
        mut receiver: Receiver<ServerMessage>,
        log: Logger,
    ) -> Result<()> {
        debug!(log, "Binding to {:?}", path);
        let listener = UnixListener::bind(path)?;
        debug!(log, "Calling accept");
        let (stream, _) = listener.accept().await?;
        let mut framed = tokio_serde::SymmetricallyFramed::new(
            tokio_util::codec::Framed::new(stream, tokio_util::codec::BytesCodec::new()),
            SymmetricalMessagePack::<ServerMessage>::default(),
        );
        loop {
            select! {
                message_opt =  framed.next() => match message_opt {
                    Some(msg) => sender.send(msg?)?,
                    None => return Ok(()),
                },
                message_opt = receiver.recv() => match message_opt {
                    Some(msg) => framed.send(msg).await?,
                    None => return Ok(()),
                }
            }
        }

        Ok(())
    }

    fn setup() -> Result<
        ((
            Logger,
            String,
            Sender<ServerMessage>,
            Receiver<ServerMessage>,
        )),
    > {
        let log = get_logger();
        let rand_string: String = thread_rng().sample_iter(&Alphanumeric).take(6).collect();
        let path: String = "/tmp/.socket_".to_owned() + &rand_string;
        // Make sure the file isn't there
        let _ = std::fs::remove_file(path.clone());
        let (server_sender, mut client_receiver) = mpsc::unbounded_channel();
        let (client_sender, server_receiver) = mpsc::unbounded_channel();
        tokio::task::spawn(server_loop(
            path.clone(),
            server_sender,
            server_receiver,
            log.new(o!(())),
        ));

        // Wait for server
        std::thread::sleep(std::time::Duration::from_secs(1));

        Ok((log, path, client_sender, client_receiver))
    }

    fn new_identity(name: &str) -> (Identity, box_::SecretKey) {
        let (public_key, secret_key) = box_::gen_keypair();
        (Identity::new(name, &public_key), secret_key)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connector_generates_key_with_no_peers() -> Result<()> {
        let (log, path, client_sender, mut client_receiver) = setup()?;

        let mut client_connector = connect(path.clone(), "foo", log.new(o!())).await?;
        client_connector.send_identity().await?;
        client_receiver.recv().await; // Identity

        // Send empty peers message
        client_sender.send(ServerMessage::Peers(vec![]))?;

        // Receive peers message
        let keyring = keyring::KeyRing::default();
        client_connector.wait_for_peers_message(&keyring).await?;

        assert!(client_connector.server_key().is_some());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connector_generates_peerlist_event_with_peers_present() -> Result<()> {
        let (log, path, client_sender, mut client_receiver) = setup()?;

        let mut client_connector = connect(path.clone(), "foo", log.new(o!())).await?;
        client_connector.send_identity().await?;
        client_receiver.recv().await; // Identity

        // Send peers message
        let (bar, _) = new_identity("bar");
        let (baz, _) = new_identity("baz");
        client_sender.send(ServerMessage::Peers(vec![bar.clone(), baz.clone()]))?;

        // Receive peers message
        let keyring = keyring::KeyRing::default();
        client_connector.wait_for_peers_message(&keyring).await?;

        debug!(log, "Waiting for event");
        match client_connector.recv_event().await {
            Some(Event::PeerList(peer_list)) => {
                assert_eq!(2, peer_list.len());
                let identity_list = peer_list
                    .iter()
                    .map(|p| p.identity.clone())
                    .collect::<Vec<Identity>>();
                assert!(identity_list.contains(&bar));
                assert!(identity_list.contains(&baz));
            }
            _ => assert!(false),
        };

        // Connector shouldn't have a server key (yet)
        assert!(client_connector.server_key().is_none());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connector_uses_server_key_from_chat_invite() -> Result<()> {
        let (log, path, client_sender, mut client_receiver) = setup()?;

        let mut client_connector = connect(path.clone(), "foo", log.new(o!())).await?;
        client_connector.send_identity().await?;
        client_receiver.recv().await; // Identity

        // Send peers message
        let (bar, secret_key) = new_identity("bar");
        let (baz, _) = new_identity("baz");
        client_sender.send(ServerMessage::Peers(vec![bar.clone(), baz.clone()]))?;

        // Receive peers message
        let keyring = keyring::KeyRing::default();
        client_connector.wait_for_peers_message(&keyring).await?;
        let _peer_list_event = client_connector.recv_event().await;

        let server_key = secretbox::gen_key();
        let public_key = &client_connector.identity.public_key;
        let mut chat_invite =
            ServerMessage::new_chat_invite(None, public_key, &secret_key, "foo", &server_key)?;
        if let ServerMessage::ChatInvite {
            ref mut sender,
            ref recipient,
            ref message,
            ref nonce,
        } = chat_invite
        {
            *sender = Some("bar".into());
        };
        client_sender.send(chat_invite)?;
        client_connector.wait_for_server_key().await?;

        assert!(client_connector.server_key().is_some());
        assert_eq!(server_key, *client_connector.server_key().unwrap());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connector_handles_same_server_key_sent_multiple_times() -> Result<()> {
        let (log, path, client_sender, mut client_receiver) = setup()?;

        let mut client_connector = connect(path.clone(), "foo", log.new(o!())).await?;
        client_connector.send_identity().await?;
        client_receiver.recv().await; // Identity

        // Send peers message
        let (bar, bar_secret_key) = new_identity("bar");
        let (baz, baz_secret_key) = new_identity("baz");
        client_sender.send(ServerMessage::Peers(vec![bar.clone(), baz.clone()]))?;

        // Receive peers message
        let keyring = keyring::KeyRing::default();
        client_connector.wait_for_peers_message(&keyring).await?;
        let _peer_list_event = client_connector.recv_event().await;

        let server_key = secretbox::gen_key();
        let public_key = &client_connector.identity.public_key;
        let mut chat_invite =
            ServerMessage::new_chat_invite(None, public_key, &bar_secret_key, "foo", &server_key)?;
        if let ServerMessage::ChatInvite {
            ref mut sender,
            ref recipient,
            ref message,
            ref nonce,
        } = chat_invite
        {
            *sender = Some("bar".into());
        };
        client_sender.send(chat_invite)?;
        client_connector.wait_for_server_key().await?;

        assert!(client_connector.server_key().is_some());
        assert_eq!(server_key, *client_connector.server_key().unwrap());

        Ok(())
    }
}

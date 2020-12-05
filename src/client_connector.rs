use crate::{
    keyring, ChatInvite, ChatMessage, ClientMessage, FramedConnection, Identity, Receiver, Result,
    Sender, ServerMessage,
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
        message: String,
    },
    PeerList(Vec<Peer>),
    ContactFound {
        contact: keyring::Contact,
        chat_name: Option<String>,
    },
    Error(String),
}

impl From<ChatMessage> for Event {
    fn from(chat_msg: ChatMessage) -> Self {
        Self::ChatMessage {
            chat_name: chat_msg.chat_name,
            message: chat_msg.message,
        }
    }
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
    chat_list: Vec<String>,
    chat_members: HashMap<String, Vec<String>>,
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
            chat_list: vec![],
            chat_members: HashMap::new(),
            log,
        }
    }

    pub async fn connect(&mut self, stream: T) -> Result<()> {
        self.connection = Some(FramedConnection::new(stream));

        Ok(())
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

    pub async fn create_chat(&mut self, chat_name: String, recipients: &[&str]) -> Result<()> {
        if self.server_key().is_none() {
            Err("Don't have server key")?;
        }

        if self.chat_list.contains(&chat_name) {
            return Err(format!("Chat name {} already exists", chat_name))?;
        }

        // Send CreateChat message to everyone
        self.send_message(ServerMessage::new_client_message(
            Some(self.peers.keys().map(|r| r.to_string()).collect()),
            &ClientMessage::new_create_chat_message(&chat_name),
            self.server_key().unwrap(),
        )?)
        .await?;

        let chat_key = secretbox::gen_key();

        // Add chat key
        self.chat_keys
            .insert(Some(chat_name.clone()), chat_key.clone());

        // Send chat invite to all recipients
        for recipient in recipients.iter() {
            match self.peers.get(&recipient.to_string()) {
                Some(peer) => {
                    let public_key = peer.identity.public_key;
                    self.send_message(ServerMessage::new_chat_invite(
                        Some(chat_name.clone().into()),
                        &public_key,
                        &self.identity.secret_key,
                        recipient,
                        &chat_key,
                    )?)
                    .await?
                }
                None => error!(self.log, "No public key found for recipient {}", recipient),
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
    ) -> Option<ChatInvite> {
        debug!(self.log, "Looking up sender {}", sender);
        match self.peers.get(sender) {
            Some(peer) => {
                debug!(self.log, "Sender is {:?}", peer.contact);
                match peer.contact {
                    Some(_) => {
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
                    None => None,
                }
            }
            // If we can't find the sender in our peers list, or if they're not in our contacts,
            // we can't authenticate the message
            _ => None,
        }
    }

    pub async fn recv_event(&mut self) -> Option<Event> {
        self.connector_receiver.recv().await
    }

    pub fn send_event(&mut self, event: Event) -> Result<()> {
        Ok(self.connector_sender.send(event)?)
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
            None => Err("Don't have chat key yet")?,
        }
    }

    pub async fn send_server_chat_message(
        &mut self,
        message: &str,
        recipients: Option<Vec<String>>,
    ) -> Result<()> {
        self._send_chat_message(None, message, recipients).await
    }

    pub async fn send_chat_message(&mut self, chat_name: &str, message: &str) -> Result<()> {
        let chat_members = match self.chat_members.get(chat_name) {
            Some(chat_members) => chat_members.clone(),
            None => Err(format!("Not member of chat {}", chat_name))?,
        };
        self._send_chat_message(Some(chat_name.to_string()), message, Some(chat_members))
            .await
    }

    async fn _send_chat_message(
        &mut self,
        chat_name: Option<String>,
        message: &str,
        recipients: Option<Vec<String>>,
    ) -> Result<()> {
        let chat_key = match self.chat_keys.get(&chat_name) {
            Some(chat_key) => chat_key.clone(),
            None => match chat_name {
                Some(ref chat_name) => Err(format!("No chat key found for {}", chat_name))?,
                None => Err("Server key not found")?,
            },
        };

        let server_key = match self.server_key() {
            Some(server_key) => server_key.clone(),
            None => Err("Server key not found")?,
        };

        self.send_message(ServerMessage::new_client_message(
            recipients,
            &ClientMessage::new_chat_message(chat_name, &chat_key, message)?,
            &server_key,
        )?)
        .await?;

        Ok(())
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
                    Some(Event::ChatMessage { chat_name, message }) => unimplemented!(),
                    Some(Event::ContactFound { contact, chat_name }) => unimplemented!(),
                    Some(_) => unimplemented!(),
                    None => break,
                }

            }
        }

        Ok(())
    }

    fn add_peer(&mut self, keyring: &keyring::KeyRing, identity: &Identity) -> Result<()> {
        // See if there's a corresponding contact
        let contact_opt = keyring.find_contact(&identity.public_key).cloned();

        // Add the peer
        self.peers.insert(
            identity.name.clone(),
            Peer::new(identity.clone(), contact_opt.clone()),
        );

        // If we found a contact, inform the client
        if let Some(contact) = contact_opt.clone() {
            self.send_event_to_client(Event::ContactFound {
                contact,
                chat_name: None,
            })?;
        }
        Ok(())
    }

    pub fn send_event_to_client(&mut self, event: Event) -> Result<()> {
        debug!(self.log, "Sending event {:?} to client", event);
        Ok(self.event_sender.send(event)?)
    }

    fn handle_client_message(&mut self, server_client_message: &ServerMessage) -> Result<()> {
        match self.server_key() {
            Some(server_key) => {
                let client_msg =
                    ServerMessage::get_client_message(&server_key, &server_client_message)?;
                match client_msg {
                    ClientMessage::CreateChat { chat_name } => unimplemented!(),
                    ClientMessage::ChatMessage {
                        ref chat_name,
                        message: _,
                        nonce: _,
                    } => match self.chat_keys.get(chat_name) {
                        Some(chat_key) => {
                            let chat_msg =
                                ClientMessage::decrypt_chat_message(chat_key, &client_msg)?;
                            self.send_event_to_client(chat_msg.into())?;
                            Ok(())
                        }
                        None => Err(format!(
                            "No chat key found for message from chat name {}",
                            chat_name.clone().unwrap()
                        ))?,
                    },
                }
            }
            None => Err("No server key found")?,
        }
    }

    async fn handle_chat_invite(
        &mut self,
        sender: Option<String>,
        message: &[u8],
        nonce: &box_::Nonce,
    ) -> Result<()> {
        // Try to decrypt the outer wrapper using my secret key
        let chat_invite_opt = match sender {
            Some(sender) => self.decrypt_chat_invite(&sender, &message, &nonce).await,
            None => None,
        };
        debug!(
            self.log,
            "Unwrapped client message is {:?}", chat_invite_opt
        );
        if let Some(ChatInvite { name, key }) = chat_invite_opt {
            match name {
                None => match self.chat_keys.get(&name) {
                    Some(_) => {
                        debug!(self.log, "Got ChatInvite when we already have key");
                        Ok(())
                    }
                    None => {
                        self.chat_keys.insert(name, key);
                        Ok(())
                    }
                },
                _ => unimplemented!(),
            }
        } else {
            Ok(())
        }
    }

    fn handle_peers_message(
        &mut self,
        keyring: &keyring::KeyRing,
        peer_list: &[Identity],
    ) -> Result<()> {
        debug!(self.log, "Got Peers message, peers = {:?}", peer_list);
        if peer_list.is_empty() {
            debug!(self.log, "Generating server key");
            self.chat_keys.insert(None, secretbox::gen_key());
        } else {
            for peer in peer_list {
                debug!(self.log, "Adding peer {}", peer.name);
                self.add_peer(keyring, &peer)?;
            }
        }
        self.send_event_to_client(Event::PeerList(self.peers.values().cloned().collect()))?;
        Ok(())
    }

    pub async fn handle_network_message(
        &mut self,
        keyring: &keyring::KeyRing,
        message: ServerMessage,
    ) -> Result<()> {
        match message {
            ServerMessage::Identity(_) => panic!("Unexpected Identity message"),
            server_client_message @ ServerMessage::ClientMessage { .. } => {
                self.handle_client_message(&server_client_message)
            }
            ServerMessage::Peers(peer_list) => self.handle_peers_message(keyring, &peer_list),
            ServerMessage::PeerJoined(identity) => self.add_peer(keyring, &identity),
            ServerMessage::PeerDisconnected(name) => {
                self.peers.remove(&name);
                Ok(())
            }
            ServerMessage::IdentityTaken { name } => {
                println!("Name {} is taken, please use a different one", name);
                Ok(())
            }
            ServerMessage::ChatInvite {
                sender,
                recipient: _,
                message,
                nonce,
            } => self.handle_chat_invite(sender, &message, &nonce).await,
            ServerMessage::ErrorMessage(error) => {
                println!("error: {}", error);
                Ok(())
            } // something => panic!("Unexpected message: {:?}", something),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClientMessage;
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

    async fn setup_client_connector(
        path: &str,
        log: &Logger,
        client_receiver: &mut Receiver<ServerMessage>,
    ) -> Result<ClientConnector<UnixStream>> {
        let mut client_connector = connect(path.to_string(), "foo", log.new(o!())).await?;
        client_connector.send_identity().await?;
        client_receiver.recv().await; // Identity

        Ok(client_connector)
    }

    async fn send_peers_message(
        mut client_connector: &mut ClientConnector<UnixStream>,
        client_sender: &Sender<ServerMessage>,
    ) -> Result<(Identity, box_::SecretKey, Identity, box_::SecretKey)> {
        let (bar, bar_secret_key) = new_identity("bar");
        let (baz, baz_secret_key) = new_identity("baz");
        client_sender.send(ServerMessage::Peers(vec![bar.clone(), baz.clone()]))?;

        Ok((bar, bar_secret_key, baz, baz_secret_key))
    }

    async fn send_chat_invite(
        mut client_connector: &mut ClientConnector<UnixStream>,
        client_sender: &Sender<ServerMessage>,
        keyring: &keyring::KeyRing,
        public_key: &box_::PublicKey,
        secret_key: &box_::SecretKey,
        server_key: &secretbox::Key,
        real_sender: &str,
    ) -> Result<()> {
        let mut chat_invite =
            ServerMessage::new_chat_invite(None, public_key, secret_key, "foo", server_key)?;
        if let ServerMessage::ChatInvite {
            ref mut sender,
            ref recipient,
            ref message,
            ref nonce,
        } = chat_invite
        {
            *sender = Some(real_sender.to_string());
        };
        client_sender.send(chat_invite)?;

        // Handle the chat invite
        Ok(handle_message(&mut client_connector, &keyring).await?)
    }

    async fn handle_message(
        client_connector: &mut ClientConnector<UnixStream>,
        keyring: &keyring::KeyRing,
    ) -> Result<()> {
        match client_connector.next_message().await {
            Some(message) => Ok(client_connector
                .handle_network_message(keyring, message?)
                .await?),
            None => Err("Client connector got None")?,
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connector_generates_key_with_no_peers() -> Result<()> {
        let (log, path, client_sender, mut client_receiver) = setup()?;

        let mut client_connector =
            setup_client_connector(&path, &log, &mut client_receiver).await?;

        // Send empty peers message
        client_sender.send(ServerMessage::Peers(vec![]))?;

        // Receive peers message
        let keyring = keyring::KeyRing::default();
        handle_message(&mut client_connector, &keyring).await?;

        assert!(client_connector.server_key().is_some());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connector_generates_peerlist_event_with_peers_present() -> Result<()> {
        let (log, path, client_sender, mut client_receiver) = setup()?;

        let mut client_connector =
            setup_client_connector(&path, &log, &mut client_receiver).await?;

        // Send peers message
        let (bar, _, baz, _) = send_peers_message(&mut client_connector, &client_sender).await?;

        // Receive peers message
        let mut keyring = keyring::KeyRing::default();
        handle_message(&mut client_connector, &keyring).await?;

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

        let mut client_connector =
            setup_client_connector(&path, &log, &mut client_receiver).await?;

        // Send peers message
        let (bar, secret_key) = new_identity("bar");
        let (baz, _) = new_identity("baz");
        client_sender.send(ServerMessage::Peers(vec![bar.clone(), baz.clone()]))?;

        // Receive ContactFound event
        let mut keyring = keyring::KeyRing::default();
        keyring.add_contact(&keyring::Contact::new("foobar", &vec![bar.public_key]));
        handle_message(&mut client_connector, &keyring).await?;
        match client_connector.recv_event().await {
            Some(Event::ContactFound { contact, chat_name }) => {
                assert_eq!(contact, keyring::Contact::new("foobar", &[bar.public_key]));
                assert_eq!(chat_name, None);
            }
            _ => assert!(false),
        };

        // Send chat invite
        let server_key = secretbox::gen_key();
        let public_key = &client_connector.identity.public_key.clone();
        send_chat_invite(
            &mut client_connector,
            &client_sender,
            &keyring,
            &public_key,
            &secret_key,
            &server_key,
            "bar",
        )
        .await?;

        assert!(client_connector.server_key().is_some());
        assert_eq!(server_key, *client_connector.server_key().unwrap());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connector_ignores_server_key_from_peer_not_in_contact_list() -> Result<()> {
        let (log, path, client_sender, mut client_receiver) = setup()?;

        let mut client_connector =
            setup_client_connector(&path, &log, &mut client_receiver).await?;

        // Send peers message
        let (bar, secret_key, baz, _) =
            send_peers_message(&mut client_connector, &client_sender).await?;

        // Receive peers message
        let mut keyring = keyring::KeyRing::default();
        handle_message(&mut client_connector, &keyring).await?;

        // Send chat invite
        let server_key = secretbox::gen_key();
        let public_key = &client_connector.identity.public_key.clone();
        send_chat_invite(
            &mut client_connector,
            &client_sender,
            &keyring,
            &public_key,
            &secret_key,
            &server_key,
            "bar",
        )
        .await?;

        assert!(client_connector.server_key().is_none());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connector_handles_same_server_key_sent_multiple_times() -> Result<()> {
        let (log, path, client_sender, mut client_receiver) = setup()?;

        let mut client_connector =
            setup_client_connector(&path, &log, &mut client_receiver).await?;

        // Send peers message
        let (bar, bar_secret_key, baz, baz_secret_key) =
            send_peers_message(&mut client_connector, &client_sender).await?;

        // Receive peers message
        let mut keyring = keyring::KeyRing::default();
        keyring.add_contact(&keyring::Contact::new("foobar", &vec![bar.public_key]));
        keyring.add_contact(&keyring::Contact::new("barfoo", &vec![baz.public_key]));
        handle_message(&mut client_connector, &keyring).await?;

        let server_key = secretbox::gen_key();
        let public_key = &client_connector.identity.public_key.clone();
        send_chat_invite(
            &mut client_connector,
            &client_sender,
            &keyring,
            &public_key,
            &bar_secret_key,
            &server_key,
            "bar",
        )
        .await?;

        let public_key = &client_connector.identity.public_key.clone();
        send_chat_invite(
            &mut client_connector,
            &client_sender,
            &keyring,
            &public_key,
            &baz_secret_key,
            &server_key,
            "baz",
        )
        .await?;

        assert!(client_connector.server_key().is_some());
        assert_eq!(server_key, *client_connector.server_key().unwrap());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connector_can_read_and_send_messages_using_server_key() -> Result<()> {
        let (log, path, client_sender, mut client_receiver) = setup()?;

        let mut client_connector =
            setup_client_connector(&path, &log, &mut client_receiver).await?;

        // Send peers message
        let (bar, bar_secret_key, baz, _) =
            send_peers_message(&mut client_connector, &client_sender).await?;

        // Receive peers message
        let mut keyring = keyring::KeyRing::default();
        keyring.add_contact(&keyring::Contact::new("foobar", &vec![bar.public_key]));
        handle_message(&mut client_connector, &keyring).await?;

        let server_key = secretbox::gen_key();
        let public_key = &client_connector.identity.public_key.clone();
        send_chat_invite(
            &mut client_connector,
            &client_sender,
            &keyring,
            &public_key,
            &bar_secret_key,
            &server_key,
            "bar",
        )
        .await?;

        // Send chat message
        client_connector
            .send_server_chat_message("Hello!", Some(vec!["bar".into(), "baz".into()]))
            .await?;

        // Receive and decrypt chat message
        let chat_message = client_receiver.recv().await.unwrap();
        assert_eq!(
            "Hello!",
            ClientMessage::decrypt_chat_message(
                &server_key,
                &ServerMessage::get_client_message(&server_key, &chat_message)?
            )?
            .message
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connector_cant_create_chat_without_server_key() -> Result<()> {
        let (log, path, client_sender, mut client_receiver) = setup()?;

        let mut client_connector =
            setup_client_connector(&path, &log, &mut client_receiver).await?;

        // Send peers message
        let (bar, bar_secret_key, baz, _) =
            send_peers_message(&mut client_connector, &client_sender).await?;

        // Receive peers message
        let mut keyring = keyring::KeyRing::default();
        keyring.add_contact(&keyring::Contact::new("foobar", &vec![bar.public_key]));
        handle_message(&mut client_connector, &keyring).await?;

        assert_eq!(
            "Don't have server key",
            client_connector
                .create_chat("new_chat".to_string(), &["bar"])
                .await
                .unwrap_err()
                .to_string()
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connector_creates_chat() -> Result<()> {
        let (log, path, client_sender, mut client_receiver) = setup()?;

        let mut client_connector =
            setup_client_connector(&path, &log, &mut client_receiver).await?;

        // Send peers message
        let (bar, bar_secret_key, baz, _) =
            send_peers_message(&mut client_connector, &client_sender).await?;

        // Receive peers message
        let mut keyring = keyring::KeyRing::default();
        keyring.add_contact(&keyring::Contact::new("foobar", &vec![bar.public_key]));
        handle_message(&mut client_connector, &keyring).await?;

        let server_key = secretbox::gen_key();
        let public_key = &client_connector.identity.public_key.clone();
        send_chat_invite(
            &mut client_connector,
            &client_sender,
            &keyring,
            &public_key,
            &bar_secret_key,
            &server_key,
            "bar",
        )
        .await?;

        client_connector
            .create_chat("new_chat".to_string(), &["bar"])
            .await?;

        // Make sure all peers get CreateChat
        let server_msg = client_receiver.recv().await.unwrap();
        match server_msg {
            ServerMessage::ClientMessage {
                sender: _,
                ref recipients,
                message: _,
                nonce: _,
            } => {
                let mut sorted = recipients.clone().unwrap().clone();
                sorted.sort();
                assert_eq!(sorted, vec!["bar".to_string(), "baz".to_string()],);
            }
            _ => assert!(false),
        };
        match ServerMessage::get_client_message(&server_key, &server_msg.clone())? {
            ClientMessage::CreateChat { chat_name } => assert_eq!("new_chat", chat_name),
            _ => assert!(false),
        };

        // Make sure recipient gets ChatInvite
        let server_msg = client_receiver.recv().await.unwrap();
        match server_msg {
            ServerMessage::ChatInvite {
                sender: _,
                ref recipient,
                message: _,
                nonce: _,
            } => {
                assert_eq!(recipient.clone(), "bar".to_string());
            }
            _ => assert!(false),
        };
        match ServerMessage::decrypt_chat_invite(
            &client_connector.identity.public_key,
            &bar_secret_key,
            &server_msg.clone(),
        )? {
            ChatInvite { name, key } => {
                assert_eq!("new_chat", name.unwrap());
                assert_eq!(
                    *client_connector
                        .chat_keys
                        .get(&Some("new_chat".to_string()))
                        .unwrap(),
                    key
                );
            }
            _ => assert!(false),
        };

        Ok(())
    }
}

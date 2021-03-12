use crate::{
    client_message::ChatMessage, client_message::DirectMessage,
    framed_connection::new_client_connection, keyring, ClientMessage, FramedClientConnection,
    Identity, Receiver, Result, Sender, ServerMessage,
};
use futures::{SinkExt, StreamExt};
use slog::{debug, error, o, Discard, Logger};
use sodiumoxide::crypto::{box_, secretbox, sign};
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
    DirectMessage {
        sender: String,
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
    connection: FramedClientConnection<T>,
    chat_keys: HashMap<Option<String>, secretbox::Key>,
    chat_name_map: HashMap<Option<String>, String>,
    log: Logger,
}

impl<T: AsyncRead + AsyncWrite + std::marker::Unpin> ClientConnector<T> {
    fn new(stream: T, identity: &keyring::Identity, name: &str, log: Option<Logger>) -> Self {
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
            connection: new_client_connection(stream),
            chat_keys: HashMap::new(),
            chat_name_map: HashMap::new(),
            log,
        }
    }

    async fn send_identity(&mut self) -> Result<()> {
        debug!(self.log, "Sending identity to server");
        Ok(self
            .send_message(ClientMessage::Identity(Identity::new(
                &self.name,
                &self.identity.public_key,
            )))
            .await?)
    }

    // NOTE: The 'a here is to get around https://github.com/rust-lang/rust/issues/63033
    pub async fn connect<'a>(
        stream: T,
        identity: &'a keyring::Identity,
        name: &'a str,
        log: Option<Logger>,
    ) -> Result<Self> {
        let mut connector = Self::new(stream, identity, name, log);
        connector.send_identity().await?;
        Ok(connector)
    }

    fn server_key(&self) -> Option<&secretbox::Key> {
        self.chat_keys.get(&None)
    }

    pub async fn recv_event(&mut self) -> Option<Event> {
        self.connector_receiver.recv().await
    }

    pub fn send_event(&mut self, event: Event) -> Result<()> {
        Ok(self.connector_sender.send(event)?)
    }

    pub async fn send_message(&mut self, message: ClientMessage) -> Result<()> {
        unimplemented!()
        // Ok(self.connection.send(message).await?)
    }

    pub async fn next_message(&mut self) -> Option<Result<ServerMessage>> {
        unimplemented!()
        // self.connection
        //     .next()
        //     .await
        //     .map(|r| r.map_err(|e| e.into()))
    }

    pub async fn handle_events(mut self, keyring: &keyring::KeyRing) -> Result<()> {
        let mut event_receiver = self.event_receiver.take().unwrap();
        // Event loop
        loop {
            select! {
                // Read from network
                message_opt = self.next_message() => {
                    match message_opt {
                        Some(server_message_result) => self.handle_network_message(
                            keyring,
                            server_message_result?
                        ).await?,
                        None => break,
                    }
                },

                // Read events from client
                event = event_receiver.recv() => match event {
                    Some(Event::ChatMessage { chat_name, message }) => unimplemented!(),
                    Some(Event::ContactFound { contact, chat_name }) => unimplemented!(),
                    Some(_) => unimplemented!(),
                    None => break,
                }

            }
        }

        Ok(())
    }

    // Add peer to peers list, check in contact list, and let client know if client found
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

    async fn handle_direct_message(
        &mut self,
        sender: String,
        encrypted: &[u8],
        nonce: &box_::Nonce,
    ) -> Result<()> {
        let sender_public_key = match self.get_sender_public_key(&sender) {
            Some(public_key) => public_key,
            None => Err(format!("Unable to access public key of {}", sender))?,
        };
        let message = DirectMessage::decrypt(
            encrypted,
            nonce,
            &self.identity.secret_key,
            &sender_public_key,
        )?;

        match message {
            DirectMessage::Message(message) => {
                self.send_event(Event::DirectMessage { sender, message })?
            }
            DirectMessage::ChatKeyRequest { chat_name } => unimplemented!(),
            DirectMessage::ChatKey {
                chat_name,
                chat_key,
            } => unimplemented!(),
            DirectMessage::ChatKeyRequestError { message } => unimplemented!(),
        }

        unimplemented!()
    }

    async fn handle_chat_message(
        &mut self,
        sender: String,
        list_name: Option<String>,
        encrypted: &[u8],
        nonce: &secretbox::Nonce,
        signature: &sign::Signature,
    ) -> Result<()> {
        let chat_key = match list_name {
            Some(list_name) => match self.chat_name_map.get(&Some(list_name.clone())) {
                Some(chat_name) => match self.chat_keys.get(&Some(chat_name.clone())) {
                    Some(chat_key) => chat_key,
                    None => Err(format!("No chat key found for chat_name {}", chat_name))?,
                },
                None => Err(format!("Unknown list name {}", list_name.clone()))?,
            },
            None => match self.chat_keys.get(&None) {
                Some(key) => key,
                None => Err("No server key found")?,
            },
        };

        let sender_public_key = match self.get_sender_public_key(&sender) {
            Some(public_key) => public_key,
            None => Err(format!("No public key found for sender {}", sender))?,
        };

        match ChatMessage::decrypt_and_verify(
            encrypted,
            nonce,
            signature,
            chat_key,
            &sender_public_key,
        ) {
            Ok(message) => match message {
                ChatMessage::Message(message) => unimplemented!(),
            },
            Err(err) => Err(err)?,
        }
    }

    fn get_sender_public_key(&self, sender: &str) -> Option<box_::PublicKey> {
        debug!(self.log, "Looking up sender {}", sender);
        match self.peers.get(sender) {
            Some(peer) => {
                debug!(self.log, "Sender is {:?}", peer.contact);
                Some(peer.identity.public_key)
            }
            _ => None,
        }
    }

    fn handle_peers_message(
        &mut self,
        keyring: &keyring::KeyRing,
        peer_list: &[Identity],
    ) -> Result<()> {
        debug!(self.log, "Got Peers message, peers = {:?}", peer_list);
        if peer_list.is_empty() {
            debug!(self.log, "I'm the first, generating server key");
            self.chat_keys.insert(None, secretbox::gen_key());
        } else {
            for peer in peer_list {
                debug!(self.log, "Adding peer {}", peer.name);
                self.add_peer(keyring, &peer)?;
            }
        }

        // Send current peer list to client in case they want to display it
        self.send_event_to_client(Event::PeerList(self.peers.values().cloned().collect()))?;
        Ok(())
    }

    pub async fn handle_network_message(
        &mut self,
        keyring: &keyring::KeyRing,
        message: ServerMessage,
    ) -> Result<()> {
        match message {
            ServerMessage::Peers(peer_list) => self.handle_peers_message(keyring, &peer_list),
            ServerMessage::IdentityTaken { name } => {
                println!("Name {} is taken, please use a different one", name);
                Ok(())
            }
            ServerMessage::PeerJoined(identity) => self.add_peer(keyring, &identity),
            ServerMessage::PeerDisconnected(name) => {
                self.peers.remove(&name);
                Ok(())
            }
            ServerMessage::DirectMessage {
                sender,
                recipient,
                encrypted,
                nonce,
            } => self.handle_direct_message(sender, &encrypted, &nonce).await,
            ServerMessage::ChatMessage {
                sender,
                list_name,
                encrypted,
                nonce,
                signature,
            } => {
                self.handle_chat_message(sender, list_name, &encrypted, &nonce, &signature)
                    .await
            }
            ServerMessage::Error(error) => {
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

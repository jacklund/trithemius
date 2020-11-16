#[macro_use]
extern crate serde_derive;

use futures::SinkExt;
use sodiumoxide::crypto::{box_, hash, pwhash, secretbox};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::stream::StreamExt;
use tokio::sync::mpsc;
use tokio_serde::formats::SymmetricalMessagePack;
use tokio_util::codec::{BytesCodec, Framed};

pub mod client_connector;
pub mod keyring;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub type Sender<T> = mpsc::UnboundedSender<T>;
pub type Receiver<T> = mpsc::UnboundedReceiver<T>;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Identity {
    pub name: String,
    pub public_key: box_::PublicKey,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum ServerMessage {
    Identity(Identity),
    Peers(Vec<Identity>),
    IdentityTaken {
        name: String,
    },
    PeerJoined(Identity),
    PeerDisconnected(String),
    ClientMessage {
        sender: Option<String>,
        recipients: Option<Vec<String>>,
        message: Vec<u8>,
        nonce: Vec<u8>,
    },
    ListUsers,
    ErrorMessage(String),
}

impl ServerMessage {
    pub fn identity(name: &str, public_key: &box_::PublicKey) -> Self {
        ServerMessage::Identity(Identity {
            name: name.into(),
            public_key: public_key.clone(),
        })
    }

    pub fn peer_disconnected(name: &str) -> Self {
        ServerMessage::PeerDisconnected(name.into())
    }

    pub fn new_client_message(
        recipients: Option<Vec<String>>,
        nonce: &[u8],
        encrypted: &[u8],
    ) -> Result<Self> {
        Ok(Self::ClientMessage {
            sender: None,
            recipients,
            message: encrypted.to_vec(),
            nonce: nonce.to_vec(),
        })
    }

    pub fn new_chat_message(
        key: &secretbox::Key,
        recipients: Option<Vec<String>>,
        message: &str,
    ) -> Result<Self> {
        let nonce = secretbox::gen_nonce();
        let encrypted = secretbox::seal(
            &rmp_serde::to_vec(&ClientMessage::ChatMessage(message.into()))?,
            &nonce,
            key,
        );
        Self::new_client_message(recipients, nonce.as_ref(), &encrypted)
    }

    pub fn new_chat_invite(
        name: Option<String>,
        participants: Option<Vec<String>>,
        public_key: &box_::PublicKey,
        secret_key: &box_::SecretKey,
        recipients: Option<Vec<String>>,
        chat_key: &secretbox::Key,
    ) -> Result<Self> {
        let nonce = box_::gen_nonce();
        let encrypted = box_::seal(
            &rmp_serde::to_vec(&ClientMessage::ChatInvite {
                name,
                participants,
                key: chat_key.clone(),
            })?,
            &nonce,
            public_key,
            secret_key,
        );
        Self::new_client_message(recipients, nonce.as_ref(), &encrypted)
    }

    pub fn get_client_message(
        key: &secretbox::Key,
        message: &ServerMessage,
    ) -> Result<ClientMessage> {
        match message {
            ServerMessage::ClientMessage {
                sender: _,
                recipients: _,
                message,
                nonce,
            } => {
                let nonce = match secretbox::Nonce::from_slice(&nonce) {
                    Some(nonce) => nonce,
                    None => Err("Error converting nonce from bytes in message")?,
                };
                let decrypted = match secretbox::open(&message, &nonce, key) {
                    Ok(decrypted) => decrypted,
                    Err(_) => Err("Error decrypting message")?,
                };
                Ok(rmp_serde::from_read_ref(&decrypted)?)
            }
            _ => Err("Not a ClientMessage")?,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum ClientMessage {
    ChatInvite {
        name: Option<String>,
        participants: Option<Vec<String>>,
        key: secretbox::Key,
    },
    ChatMessage(String),
}

pub struct FramedConnection<T: AsyncRead + AsyncWrite + std::marker::Unpin> {
    framed: tokio_serde::Framed<
        tokio_util::codec::Framed<T, tokio_util::codec::BytesCodec>,
        ServerMessage,
        ServerMessage,
        tokio_serde::formats::MessagePack<ServerMessage, ServerMessage>,
    >,
}

impl<T: AsyncRead + AsyncWrite + std::marker::Unpin> FramedConnection<T> {
    pub fn new(connection: T) -> Self {
        Self {
            framed: tokio_serde::SymmetricallyFramed::new(
                tokio_util::codec::Framed::new(connection, tokio_util::codec::BytesCodec::new()),
                SymmetricalMessagePack::<ServerMessage>::default(),
            ),
        }
    }

    pub fn get_mut(&mut self) -> &mut Framed<T, BytesCodec> {
        self.framed.get_mut()
    }

    pub async fn send(&mut self, message: ServerMessage) -> Result<()> {
        Ok(self.framed.send(message).await?)
    }

    pub async fn next(&mut self) -> Option<Result<ServerMessage>> {
        match self.framed.next().await {
            None => None,
            Some(Ok(message)) => Some(Ok(message)),
            Some(Err(error)) => Err(error).ok()?,
        }
    }
}

fn derive_file_encryption_key(password: &str, salt: &pwhash::Salt) -> Result<secretbox::Key> {
    // Buffer
    let mut file_encryption_key_bytes: [u8; secretbox::KEYBYTES] = [0; secretbox::KEYBYTES];

    // Derive key bytes
    let file_encryption_key_bytes = match pwhash::derive_key_interactive(
        &mut file_encryption_key_bytes,
        password.as_bytes(),
        &salt,
    ) {
        Ok(key) => key,
        Err(_) => Err("Error deriving key encryption key from password and salt")?,
    };

    // Turn into key and return
    Ok(
        match secretbox::Key::from_slice(file_encryption_key_bytes) {
            Some(key) => key,
            None => Err("Error creating file encryption key from raw bytes")?,
        },
    )
}

pub fn fingerprint(key: &[u8]) -> String {
    let digest = hash::hash(key);
    let mut hexed = hex::encode(&digest.as_ref()[..16]);
    let mut v = vec![];
    loop {
        let pair: String = hexed.drain(..2).collect();
        v.push(pair);
        if hexed.is_empty() {
            break;
        }
        v.push(":".into());
    }

    v.into_iter().collect()
}

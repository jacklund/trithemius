#[macro_use]
extern crate serde_derive;

use futures::SinkExt;
use sodiumoxide::crypto::{pwhash, secretbox};
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Message {
    Identity(String),
    ChatMessage {
        sender: Option<String>,
        recipients: Option<Vec<String>>,
        message: Vec<u8>,
        nonce: secretbox::Nonce,
    },
    ErrorMessage(String),
}

impl Message {
    pub fn new_chat_message(
        key: &secretbox::Key,
        recipients: Option<Vec<String>>,
        message: &str,
    ) -> Self {
        let nonce = secretbox::gen_nonce();
        let encrypted = secretbox::seal(message.as_bytes(), &nonce, key);
        Self::ChatMessage {
            sender: None,
            recipients,
            message: encrypted,
            nonce,
        }
    }
}

pub struct FramedConnection<T: AsyncRead + AsyncWrite + std::marker::Unpin> {
    framed: tokio_serde::Framed<
        tokio_util::codec::Framed<T, tokio_util::codec::BytesCodec>,
        Message,
        Message,
        tokio_serde::formats::MessagePack<Message, Message>,
    >,
}

impl<T: AsyncRead + AsyncWrite + std::marker::Unpin> FramedConnection<T> {
    pub fn new(connection: T) -> Self {
        Self {
            framed: tokio_serde::SymmetricallyFramed::new(
                tokio_util::codec::Framed::new(connection, tokio_util::codec::BytesCodec::new()),
                SymmetricalMessagePack::<Message>::default(),
            ),
        }
    }

    pub fn get_mut(&mut self) -> &mut Framed<T, BytesCodec> {
        self.framed.get_mut()
    }

    pub async fn send(&mut self, message: Message) -> Result<()> {
        Ok(self.framed.send(message).await?)
    }

    pub async fn next(&mut self) -> Option<Result<Message>> {
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

pub fn fingerprint(data: &[u8]) -> String {
    let mut hexed = hex::encode(data);
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

#[macro_use]
extern crate serde_derive;

use client_message::ClientMessage;
use framed_connection::FramedClientConnection;
use server_message::ServerMessage;
use sodiumoxide::crypto::{box_, hash, pwhash, secretbox};
use tokio::sync::mpsc;

pub mod client_connector;
pub mod client_message;
pub mod framed_connection;
pub mod keyring;
pub mod server_message;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub type Sender<T> = mpsc::UnboundedSender<T>;
pub type Receiver<T> = mpsc::UnboundedReceiver<T>;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Identity {
    pub name: String,
    pub public_key: box_::PublicKey,
}

impl Identity {
    pub fn new(name: &str, public_key: &box_::PublicKey) -> Self {
        Self {
            name: name.into(),
            public_key: public_key.clone(),
        }
    }
}

// #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
// pub enum ClientMessage {
//     CreateChat {
//         chat_name: String,
//     },
//     ChatMessage {
//         chat_name: Option<String>,
//         message: Vec<u8>,
//         nonce: secretbox::Nonce,
//     },
// }

// #[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
// pub struct ChatInvite {
//     name: Option<String>,
//     key: secretbox::Key,
// }
//
// impl ChatInvite {
//     pub fn new(name: Option<String>, key: &secretbox::Key) -> Self {
//         Self {
//             name,
//             key: key.clone(),
//         }
//     }
// }
//
// pub struct ChatMessage {
//     pub chat_name: Option<String>,
//     pub message: String,
// }

// impl ClientMessage {
//     pub fn new_create_chat_message(chat_name: &str) -> Self {
//         Self::CreateChat {
//             chat_name: chat_name.to_string(),
//         }
//     }
//
//     pub fn new_chat_message(
//         chat_name: Option<String>,
//         key: &secretbox::Key,
//         message: &str,
//     ) -> Result<Self> {
//         let nonce = secretbox::gen_nonce();
//         Ok(Self::ChatMessage {
//             chat_name,
//             message: secretbox::seal(message.as_bytes(), &nonce, key),
//             nonce,
//         })
//     }
//
//     pub fn decrypt_chat_message(
//         key: &secretbox::Key,
//         message: &ClientMessage,
//     ) -> Result<ChatMessage> {
//         match message {
//             ClientMessage::ChatMessage {
//                 chat_name,
//                 message,
//                 nonce,
//             } => match secretbox::open(message, nonce, key) {
//                 Ok(decrypted) => Ok(ChatMessage {
//                     chat_name: chat_name.clone(),
//                     message: std::str::from_utf8(&decrypted)?.into(),
//                 }),
//                 Err(_) => Err("Error decrypting message")?,
//             },
//             _ => Err(format!("Expected ChatMessage, got {:?}", message))?,
//         }
//     }
// }

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

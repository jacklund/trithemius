use crate::{ClientMessage, Identity, Result};
use sodiumoxide::crypto::{box_, secretbox};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum ServerMessage {
    Identity(Identity),
    Peers(Vec<Identity>),
    IdentityTaken {
        name: String,
    },
    PeerJoined(Identity),
    PeerDisconnected(String),
    // ChatInvite is encrypted with recipients public key
    ChatInvite {
        sender: Option<String>,
        recipient: String,
        message: Vec<u8>,
        nonce: box_::Nonce,
    },
    // ClientMessage is encrypted with chat key
    ClientMessage {
        sender: Option<String>,
        recipients: Option<Vec<String>>,
        message: Vec<u8>,
        nonce: secretbox::Nonce,
    },
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
        nonce: secretbox::Nonce,
        encrypted: Vec<u8>,
    ) -> Result<Self> {
        Ok(Self::ClientMessage {
            sender: None,
            recipients,
            message: encrypted,
            nonce,
        })
    }

    pub fn new_new_chat_message(server_key: &secretbox::Key, name: &str) -> Result<Self> {
        let server_nonce = secretbox::gen_nonce();
        let encrypted = secretbox::seal(
            &rmp_serde::to_vec(&ClientMessage::NewChat {
                chat_name: name.into(),
            })?,
            &server_nonce,
            server_key,
        );

        Self::new_client_message(None, server_nonce, encrypted)
    }

    pub fn new_chat_message(
        server_key: &secretbox::Key,
        chat_key: &secretbox::Key,
        chat_name: Option<String>,
        recipients: Option<Vec<String>>,
        message: &str,
    ) -> Result<Self> {
        let chat_nonce = secretbox::gen_nonce();
        let encrypted = secretbox::seal(message.as_bytes(), &chat_nonce, chat_key);
        let server_nonce = secretbox::gen_nonce();
        let encrypted_chat_message = secretbox::seal(
            &rmp_serde::to_vec(&ClientMessage::ChatMessage {
                chat_name: chat_name.into(),
                message: encrypted,
                nonce: chat_nonce,
            })?,
            &server_nonce,
            server_key,
        );
        Self::new_client_message(recipients, server_nonce, encrypted_chat_message)
    }

    pub fn new_chat_invite(
        name: Option<String>,
        public_key: &box_::PublicKey,
        secret_key: &box_::SecretKey,
        recipient: &str,
        chat_key: &secretbox::Key,
    ) -> Result<Self> {
        let nonce = box_::gen_nonce();
        let encrypted = box_::seal(
            &rmp_serde::to_vec(&ClientMessage::ChatInvite {
                name,
                key: chat_key.clone(),
            })?,
            &nonce,
            public_key,
            secret_key,
        );
        Ok(Self::ChatInvite {
            sender: None,
            recipient: recipient.into(),
            message: encrypted,
            nonce: nonce,
        })
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

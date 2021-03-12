use crate::{Identity, Result};
use sodiumoxide::crypto::{box_, secretbox, sign};

/// Message sent from a client to the server

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum ClientMessage {
    Identity(Identity),
    PeersRequest,
    ChatListRequest,
    DirectMessage {
        recipient: String,
        encrypted: Vec<u8>,
        nonce: box_::Nonce,
    },
    ChatMessage {
        list_name: Option<String>,
        encrypted: Vec<u8>,
        nonce: secretbox::Nonce,
        signature: sign::Signature,
    },
}

impl From<Identity> for ClientMessage {
    fn from(identity: Identity) -> Self {
        Self::Identity(identity)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum DirectMessage {
    Message(String),
    ChatKeyRequest {
        chat_name: Option<String>,
    },
    ChatKey {
        chat_name: Option<String>,
        chat_key: secretbox::Key,
    },
    ChatKeyRequestError {
        message: String,
    },
}

impl DirectMessage {
    fn encrypt_and_wrap(
        &self,
        recipient: &str,
        public_key: &box_::PublicKey, // Recipient's public key
        secret_key: &box_::SecretKey, // My secret key
    ) -> Result<ClientMessage> {
        let nonce = box_::gen_nonce();
        let encrypted = box_::seal(&rmp_serde::to_vec(self)?, &nonce, public_key, secret_key);
        Ok(ClientMessage::DirectMessage {
            recipient: recipient.to_string(),
            encrypted,
            nonce,
        })
    }

    pub fn decrypt(
        encrypted: &[u8],
        nonce: &box_::Nonce,
        secret_key: &box_::SecretKey,
        public_key: &box_::PublicKey,
    ) -> Result<Self> {
        match box_::open(encrypted, nonce, public_key, secret_key) {
            Ok(decrypted) => Ok(rmp_serde::from_read_ref(&decrypted)?),
            Err(_) => Err("Error decrypting direct message")?,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum ChatMessage {
    Message(String),
}

impl ChatMessage {
    fn encrypt_and_wrap(
        &self,
        list_name: Option<String>, // Obfuscated chat name
        chat_key: &secretbox::Key, // Chat key
        secret_key: &box_::SecretKey,
    ) -> Result<ClientMessage> {
        let nonce = secretbox::gen_nonce();
        let encoded = rmp_serde::to_vec(self)?;
        let encrypted = secretbox::seal(&encoded, &nonce, chat_key);
        let signature = sign::sign_detached(
            &encoded,
            &sign::SecretKey::from_slice(secret_key.as_ref()).unwrap(),
        );
        Ok(ClientMessage::ChatMessage {
            list_name,
            encrypted,
            nonce,
            signature,
        })
    }

    pub fn decrypt_and_verify(
        encrypted: &[u8],
        nonce: &secretbox::Nonce,
        signature: &sign::Signature,
        chat_key: &secretbox::Key,
        public_key: &box_::PublicKey,
    ) -> Result<Self> {
        match secretbox::open(encrypted, nonce, chat_key) {
            Ok(decrypted) => {
                if !sign::verify_detached(
                    signature,
                    &decrypted,
                    &sign::PublicKey::from_slice(public_key.as_ref()).unwrap(),
                ) {
                    Err("Error verifying message signature")?
                } else {
                    Ok(rmp_serde::from_read_ref(&decrypted)?)
                }
            }
            Err(_) => Err("Error decrypting direct message")?,
        }
    }
}

use crate::{ClientMessage, Identity, Result};
use sodiumoxide::crypto::{box_, secretbox, sign};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum ServerMessage {
    Peers(Vec<Identity>),
    IdentityTaken {
        name: String,
    },
    PeerJoined(Identity),
    PeerDisconnected(String),
    DirectMessage {
        sender: String,
        recipient: String,
        encrypted: Vec<u8>,
        nonce: box_::Nonce,
    },
    ChatMessage {
        sender: String,
        list_name: Option<String>,
        encrypted: Vec<u8>,
        nonce: secretbox::Nonce,
        signature: sign::Signature,
    },
    Error(String),
}

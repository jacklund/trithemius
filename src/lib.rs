#[macro_use]
extern crate serde_derive;

use sodiumoxide::crypto::{pwhash, secretbox};
use std::fs::File;
use std::io::{ErrorKind, Read, Write};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Message {
    Identity(String),
    ChatMessage {
        sender: Option<String>,
        recipients: Option<Vec<String>>,
        message: Vec<u8>,
        nonce: Vec<u8>,
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
            nonce: nonce.as_ref().to_vec(),
        }
    }
}

// TODO: Add unit tests
// TODO: Remove unwraps and add error messages
pub fn read_key_from_keyfile(password: &str) -> Result<secretbox::Key> {
    let mut keyfile = dirs::home_dir().unwrap();
    keyfile.push(".trithemius");
    Ok(match File::open(&keyfile) {
        Ok(mut file) => {
            let mut data = vec![];
            file.read_to_end(&mut data)?;
            let encrypted = data.split_off(secretbox::NONCEBYTES + pwhash::SALTBYTES);
            let salt = pwhash::Salt::from_slice(&data.split_off(secretbox::NONCEBYTES)).unwrap();
            let nonce = secretbox::Nonce::from_slice(&data).unwrap();
            let key_encryption_key = derive_file_encryption_key(password, &salt)?;
            secretbox::Key::from_slice(
                &secretbox::open(&encrypted, &nonce, &key_encryption_key).unwrap(),
            )
            .unwrap()
        }
        Err(error) => match error.kind() {
            ErrorKind::NotFound => {
                let salt = pwhash::gen_salt();
                let key = secretbox::gen_key();
                let key_encryption_key = derive_file_encryption_key(password, &salt)?;
                let nonce = secretbox::gen_nonce();
                let encrypted = secretbox::seal(key.as_ref(), &nonce, &key_encryption_key);
                let mut nonce_salt_and_encrypted = nonce.as_ref().to_vec();
                nonce_salt_and_encrypted.extend_from_slice(salt.as_ref());
                nonce_salt_and_encrypted.extend_from_slice(&encrypted);
                let mut file = File::create(&keyfile)?;
                file.write_all(&nonce_salt_and_encrypted)?;
                key
            }
            _ => Err(error)?,
        },
    })
}

fn derive_file_encryption_key(password: &str, salt: &pwhash::Salt) -> Result<secretbox::Key> {
    let mut key_encryption_key: [u8; secretbox::KEYBYTES] = [0; secretbox::KEYBYTES];
    Ok(secretbox::Key::from_slice(
        pwhash::derive_key_interactive(&mut key_encryption_key, password.as_bytes(), &salt)
            .unwrap(),
    )
    .unwrap())
}

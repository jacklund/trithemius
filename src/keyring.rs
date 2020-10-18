use crate::{derive_file_encryption_key, Result};
use rmp_serde;
use sodiumoxide::crypto::{box_, pwhash, secretbox};
use std::collections::HashMap;
use std::fs::File;
use std::io::ErrorKind;
use std::path::Path;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Identity {
    name: String,
    public_key: box_::PublicKey,
    secret_key: box_::SecretKey,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Contact {
    name: String,
    public_keys: Vec<box_::PublicKey>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct KeyRing {
    identities: HashMap<String, Identity>,
    contacts: HashMap<String, Contact>,
    keys: HashMap<String, secretbox::Key>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct KeyRingFile {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    encrypted: Vec<u8>,
    path: Option<String>,
}

impl Identity {
    pub fn new(name: &str) -> Self {
        let (public_key, secret_key) = box_::gen_keypair();
        Self {
            name: name.into(),
            public_key,
            secret_key,
        }
    }
}

impl KeyRingFile {
    fn get_salt(&self) -> pwhash::Salt {
        pwhash::Salt::from_slice(&self.salt).unwrap()
    }

    fn get_nonce(&self) -> secretbox::Nonce {
        secretbox::Nonce::from_slice(&self.nonce).unwrap()
    }

    pub fn read<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_string = path.as_ref().to_str().unwrap().to_string();
        match File::open(path_string.clone()) {
            Ok(file) => {
                let keyring_file: KeyRingFile = rmp_serde::from_read(file)?;
                Ok(keyring_file)
            }
            Err(error) => match error.kind() {
                ErrorKind::NotFound => {
                    File::create(path_string.clone())?;
                    let mut keyring_file = KeyRingFile::default();
                    keyring_file.salt = pwhash::gen_salt().as_ref().to_vec();
                    keyring_file.nonce = pwhash::gen_salt().as_ref().to_vec();
                    keyring_file.path = Some(path_string);
                    Ok(keyring_file)
                }
                _ => Err(error)?,
            },
        }
    }

    pub fn save(&mut self, keyring: &KeyRing) -> Result<()> {
        let mut file = File::open(self.path.clone().unwrap())?;
        rmp_serde::encode::write(&mut file, &keyring)?;

        Ok(())
    }
}

impl KeyRing {
    pub fn read_from_file<P: AsRef<Path>>(path: &P, password: &str) -> Result<(Self, KeyRingFile)> {
        let keyring_file = KeyRingFile::read(path)?;
        let file_encryption_key = derive_file_encryption_key(password, &keyring_file.get_salt())?;
        let decrypted = secretbox::open(
            &keyring_file.encrypted,
            &keyring_file.get_nonce(),
            &file_encryption_key,
        )
        .unwrap();
        let keyring: KeyRing = rmp_serde::from_slice(&decrypted)?;
        Ok((keyring, keyring_file))
    }

    pub fn save(&mut self, file: &mut KeyRingFile, password: &str) -> Result<()> {
        let file_encryption_key = derive_file_encryption_key(password, &file.get_salt())?;
        file.encrypted = secretbox::seal(
            &rmp_serde::to_vec(self)?,
            &file.get_nonce(),
            &file_encryption_key,
        );
        file.save(&self)?;

        Ok(())
    }

    pub fn add_identity(&mut self, name: &str) -> Result<()> {
        if self.identities.contains_key(name) {
            Err(format!("Identity {} already exists in keyring", name))?;
        }

        let identity = Identity::new(name);
        self.identities.insert(name.into(), identity);

        Ok(())
    }

    pub fn remove_identity(&mut self, name: &str) -> Result<()> {
        if !self.identities.contains_key(name) {
            Err(format!("Identity {} not found in keyring", name))?;
        }

        self.identities.remove(name.into());

        Ok(())
    }

    pub fn add_contact(&mut self, contact: &Contact) -> Result<()> {
        if self.contacts.contains_key(&contact.name) {
            Err(format!(
                "Contact {} already exists in keyring",
                contact.name
            ))?;
        }

        self.contacts.insert(contact.name.clone(), contact.clone());

        Ok(())
    }

    pub fn remove_contact(&mut self, contact: &Contact) -> Result<()> {
        if !self.contacts.contains_key(&contact.name) {
            Err(format!("Contact {} not foundin keyring", contact.name))?;
        }

        self.contacts.remove(&contact.name);

        Ok(())
    }

    pub fn add_key(&mut self, name: &str, key: &secretbox::Key) -> Result<()> {
        if self.keys.contains_key(name) {
            Err(format!("Key {} already exists in keyring", name))?;
        }

        self.keys.insert(name.into(), key.clone());

        Ok(())
    }

    pub fn remove_key(&mut self, name: &str) -> Result<()> {
        if !self.keys.contains_key(name) {
            Err(format!("Key {} not foundin keyring", name))?;
        }

        self.keys.remove(name);

        Ok(())
    }
}

use crate::{derive_file_encryption_key, fingerprint, Result};
use sodiumoxide::crypto::{box_, hash, pwhash, secretbox};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

// TODO: Unit tests
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Identity {
    pub name: String,
    pub public_key: box_::PublicKey,
    pub secret_key: box_::SecretKey,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Contact {
    name: String,
    public_keys: Vec<box_::PublicKey>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Key {
    name: String,
    key: secretbox::Key,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct KeyRing {
    identities: HashMap<String, Identity>,
    contacts: HashMap<String, Contact>,
    keys: HashMap<String, Key>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyRingFile {
    salt: Vec<u8>,
    nonce: Vec<u8>,
    encrypted: Vec<u8>,
    path: PathBuf,
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

    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    pub fn get_fingerprint(&self) -> String {
        let digest = hash::hash(self.public_key.as_ref());
        fingerprint(&digest.as_ref()[..16])
    }
}

impl Key {
    pub fn new(name: &str, key: &secretbox::Key) -> Self {
        Self {
            name: name.into(),
            key: key.clone(),
        }
    }

    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    pub fn get_key(&self) -> secretbox::Key {
        self.key.clone()
    }

    pub fn get_fingerprint(&self) -> String {
        let digest = hash::hash(self.key.as_ref());
        fingerprint(&digest.as_ref()[..16])
    }
}

impl KeyRingFile {
    fn new<P: AsRef<Path>>(path: &P) -> Self {
        Self {
            salt: pwhash::gen_salt().as_ref().to_vec(),
            nonce: secretbox::gen_nonce().as_ref().to_vec(),
            encrypted: vec![],
            path: path.as_ref().to_path_buf(),
        }
    }

    fn get_salt(&self) -> Result<pwhash::Salt> {
        match pwhash::Salt::from_slice(&self.salt) {
            Some(salt) => Ok(salt),
            None => Err("Error recovering salt from keyring file")?,
        }
    }

    fn get_nonce(&self) -> Result<secretbox::Nonce> {
        match secretbox::Nonce::from_slice(&self.nonce) {
            Some(nonce) => Ok(nonce),
            None => Err("Error recovering nonce from keyring file")?,
        }
    }

    pub fn read<P: AsRef<Path>>(path: P, password: &str) -> Result<Self> {
        match File::open(path.as_ref()) {
            Ok(file) => {
                let keyring_file: KeyRingFile = rmp_serde::from_read(file)?;
                Ok(keyring_file)
            }
            Err(error) => match error.kind() {
                ErrorKind::NotFound => {
                    let mut keyring_file = KeyRingFile::new(&path);
                    let mut keyring = KeyRing::default();
                    keyring.save(&mut keyring_file, password)?;
                    Ok(keyring_file)
                }
                _ => Err(error)?,
            },
        }
    }

    pub fn save(&mut self, password: &str, keyring: &KeyRing) -> Result<()> {
        self.encrypted = keyring.encrypt(password, &self.get_salt()?, &self.get_nonce()?)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(self.path.clone())?;
        rmp_serde::encode::write_named(&mut file, &self)?;

        Ok(())
    }
}

impl KeyRing {
    pub fn read_from_file<P: AsRef<Path>>(path: &P, password: &str) -> Result<(Self, KeyRingFile)> {
        let keyring_file = KeyRingFile::read(path, password)?;
        let file_encryption_key = derive_file_encryption_key(password, &keyring_file.get_salt()?)?;
        match secretbox::open(
            &keyring_file.encrypted,
            &keyring_file.get_nonce()?,
            &file_encryption_key,
        ) {
            Ok(decrypted) => {
                let keyring: KeyRing = rmp_serde::from_read_ref::<[u8], KeyRing>(&decrypted)?;
                Ok((keyring, keyring_file))
            }
            Err(_) => Err(format!("Error decrypting keyring"))?,
        }
    }

    fn encrypt(
        &self,
        password: &str,
        salt: &pwhash::Salt,
        nonce: &secretbox::Nonce,
    ) -> Result<Vec<u8>> {
        let file_encryption_key = derive_file_encryption_key(password, salt)?;
        Ok(secretbox::seal(
            &rmp_serde::to_vec(self)?,
            nonce,
            &file_encryption_key,
        ))
    }

    pub fn save(&mut self, file: &mut KeyRingFile, password: &str) -> Result<()> {
        file.save(password, self)?;

        Ok(())
    }

    pub fn get_identity(&self, name: &str) -> Option<&Identity> {
        self.identities.get(name)
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

        self.identities.remove(name);

        Ok(())
    }

    pub fn get_identities(&self) -> Vec<&Identity> {
        self.identities.values().collect()
    }

    pub fn get_contact(&self, name: &str) -> Option<&Contact> {
        self.contacts.get(name)
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

    pub fn get_key(&self, name: &str) -> Option<&Key> {
        self.keys.get(name)
    }

    pub fn get_keys(&self) -> Vec<(&String, &Key)> {
        let mut ret = vec![];
        for (name, key) in self.keys.iter() {
            ret.push((name, key))
        }

        ret
    }

    pub fn add_key(&mut self, name: &str, key: &secretbox::Key) -> Result<()> {
        if self.keys.contains_key(name) {
            Err(format!("Key {} already exists in keyring", name))?;
        }

        self.keys.insert(name.into(), Key::new(name, key));

        Ok(())
    }

    pub fn remove_key(&mut self, name: &str) -> Result<()> {
        if !self.keys.contains_key(name) {
            Err(format!("Key {} not found in keyring", name))?;
        }

        self.keys.remove(name);

        Ok(())
    }
}

use std::{
    fs,
    path::{Path, PathBuf},
};

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use dirs::data_local_dir;
use keyring::Entry;

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub root: PathBuf,
    pub database: PathBuf,
    pub known_hosts: PathBuf,
    pub key_blobs: PathBuf,
}

impl AppPaths {
    pub fn discover() -> Result<Self> {
        let base = data_local_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("puppyterm");
        let paths = Self {
            root: base.clone(),
            database: base.join("puppyterm.sqlite3"),
            known_hosts: base.join("known_hosts"),
            key_blobs: base.join("key_blobs"),
        };
        paths.ensure()?;
        Ok(paths)
    }

    pub fn ensure(&self) -> Result<()> {
        fs::create_dir_all(&self.root)
            .with_context(|| format!("creating {}", self.root.display()))?;
        fs::create_dir_all(&self.key_blobs)
            .with_context(|| format!("creating {}", self.key_blobs.display()))?;
        if !self.known_hosts.exists() {
            fs::write(&self.known_hosts, "")
                .with_context(|| format!("initializing {}", self.known_hosts.display()))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnlockStatus {
    Available,
    Unavailable(String),
}

pub trait SecretStore: Send + Sync {
    fn put_secret(&self, key: &str, value: &str) -> Result<()>;
    fn get_secret(&self, key: &str) -> Result<Option<String>>;
    fn delete_secret(&self, key: &str) -> Result<()>;
    fn unlock_status(&self) -> UnlockStatus;
}

#[derive(Debug, Clone)]
pub struct KeyringSecretStore {
    service: String,
}

impl KeyringSecretStore {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, key: &str) -> Result<Entry> {
        Entry::new(&self.service, key).map_err(|error| anyhow!(error))
    }
}

impl SecretStore for KeyringSecretStore {
    fn put_secret(&self, key: &str, value: &str) -> Result<()> {
        self.entry(key)?
            .set_password(value)
            .map_err(|error| anyhow!(error))
    }

    fn get_secret(&self, key: &str) -> Result<Option<String>> {
        match self.entry(key)?.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(anyhow!(error)),
        }
    }

    fn delete_secret(&self, key: &str) -> Result<()> {
        match self.entry(key)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(anyhow!(error)),
        }
    }

    fn unlock_status(&self) -> UnlockStatus {
        UnlockStatus::Available
    }
}

pub fn load_or_create_master_key(secret_store: &dyn SecretStore) -> Result<Vec<u8>> {
    let secret_name = "master_key";
    if let Some(encoded) = secret_store.get_secret(secret_name)? {
        return STANDARD
            .decode(encoded)
            .context("decoding stored master key");
    }

    let mut bytes = vec![0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    secret_store.put_secret(secret_name, &STANDARD.encode(&bytes))?;
    Ok(bytes)
}

pub fn encrypt_blob(master_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(master_key).context("invalid master key length")?;
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|error| anyhow!("encrypting private key blob: {error}"))?;
    let mut payload = nonce.to_vec();
    payload.extend_from_slice(&ciphertext);
    Ok(payload)
}

pub fn decrypt_blob(master_key: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() < 12 {
        return Err(anyhow!("encrypted blob is too short"));
    }

    let (nonce, ciphertext) = payload.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(master_key).context("invalid master key length")?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|error| anyhow!("decrypting private key blob: {error}"))
}

pub fn expand_tilde(path: &str) -> PathBuf {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    }
    Path::new(path).to_path_buf()
}

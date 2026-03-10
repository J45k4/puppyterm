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
    pub secrets: PathBuf,
    pub updates: PathBuf,
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
            secrets: base.join("secrets"),
            updates: base.join("updates"),
        };
        paths.ensure()?;
        Ok(paths)
    }

    pub fn ensure(&self) -> Result<()> {
        fs::create_dir_all(&self.root)
            .with_context(|| format!("creating {}", self.root.display()))?;
        fs::create_dir_all(&self.key_blobs)
            .with_context(|| format!("creating {}", self.key_blobs.display()))?;
        fs::create_dir_all(&self.secrets)
            .with_context(|| format!("creating {}", self.secrets.display()))?;
        fs::create_dir_all(&self.updates)
            .with_context(|| format!("creating {}", self.updates.display()))?;
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

#[derive(Debug, Clone)]
pub struct HybridSecretStore {
    keyring: KeyringSecretStore,
    fallback_dir: PathBuf,
    master_key: Vec<u8>,
}

impl HybridSecretStore {
    pub fn new(service: impl Into<String>, paths: &AppPaths) -> Result<Self> {
        let service = service.into();
        let keyring = KeyringSecretStore::new(service);
        let master_key =
            load_or_create_master_key_with_fallback(&keyring, &paths.root.join("master_key.b64"))?;
        Ok(Self {
            keyring,
            fallback_dir: paths.secrets.clone(),
            master_key,
        })
    }

    fn fallback_path(&self, key: &str) -> PathBuf {
        let safe = key
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                    ch
                } else {
                    '_'
                }
            })
            .collect::<String>();
        self.fallback_dir.join(format!("{safe}.enc"))
    }

    fn write_fallback_secret(&self, key: &str, value: &str) -> Result<()> {
        let path = self.fallback_path(key);
        let payload = encrypt_blob(&self.master_key, value.as_bytes())?;
        fs::write(&path, payload).with_context(|| format!("writing {}", path.display()))
    }

    fn read_fallback_secret(&self, key: &str) -> Result<Option<String>> {
        let path = self.fallback_path(key);
        let payload = match fs::read(&path) {
            Ok(payload) => payload,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
        };
        let plaintext = decrypt_blob(&self.master_key, &payload)?;
        Ok(Some(
            String::from_utf8(plaintext).context("decoding fallback secret as UTF-8")?,
        ))
    }
}

impl SecretStore for HybridSecretStore {
    fn put_secret(&self, key: &str, value: &str) -> Result<()> {
        let _ = self.keyring.put_secret(key, value);
        self.write_fallback_secret(key, value)
    }

    fn get_secret(&self, key: &str) -> Result<Option<String>> {
        match self.keyring.get_secret(key) {
            Ok(Some(value)) => Ok(Some(value)),
            Ok(None) | Err(_) => self.read_fallback_secret(key),
        }
    }

    fn delete_secret(&self, key: &str) -> Result<()> {
        let _ = self.keyring.delete_secret(key);
        let path = self.fallback_path(key);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| format!("removing {}", path.display())),
        }
    }

    fn unlock_status(&self) -> UnlockStatus {
        UnlockStatus::Available
    }
}

fn load_or_create_master_key_with_fallback(
    keyring: &KeyringSecretStore,
    fallback_path: &Path,
) -> Result<Vec<u8>> {
    if let Ok(Some(encoded)) = keyring.get_secret("master_key") {
        return STANDARD
            .decode(encoded)
            .context("decoding keychain master key");
    }

    if let Ok(encoded) = fs::read_to_string(fallback_path) {
        return STANDARD
            .decode(encoded.trim())
            .context("decoding fallback master key");
    }

    let mut bytes = vec![0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let encoded = STANDARD.encode(&bytes);
    let _ = keyring.put_secret("master_key", &encoded);
    fs::write(fallback_path, &encoded)
        .with_context(|| format!("writing {}", fallback_path.display()))?;
    Ok(bytes)
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

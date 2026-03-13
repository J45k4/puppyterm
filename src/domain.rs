use std::path::PathBuf;

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type EntityId = String;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordMeta {
    pub created_at: String,
    pub updated_at: String,
    pub version: u32,
    pub sync_state: Option<String>,
}

impl RecordMeta {
    pub fn new() -> Self {
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        Self {
            created_at: now.clone(),
            updated_at: now,
            version: 1,
            sync_state: None,
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        self.version += 1;
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProfileSource {
    SystemDiscovered,
    AppManaged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthMethod {
    Password { secret_id: String },
    KeyRef { key_id: EntityId },
    AgentOnly,
    SystemKey { path: PathBuf },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SshOptions {
    pub proxy_jump: Option<String>,
    pub forward_agent: bool,
    pub extra_args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostProfile {
    pub id: EntityId,
    pub source: ProfileSource,
    pub alias: Option<String>,
    pub display_name: String,
    pub hostname: String,
    pub port: u16,
    pub username: Option<String>,
    pub remote_directory: Option<String>,
    pub tags: Vec<String>,
    pub auth_method: AuthMethod,
    pub identity_path: Option<PathBuf>,
    pub ssh_options: SshOptions,
    pub meta: RecordMeta,
}

impl HostProfile {
    pub fn new_app(display_name: impl Into<String>, hostname: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            source: ProfileSource::AppManaged,
            alias: None,
            display_name: display_name.into(),
            hostname: hostname.into(),
            port: 22,
            username: None,
            remote_directory: None,
            tags: Vec::new(),
            auth_method: AuthMethod::AgentOnly,
            identity_path: None,
            ssh_options: SshOptions::default(),
            meta: RecordMeta::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredKey {
    pub id: EntityId,
    pub source: ProfileSource,
    pub name: String,
    pub path: Option<PathBuf>,
    pub public_key_path: Option<PathBuf>,
    #[serde(default)]
    pub inline_public_key: Option<String>,
    pub fingerprint: Option<String>,
    pub encrypted_blob_path: Option<PathBuf>,
    pub meta: RecordMeta,
}

impl StoredKey {
    pub fn system(
        name: impl Into<String>,
        path: PathBuf,
        public_key_path: Option<PathBuf>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            source: ProfileSource::SystemDiscovered,
            name: name.into(),
            path: Some(path),
            public_key_path,
            inline_public_key: None,
            fingerprint: None,
            encrypted_blob_path: None,
            meta: RecordMeta::new(),
        }
    }

    pub fn system_public(
        name: impl Into<String>,
        source_path: PathBuf,
        public_key: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            source: ProfileSource::SystemDiscovered,
            name: name.into(),
            path: Some(source_path),
            public_key_path: None,
            inline_public_key: Some(public_key.into()),
            fingerprint: None,
            encrypted_blob_path: None,
            meta: RecordMeta::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnownHostEntry {
    pub hosts: Vec<String>,
    pub key_type: String,
    pub key: String,
    pub source_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TunnelMode {
    Local,
    Remote,
    DynamicSocks,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelSpec {
    pub id: EntityId,
    pub profile_id: EntityId,
    pub name: String,
    pub mode: TunnelMode,
    pub bind_host: String,
    pub bind_port: u16,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub meta: RecordMeta,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransferDirection {
    Upload,
    Download,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransferStatus {
    Queued,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferJob {
    pub id: EntityId,
    pub profile_id: EntityId,
    pub direction: TransferDirection,
    pub local_path: PathBuf,
    pub remote_path: String,
    pub status: TransferStatus,
    pub message: Option<String>,
    pub meta: RecordMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionRecord {
    pub id: EntityId,
    pub profile_id: EntityId,
    pub title: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub last_exit_code: Option<i32>,
    pub meta: RecordMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemProfileIndex {
    pub profiles: Vec<HostProfile>,
    pub keys: Vec<StoredKey>,
    pub known_hosts: Vec<KnownHostEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseAsset {
    pub name: String,
    pub download_url: String,
    pub signature_url: String,
    pub os: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleaseInfo {
    pub id: u64,
    pub tag_name: String,
    pub published_at: String,
    pub html_url: String,
    pub notes: String,
    pub assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingInstall {
    pub release_id: u64,
    pub tag_name: String,
    pub staged_path: PathBuf,
    pub release_notes_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UpdateCheckResult {
    UpToDate,
    UpdateAvailable,
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateState {
    pub last_checked_at: Option<String>,
    pub check_in_progress: bool,
    pub available_release_id: Option<u64>,
    pub dismissed_release_id: Option<u64>,
    pub downloaded_release_id: Option<u64>,
    pub pending_install: Option<PendingInstall>,
    pub last_result: Option<UpdateCheckResult>,
    pub available_release: Option<ReleaseInfo>,
}

impl Default for UpdateState {
    fn default() -> Self {
        Self {
            last_checked_at: None,
            check_in_progress: false,
            available_release_id: None,
            dismissed_release_id: None,
            downloaded_release_id: None,
            pending_install: None,
            last_result: None,
            available_release: None,
        }
    }
}

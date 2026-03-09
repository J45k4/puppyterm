use std::{
    io::Write,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Arc,
};

use anyhow::{Context, Result};
use chrono::{SecondsFormat, Utc};
use parking_lot::Mutex;
use uuid::Uuid;

use crate::{
    domain::{
        AuthMethod, HostProfile, SessionRecord, TransferDirection, TransferJob, TransferStatus,
        TunnelMode, TunnelSpec,
    },
    platform::AppPaths,
    terminal::{TerminalCommand, TerminalService, TerminalSessionHandle},
};

pub trait SshBackend: Send + Sync {
    fn ssh_status(&self) -> BinaryStatus;
    fn terminal_command_for_profile(&self, profile: &HostProfile) -> TerminalCommand;
    fn preview_tunnel_command(&self, profile: &HostProfile, spec: &TunnelSpec) -> String;
    fn open_terminal_session(&self, profile: &HostProfile) -> Result<TerminalSessionHandle>;
    fn start_tunnel(&self, profile: &HostProfile, spec: &TunnelSpec) -> Result<ManagedTunnel>;
    fn run_sftp_op(&self, profile: &HostProfile, operation: &SftpOperation) -> Result<SftpResult>;
    fn transfer_job(
        &self,
        profile: &HostProfile,
        direction: TransferDirection,
        local_path: PathBuf,
        remote_path: String,
    ) -> TransferJob;
}

#[derive(Debug, Clone)]
pub struct BinaryStatus {
    pub ssh: bool,
    pub sftp: bool,
    pub scp: bool,
}

#[derive(Debug, Clone)]
pub enum SftpOperation {
    ListDirectory {
        path: String,
    },
    MakeDirectory {
        path: String,
    },
    Delete {
        path: String,
    },
    Rename {
        from: String,
        to: String,
    },
    Upload {
        local_path: PathBuf,
        remote_path: String,
    },
    Download {
        remote_path: String,
        local_path: PathBuf,
    },
}

#[derive(Debug, Clone)]
pub struct SftpResult {
    pub command_preview: String,
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
}

#[derive(Clone)]
pub struct ManagedTunnel {
    pub spec: TunnelSpec,
    pub command_preview: String,
    process: ManagedTunnelProcess,
}

#[derive(Clone)]
enum ManagedTunnelProcess {
    Child(Arc<Mutex<Child>>),
    Pty(TerminalSessionHandle),
}

impl ManagedTunnel {
    pub fn stop(&self) -> Result<()> {
        match &self.process {
            ManagedTunnelProcess::Child(child) => {
                child.lock().kill().context("stopping SSH tunnel")
            }
            ManagedTunnelProcess::Pty(handle) => handle.terminate(),
        }
    }

    pub fn session_handle(&self) -> Option<TerminalSessionHandle> {
        match &self.process {
            ManagedTunnelProcess::Pty(handle) => Some(handle.clone()),
            ManagedTunnelProcess::Child(_) => None,
        }
    }
}

#[derive(Clone)]
pub struct OpenSshBackend {
    app_paths: AppPaths,
    terminal: Arc<TerminalService>,
}

impl OpenSshBackend {
    pub fn new(app_paths: AppPaths) -> Self {
        Self {
            app_paths,
            terminal: Arc::new(TerminalService),
        }
    }

    pub fn record_for_session(
        &self,
        profile: &HostProfile,
        title: impl Into<String>,
    ) -> SessionRecord {
        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
        SessionRecord {
            id: Uuid::new_v4().to_string(),
            profile_id: profile.id.clone(),
            title: title.into(),
            started_at: now,
            finished_at: None,
            last_exit_code: None,
            meta: crate::domain::RecordMeta::new(),
        }
    }

    pub fn preview_tunnel_command_impl(&self, profile: &HostProfile, spec: &TunnelSpec) -> String {
        let mut args = self.base_ssh_args(profile);
        args.push("-N".into());
        match spec.mode {
            TunnelMode::Local => {
                let target = format!(
                    "{}:{}",
                    spec.target_host
                        .clone()
                        .unwrap_or_else(|| "127.0.0.1".into()),
                    spec.target_port.unwrap_or(0)
                );
                args.push("-L".into());
                args.push(format!("{}:{}:{}", spec.bind_host, spec.bind_port, target));
            }
            TunnelMode::Remote => {
                let target = format!(
                    "{}:{}",
                    spec.target_host
                        .clone()
                        .unwrap_or_else(|| "127.0.0.1".into()),
                    spec.target_port.unwrap_or(0)
                );
                args.push("-R".into());
                args.push(format!("{}:{}:{}", spec.bind_host, spec.bind_port, target));
            }
            TunnelMode::DynamicSocks => {
                args.push("-D".into());
                args.push(format!("{}:{}", spec.bind_host, spec.bind_port));
            }
        }
        args.push(self.connection_target(profile));
        format!("ssh {}", args.join(" "))
    }

    fn base_ssh_args(&self, profile: &HostProfile) -> Vec<String> {
        let mut args = Vec::new();
        match profile.source {
            crate::domain::ProfileSource::SystemDiscovered => {}
            crate::domain::ProfileSource::AppManaged => {
                args.push("-o".into());
                args.push(format!(
                    "UserKnownHostsFile={}",
                    self.app_paths.known_hosts.display()
                ));
                args.push("-o".into());
                args.push("StrictHostKeyChecking=accept-new".into());
                if let Some(username) = &profile.username {
                    args.push("-l".into());
                    args.push(username.clone());
                }
                if profile.port != 22 {
                    args.push("-p".into());
                    args.push(profile.port.to_string());
                }
                if let Some(identity_path) = &profile.identity_path {
                    args.push("-i".into());
                    args.push(identity_path.display().to_string());
                }
                if let Some(proxy_jump) = &profile.ssh_options.proxy_jump {
                    args.push("-J".into());
                    args.push(proxy_jump.clone());
                }
                if profile.ssh_options.forward_agent {
                    args.push("-A".into());
                }
                args.extend(profile.ssh_options.extra_args.clone());
            }
        }

        match &profile.auth_method {
            AuthMethod::SystemKey { path }
                if profile.source == crate::domain::ProfileSource::SystemDiscovered =>
            {
                args.push("-i".into());
                args.push(path.display().to_string());
            }
            AuthMethod::KeyRef { .. }
            | AuthMethod::Password { .. }
            | AuthMethod::AgentOnly
            | AuthMethod::SystemKey { .. } => {}
        }

        args
    }

    fn connection_target(&self, profile: &HostProfile) -> String {
        if matches!(
            profile.source,
            crate::domain::ProfileSource::SystemDiscovered
        ) {
            if let Some(alias) = &profile.alias {
                return alias.clone();
            }
        }

        match &profile.username {
            Some(user) => format!("{user}@{}", profile.hostname),
            None => profile.hostname.clone(),
        }
    }

    fn sftp_args(&self, profile: &HostProfile) -> Vec<String> {
        let mut args = Vec::new();
        match profile.source {
            crate::domain::ProfileSource::SystemDiscovered => {}
            crate::domain::ProfileSource::AppManaged => {
                args.push("-o".into());
                args.push(format!(
                    "UserKnownHostsFile={}",
                    self.app_paths.known_hosts.display()
                ));
                if profile.port != 22 {
                    args.push("-P".into());
                    args.push(profile.port.to_string());
                }
                if let Some(identity_path) = &profile.identity_path {
                    args.push("-i".into());
                    args.push(identity_path.display().to_string());
                }
            }
        }
        args
    }

    fn serialize_sftp_batch(operation: &SftpOperation) -> String {
        match operation {
            SftpOperation::ListDirectory { path } => format!("ls -la {}\n", path),
            SftpOperation::MakeDirectory { path } => format!("mkdir {}\n", path),
            SftpOperation::Delete { path } => format!("rm {}\n", path),
            SftpOperation::Rename { from, to } => format!("rename {} {}\n", from, to),
            SftpOperation::Upload {
                local_path,
                remote_path,
            } => format!("put {} {}\n", local_path.display(), remote_path),
            SftpOperation::Download {
                remote_path,
                local_path,
            } => format!("get {} {}\n", remote_path, local_path.display()),
        }
    }
}

impl SshBackend for OpenSshBackend {
    fn ssh_status(&self) -> BinaryStatus {
        BinaryStatus {
            ssh: Command::new("ssh").arg("-V").output().is_ok(),
            sftp: Command::new("sftp").arg("-V").output().is_ok(),
            scp: Command::new("scp").arg("-V").output().is_ok(),
        }
    }

    fn terminal_command_for_profile(&self, profile: &HostProfile) -> TerminalCommand {
        let mut args = self.base_ssh_args(profile);
        args.push(self.connection_target(profile));
        TerminalCommand {
            title: format!("SSH {}", profile.display_name),
            program: "ssh".into(),
            args,
            env: Vec::new(),
            cwd: None,
        }
    }

    fn preview_tunnel_command(&self, profile: &HostProfile, spec: &TunnelSpec) -> String {
        self.preview_tunnel_command_impl(profile, spec)
    }

    fn open_terminal_session(&self, profile: &HostProfile) -> Result<TerminalSessionHandle> {
        self.terminal
            .spawn(self.terminal_command_for_profile(profile))
    }

    fn start_tunnel(&self, profile: &HostProfile, spec: &TunnelSpec) -> Result<ManagedTunnel> {
        let preview = self.preview_tunnel_command(profile, spec);
        let mut args = self.base_ssh_args(profile);
        args.push("-N".into());
        match spec.mode {
            TunnelMode::Local => {
                args.push("-L".into());
                args.push(format!(
                    "{}:{}:{}:{}",
                    spec.bind_host,
                    spec.bind_port,
                    spec.target_host
                        .clone()
                        .unwrap_or_else(|| "127.0.0.1".into()),
                    spec.target_port.unwrap_or(0)
                ));
            }
            TunnelMode::Remote => {
                args.push("-R".into());
                args.push(format!(
                    "{}:{}:{}:{}",
                    spec.bind_host,
                    spec.bind_port,
                    spec.target_host
                        .clone()
                        .unwrap_or_else(|| "127.0.0.1".into()),
                    spec.target_port.unwrap_or(0)
                ));
            }
            TunnelMode::DynamicSocks => {
                args.push("-D".into());
                args.push(format!("{}:{}", spec.bind_host, spec.bind_port));
            }
        }
        args.push(self.connection_target(profile));

        let handle = self
            .terminal
            .spawn(TerminalCommand {
                title: format!("Tunnel {}", spec.name),
                program: "ssh".into(),
                args,
                env: Vec::new(),
                cwd: None,
            })
            .context("spawning SSH tunnel")?;
        Ok(ManagedTunnel {
            spec: spec.clone(),
            command_preview: preview,
            process: ManagedTunnelProcess::Pty(handle),
        })
    }

    fn run_sftp_op(&self, profile: &HostProfile, operation: &SftpOperation) -> Result<SftpResult> {
        let mut command = Command::new("sftp");
        let args = self.sftp_args(profile);
        for arg in &args {
            command.arg(arg);
        }
        command.arg("-b");
        command.arg("-");
        command.arg(self.connection_target(profile));
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let preview = format!(
            "sftp {} -b - {}",
            args.join(" "),
            self.connection_target(profile)
        );
        let batch = Self::serialize_sftp_batch(operation);
        let mut child = command.spawn().context("spawning sftp process")?;
        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(batch.as_bytes())
                .context("writing sftp batch instructions")?;
        }
        let output = child
            .wait_with_output()
            .context("waiting for sftp command")?;
        Ok(SftpResult {
            command_preview: preview,
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            success: output.status.success(),
        })
    }

    fn transfer_job(
        &self,
        profile: &HostProfile,
        direction: TransferDirection,
        local_path: PathBuf,
        remote_path: String,
    ) -> TransferJob {
        TransferJob {
            id: Uuid::new_v4().to_string(),
            profile_id: profile.id.clone(),
            direction,
            local_path,
            remote_path,
            status: TransferStatus::Queued,
            message: None,
            meta: crate::domain::RecordMeta::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::{
        AuthMethod, HostProfile, ProfileSource, RecordMeta, SshOptions, TunnelMode, TunnelSpec,
    };

    use super::{OpenSshBackend, SftpOperation, SshBackend};

    fn backend() -> OpenSshBackend {
        OpenSshBackend::new(crate::platform::AppPaths {
            root: std::env::temp_dir().join("puppyterm-test"),
            database: std::env::temp_dir().join("puppyterm-test.sqlite"),
            known_hosts: std::env::temp_dir().join("puppyterm-known-hosts"),
            key_blobs: std::env::temp_dir().join("puppyterm-key-blobs"),
            secrets: std::env::temp_dir().join("puppyterm-secrets"),
        })
    }

    fn app_profile() -> HostProfile {
        HostProfile {
            id: "1".into(),
            source: ProfileSource::AppManaged,
            alias: None,
            display_name: "Prod".into(),
            hostname: "prod.example.com".into(),
            port: 2222,
            username: Some("root".into()),
            remote_directory: None,
            tags: Vec::new(),
            auth_method: AuthMethod::AgentOnly,
            identity_path: Some("/tmp/id_ed25519".into()),
            ssh_options: SshOptions {
                proxy_jump: Some("jump-box".into()),
                forward_agent: true,
                extra_args: vec!["-o".into(), "ServerAliveInterval=30".into()],
            },
            meta: RecordMeta::new(),
        }
    }

    #[test]
    fn builds_explicit_command_for_app_profiles() {
        let preview = backend()
            .terminal_command_for_profile(&app_profile())
            .preview();
        assert!(preview.contains("ssh"));
        assert!(preview.contains("UserKnownHostsFile"));
        assert!(preview.contains("root@prod.example.com"));
        assert!(preview.contains("-J"));
    }

    #[test]
    fn system_profile_uses_alias_target() {
        let profile = HostProfile {
            alias: Some("prod".into()),
            source: ProfileSource::SystemDiscovered,
            auth_method: AuthMethod::SystemKey {
                path: "/tmp/id_ed25519".into(),
            },
            ..app_profile()
        };
        let preview = backend().terminal_command_for_profile(&profile).preview();
        assert!(preview.ends_with("prod"));
    }

    #[test]
    fn serializes_sftp_batch_operations() {
        let result = backend()
            .run_sftp_op(
                &app_profile(),
                &SftpOperation::ListDirectory {
                    path: "/srv".into(),
                },
            )
            .expect("sftp preview should return a result or a command invocation");
        assert!(result.command_preview.contains("sftp"));
    }

    #[test]
    fn previews_tunnel_variants() {
        let spec = TunnelSpec {
            id: "t1".into(),
            profile_id: "1".into(),
            name: "SOCKS".into(),
            mode: TunnelMode::DynamicSocks,
            bind_host: "127.0.0.1".into(),
            bind_port: 1080,
            target_host: None,
            target_port: None,
            meta: RecordMeta::new(),
        };
        let preview = backend().preview_tunnel_command_impl(&app_profile(), &spec);
        assert!(preview.contains("-D"));
        assert!(preview.contains("127.0.0.1:1080"));
    }
}

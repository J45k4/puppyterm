use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::{
    domain::{
        AuthMethod, HostProfile, KnownHostEntry, ProfileSource, RecordMeta, SshOptions, StoredKey,
        SystemProfileIndex,
    },
    platform::expand_tilde,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigHostBlock {
    pub patterns: Vec<String>,
    pub options: HashMap<String, String>,
}

pub fn scan_default_ssh_assets() -> Result<SystemProfileIndex> {
    let home = dirs::home_dir().context("unable to locate user home directory")?;
    scan_ssh_assets(home.join(".ssh"))
}

pub fn scan_ssh_assets(ssh_dir: impl AsRef<Path>) -> Result<SystemProfileIndex> {
    let ssh_dir = ssh_dir.as_ref();
    let config_blocks = parse_ssh_config_file(&ssh_dir.join("config"))?;
    let mut profiles = Vec::new();
    for block in &config_blocks {
        profiles.extend(block_to_profiles(block));
    }

    let keys = discover_keys(ssh_dir)?;
    let known_hosts = parse_known_hosts(&ssh_dir.join("known_hosts"))?;

    Ok(SystemProfileIndex {
        profiles,
        keys,
        known_hosts,
    })
}

pub fn parse_ssh_config_file(path: &Path) -> Result<Vec<ConfigHostBlock>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(path)
        .with_context(|| format!("reading SSH config {}", path.display()))?;
    Ok(parse_ssh_config(&contents))
}

pub fn parse_ssh_config(contents: &str) -> Vec<ConfigHostBlock> {
    let mut blocks = Vec::new();
    let mut current: Option<ConfigHostBlock> = None;

    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut split = line.splitn(2, char::is_whitespace);
        let key = split.next().unwrap_or_default().trim().to_ascii_lowercase();
        let value = split.next().unwrap_or_default().trim();
        if key.is_empty() || value.is_empty() {
            continue;
        }

        if key == "host" {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            current = Some(ConfigHostBlock {
                patterns: value.split_whitespace().map(ToOwned::to_owned).collect(),
                options: HashMap::new(),
            });
        } else if let Some(block) = current.as_mut() {
            block.options.insert(key, value.to_string());
        }
    }

    if let Some(block) = current {
        blocks.push(block);
    }

    blocks
}

fn block_to_profiles(block: &ConfigHostBlock) -> Vec<HostProfile> {
    block
        .patterns
        .iter()
        .filter(|pattern| is_direct_host(pattern))
        .map(|pattern| {
            let identity_path = block
                .options
                .get("identityfile")
                .map(|path| expand_tilde(path));
            let auth_method = identity_path
                .clone()
                .map(|path| AuthMethod::SystemKey { path })
                .unwrap_or(AuthMethod::AgentOnly);
            HostProfile {
                id: Uuid::new_v4().to_string(),
                source: ProfileSource::SystemDiscovered,
                alias: Some(pattern.clone()),
                display_name: pattern.clone(),
                hostname: block
                    .options
                    .get("hostname")
                    .cloned()
                    .unwrap_or_else(|| pattern.clone()),
                port: block
                    .options
                    .get("port")
                    .and_then(|port| port.parse::<u16>().ok())
                    .unwrap_or(22),
                username: block.options.get("user").cloned(),
                remote_directory: None,
                tags: vec!["system".to_string()],
                auth_method,
                identity_path,
                ssh_options: SshOptions {
                    proxy_jump: block.options.get("proxyjump").cloned(),
                    forward_agent: matches!(
                        block
                            .options
                            .get("forwardagent")
                            .map(|value| value.as_str()),
                        Some("yes" | "true")
                    ),
                    extra_args: Vec::new(),
                },
                meta: RecordMeta::new(),
            }
        })
        .collect()
}

fn is_direct_host(pattern: &str) -> bool {
    !pattern.contains('*') && !pattern.contains('?') && !pattern.starts_with('!')
}

fn discover_keys(ssh_dir: &Path) -> Result<Vec<StoredKey>> {
    if !ssh_dir.exists() {
        return Ok(Vec::new());
    }

    let mut keys = Vec::new();
    for entry in fs::read_dir(ssh_dir).with_context(|| format!("reading {}", ssh_dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let file_name = entry.file_name().to_string_lossy().to_string();
        if file_name.ends_with(".pub")
            || file_name.ends_with(".pem")
            || file_name.ends_with(".crt")
            || file_name.contains("known_hosts")
            || file_name.contains("config")
        {
            continue;
        }

        if !looks_like_private_key(&path)? {
            continue;
        }

        let public_key_path = {
            let candidate = PathBuf::from(format!("{}.pub", path.display()));
            candidate.exists().then_some(candidate)
        };

        keys.push(StoredKey::system(file_name, path, public_key_path));
    }
    keys.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(keys)
}

fn looks_like_private_key(path: &Path) -> Result<bool> {
    let sample = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let text = String::from_utf8_lossy(&sample);
    Ok(text.contains("BEGIN OPENSSH PRIVATE KEY")
        || text.contains("BEGIN RSA PRIVATE KEY")
        || text.contains("BEGIN EC PRIVATE KEY")
        || text.contains("BEGIN DSA PRIVATE KEY")
        || text.contains("BEGIN PRIVATE KEY"))
}

pub fn parse_known_hosts(path: &Path) -> Result<Vec<KnownHostEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let contents = fs::read_to_string(path)
        .with_context(|| format!("reading known_hosts {}", path.display()))?;
    let mut entries = Vec::new();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let columns = line.split_whitespace().collect::<Vec<_>>();
        if columns.len() < 3 {
            continue;
        }

        entries.push(KnownHostEntry {
            hosts: columns[0].split(',').map(ToOwned::to_owned).collect(),
            key_type: columns[1].to_string(),
            key: columns[2].to_string(),
            source_path: Some(path.to_path_buf()),
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use anyhow::Result;
    use tempfile::tempdir;

    use super::{parse_known_hosts, parse_ssh_config, scan_ssh_assets};

    #[test]
    fn parses_basic_ssh_config_blocks() {
        let blocks = parse_ssh_config(
            r#"
            Host prod
                HostName prod.example.com
                User root
                Port 2222
                IdentityFile ~/.ssh/id_ed25519

            Host *.internal
                User deploy
            "#,
        );

        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].patterns, vec!["prod"]);
        assert_eq!(blocks[0].options["hostname"], "prod.example.com");
        assert_eq!(blocks[1].patterns, vec!["*.internal"]);
    }

    #[test]
    fn scans_ssh_directory_and_ignores_wildcards() -> Result<()> {
        let temp = tempdir()?;
        fs::write(
            temp.path().join("config"),
            r#"
            Host prod
                HostName prod.example.com
                User root
            Host *.internal
                User deploy
            "#,
        )?;
        fs::write(
            temp.path().join("known_hosts"),
            "prod.example.com ssh-ed25519 AAAAC3Nz\n",
        )?;
        fs::write(
            temp.path().join("id_ed25519"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nkey\n-----END OPENSSH PRIVATE KEY-----\n",
        )?;
        fs::write(
            temp.path().join("id_ed25519.pub"),
            "ssh-ed25519 AAAA user@host\n",
        )?;

        let index = scan_ssh_assets(temp.path())?;
        assert_eq!(index.profiles.len(), 1);
        assert_eq!(index.profiles[0].display_name, "prod");
        assert_eq!(index.keys.len(), 1);
        assert_eq!(index.known_hosts.len(), 1);
        Ok(())
    }

    #[test]
    fn parses_known_hosts_lines() -> Result<()> {
        let temp = tempdir()?;
        let path = PathBuf::from(temp.path().join("known_hosts"));
        fs::write(&path, "github.com,192.30.255.113 ssh-ed25519 AAAA\n")?;

        let entries = parse_known_hosts(&path)?;
        assert_eq!(entries[0].hosts.len(), 2);
        assert_eq!(entries[0].key_type, "ssh-ed25519");
        Ok(())
    }
}

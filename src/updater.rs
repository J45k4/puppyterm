use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use reqwest::blocking::Client;
use serde::Deserialize;
use zip::ZipArchive;

use crate::{
    domain::{PendingInstall, ReleaseAsset, ReleaseInfo, UpdateCheckResult, UpdateState},
    platform::AppPaths,
};

const GITHUB_OWNER: &str = "J45k4";
const GITHUB_REPO: &str = "puppyterm";
const UPDATE_PUBLIC_KEY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/update_signature_public_key.txt"
));
const BUILD_TAG: &str = match option_env!("PUPPYTERM_BUILD_TAG") {
    Some(value) => value,
    None => "dev",
};

#[derive(Clone)]
pub struct GitHubUpdater {
    app_paths: AppPaths,
    client: Client,
}

#[derive(Debug, Clone)]
pub struct InstalledBuild {
    pub tag_name: String,
    pub version: String,
    pub can_apply_update: bool,
    pub install_root: Option<PathBuf>,
    pub executable_path: PathBuf,
    pub os: String,
    pub arch: String,
}

impl GitHubUpdater {
    pub fn new(app_paths: AppPaths) -> Result<Self> {
        let client = Client::builder()
            .user_agent(format!("puppyterm/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .context("building updater HTTP client")?;
        Ok(Self { app_paths, client })
    }

    pub fn current_build(&self) -> InstalledBuild {
        let executable_path =
            std::env::current_exe().unwrap_or_else(|_| PathBuf::from("puppyterm"));
        let install_root = detect_install_root(&executable_path);
        InstalledBuild {
            tag_name: BUILD_TAG.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            can_apply_update: install_root.is_some(),
            install_root,
            executable_path,
            os: current_os().into(),
            arch: current_arch().into(),
        }
    }

    pub fn check_for_updates(
        &self,
        mut state: UpdateState,
        force: bool,
        build: &InstalledBuild,
    ) -> Result<UpdateState> {
        if !force && !should_check_updates(state.last_checked_at.as_deref()) {
            state.check_in_progress = false;
            return Ok(state);
        }

        state.last_checked_at = Some(Utc::now().to_rfc3339());
        state.check_in_progress = false;

        let release = match self.fetch_latest_release() {
            Ok(release) => release,
            Err(error) => {
                state.last_result = Some(UpdateCheckResult::Failed(error.to_string()));
                return Ok(state);
            }
        };

        if release.tag_name == build.tag_name {
            state.available_release_id = None;
            state.available_release = None;
            state.downloaded_release_id = None;
            state.pending_install = None;
            state.last_result = Some(UpdateCheckResult::UpToDate);
            return Ok(state);
        }

        state.available_release_id = Some(release.id);
        state.available_release = Some(release);
        state.pending_install = None;
        state.last_result = Some(UpdateCheckResult::UpdateAvailable);
        Ok(state)
    }

    pub fn download_available_update(
        &self,
        mut state: UpdateState,
        build: &InstalledBuild,
    ) -> Result<UpdateState> {
        let release = state
            .available_release
            .clone()
            .ok_or_else(|| anyhow!("no release is currently available"))?;
        let asset = select_release_asset(&release, &build.os, &build.arch)?;
        let archive_bytes = self.download_bytes(&asset.download_url)?;
        let signature_bytes = self.download_bytes(&asset.signature_url)?;
        verify_signature(&archive_bytes, &signature_bytes)?;

        let stage_root = self
            .app_paths
            .updates
            .join(format!("release-{}", release.id));
        if stage_root.exists() {
            fs::remove_dir_all(&stage_root)
                .with_context(|| format!("removing {}", stage_root.display()))?;
        }
        fs::create_dir_all(&stage_root)
            .with_context(|| format!("creating {}", stage_root.display()))?;

        let archive_path = stage_root.join(&asset.name);
        let signature_path = stage_root.join(format!("{}.sig", asset.name));
        fs::write(&archive_path, &archive_bytes)
            .with_context(|| format!("writing {}", archive_path.display()))?;
        fs::write(&signature_path, &signature_bytes)
            .with_context(|| format!("writing {}", signature_path.display()))?;

        let extracted_root = stage_root.join("extracted");
        fs::create_dir_all(&extracted_root)
            .with_context(|| format!("creating {}", extracted_root.display()))?;
        extract_zip_archive(&archive_bytes, &extracted_root)?;
        let staged_path = locate_staged_install(&extracted_root, build)?;

        state.downloaded_release_id = Some(release.id);
        state.pending_install = Some(PendingInstall {
            release_id: release.id,
            tag_name: release.tag_name.clone(),
            staged_path,
            release_notes_url: release.html_url.clone(),
        });
        state.last_result = Some(UpdateCheckResult::UpdateAvailable);
        Ok(state)
    }

    pub fn apply_pending_update(&self, state: &UpdateState, build: &InstalledBuild) -> Result<()> {
        let pending = state
            .pending_install
            .as_ref()
            .ok_or_else(|| anyhow!("no verified update is ready to install"))?;
        let install_root = build
            .install_root
            .as_ref()
            .ok_or_else(|| anyhow!("self-update is disabled for development builds"))?;

        #[cfg(target_os = "macos")]
        return spawn_unix_install_helper(
            install_root,
            &pending.staged_path,
            &[
                "open".to_string(),
                install_root.to_string_lossy().to_string(),
            ],
            &self.app_paths.updates,
        );

        #[cfg(target_os = "linux")]
        return spawn_unix_install_helper(
            install_root,
            &pending.staged_path,
            &[install_root.join("PuppyTerm").display().to_string()],
            &self.app_paths.updates,
        );

        #[cfg(target_os = "windows")]
        return spawn_windows_install_helper(
            install_root,
            &pending.staged_path,
            &self.app_paths.updates,
        );

        #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
        {
            let _ = (install_root, pending);
            bail!("self-update is not supported on this platform")
        }
    }

    fn fetch_latest_release(&self) -> Result<ReleaseInfo> {
        let url = format!(
            "https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases?per_page=20"
        );
        let releases = self
            .client
            .get(&url)
            .send()
            .context("fetching GitHub releases")?
            .error_for_status()
            .context("GitHub releases request failed")?
            .json::<Vec<GitHubReleaseResponse>>()
            .context("parsing GitHub release JSON")?;
        release_from_responses(&releases)
    }

    fn download_bytes(&self, url: &str) -> Result<Vec<u8>> {
        self.client
            .get(url)
            .send()
            .with_context(|| format!("downloading {url}"))?
            .error_for_status()
            .with_context(|| format!("download failed for {url}"))?
            .bytes()
            .map(|bytes| bytes.to_vec())
            .context("reading download response")
    }
}

#[derive(Debug, Deserialize, Clone)]
struct GitHubReleaseResponse {
    id: u64,
    tag_name: String,
    html_url: String,
    body: Option<String>,
    published_at: Option<String>,
    draft: bool,
    prerelease: bool,
    assets: Vec<GitHubReleaseAssetResponse>,
}

#[derive(Debug, Deserialize, Clone)]
struct GitHubReleaseAssetResponse {
    name: String,
    browser_download_url: String,
}

pub fn verify_signature(payload: &[u8], signature_bytes: &[u8]) -> Result<()> {
    let public_key = UPDATE_PUBLIC_KEY.trim();
    if public_key.is_empty() {
        bail!("embedded update public key file is empty")
    }
    verify_signature_with_public_key(payload, signature_bytes, public_key)
}

pub fn verify_signature_with_public_key(
    payload: &[u8],
    signature_bytes: &[u8],
    public_key_b64: &str,
) -> Result<()> {
    let public_key_bytes = STANDARD
        .decode(public_key_b64.trim())
        .context("decoding embedded updater public key")?;
    let verifying_key = VerifyingKey::from_bytes(
        &public_key_bytes
            .try_into()
            .map_err(|_| anyhow!("updater public key must be 32 bytes"))?,
    )
    .context("constructing updater public key")?;
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|error| anyhow!("invalid update signature: {error}"))?;
    verifying_key
        .verify(payload, &signature)
        .context("update signature verification failed")
}

pub fn should_check_updates(last_checked_at: Option<&str>) -> bool {
    let Some(last_checked_at) = last_checked_at else {
        return true;
    };
    let Ok(timestamp) = DateTime::parse_from_rfc3339(last_checked_at) else {
        return true;
    };
    Utc::now() - timestamp.with_timezone(&Utc) >= Duration::hours(24)
}

fn release_from_responses(releases: &[GitHubReleaseResponse]) -> Result<ReleaseInfo> {
    let latest = releases
        .iter()
        .filter(|release| !release.draft && !release.prerelease)
        .filter_map(|release| {
            let published_at = release.published_at.clone()?;
            let timestamp = DateTime::parse_from_rfc3339(&published_at).ok()?;
            Some((timestamp, release))
        })
        .max_by_key(|(timestamp, _)| *timestamp)
        .map(|(_, release)| release)
        .ok_or_else(|| anyhow!("no published GitHub releases were found"))?;

    let assets = latest
        .assets
        .iter()
        .filter(|asset| !asset.name.ends_with(".sig"))
        .filter_map(|asset| {
            let (os, arch) = parse_asset_platform(&asset.name)?;
            let signature_name = format!("{}.sig", asset.name);
            let signature_asset = latest
                .assets
                .iter()
                .find(|candidate| candidate.name == signature_name)?;
            Some(ReleaseAsset {
                name: asset.name.clone(),
                download_url: asset.browser_download_url.clone(),
                signature_url: signature_asset.browser_download_url.clone(),
                os,
                arch,
            })
        })
        .collect::<Vec<_>>();

    Ok(ReleaseInfo {
        id: latest.id,
        tag_name: latest.tag_name.clone(),
        published_at: latest
            .published_at
            .clone()
            .unwrap_or_else(|| Utc::now().to_rfc3339()),
        html_url: latest.html_url.clone(),
        notes: latest.body.clone().unwrap_or_default(),
        assets,
    })
}

fn select_release_asset(release: &ReleaseInfo, os: &str, arch: &str) -> Result<ReleaseAsset> {
    release
        .assets
        .iter()
        .find(|asset| asset.os == os && asset.arch == arch)
        .cloned()
        .ok_or_else(|| anyhow!("no release asset found for {os}/{arch}"))
}

fn parse_asset_platform(name: &str) -> Option<(String, String)> {
    let name = name.strip_suffix(".zip")?;
    let parts = name.split('-').collect::<Vec<_>>();
    if parts.len() < 3 {
        return None;
    }
    Some((
        parts[parts.len() - 2].to_string(),
        parts[parts.len() - 1].to_string(),
    ))
}

fn current_os() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macos",
        "windows" => "windows",
        "linux" => "linux",
        other => other,
    }
}

fn current_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => other,
    }
}

fn detect_install_root(executable_path: &Path) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let macos_dir = executable_path.parent()?;
        if macos_dir.file_name()?.to_string_lossy() != "MacOS" {
            return None;
        }
        let contents_dir = macos_dir.parent()?;
        if contents_dir.file_name()?.to_string_lossy() != "Contents" {
            return None;
        }
        let app_dir = contents_dir.parent()?;
        if app_dir.extension().is_some_and(|ext| ext == "app") {
            return Some(app_dir.to_path_buf());
        }
        return None;
    }

    #[cfg(not(target_os = "macos"))]
    {
        let parent = executable_path.parent()?;
        if parent.file_name()?.to_string_lossy() == "PuppyTerm" {
            Some(parent.to_path_buf())
        } else {
            None
        }
    }
}

fn locate_staged_install(extracted_root: &Path, _build: &InstalledBuild) -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let app_path = extracted_root.join("PuppyTerm.app");
        if app_path.exists() {
            return Ok(app_path);
        }
        bail!("macOS update archive does not contain PuppyTerm.app");
    }

    #[cfg(not(target_os = "macos"))]
    {
        let dir_path = extracted_root.join("PuppyTerm");
        if dir_path.exists() {
            return Ok(dir_path);
        }
        let fallback = extracted_root.join(if build.os == "windows" {
            "PuppyTerm.exe"
        } else {
            "PuppyTerm"
        });
        if fallback.exists() {
            return Ok(extracted_root.to_path_buf());
        }
        bail!("update archive does not contain a staged PuppyTerm install")
    }
}

fn extract_zip_archive(bytes: &[u8], destination: &Path) -> Result<()> {
    let cursor = Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor).context("opening update archive")?;
    for index in 0..archive.len() {
        let mut file = archive.by_index(index).context("reading archive entry")?;
        let out_path = destination.join(file.mangled_name());
        if file.name().ends_with('/') {
            fs::create_dir_all(&out_path)
                .with_context(|| format!("creating {}", out_path.display()))?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut output = fs::File::create(&out_path)
            .with_context(|| format!("creating {}", out_path.display()))?;
        std::io::copy(&mut file, &mut output)
            .with_context(|| format!("extracting {}", out_path.display()))?;
        #[cfg(unix)]
        if let Some(mode) = file.unix_mode() {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&out_path, fs::Permissions::from_mode(mode))
                .with_context(|| format!("setting permissions for {}", out_path.display()))?;
        }
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn spawn_unix_install_helper(
    install_root: &Path,
    staged_path: &Path,
    relaunch_command: &[String],
    updates_root: &Path,
) -> Result<()> {
    let script_path = updates_root.join("apply_update.sh");
    let relaunch_line = relaunch_command
        .iter()
        .map(|part| format!("\"{}\"", part.replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(" ");
    let script = format!(
        "#!/bin/sh\nset -e\nPID=\"{}\"\nTARGET=\"{}\"\nSTAGED=\"{}\"\nwhile kill -0 \"$PID\" 2>/dev/null; do sleep 1; done\nrm -rf \"$TARGET.old\"\nif [ -e \"$TARGET\" ]; then mv \"$TARGET\" \"$TARGET.old\"; fi\nmv \"$STAGED\" \"$TARGET\"\nrm -rf \"$TARGET.old\"\n{} &\n",
        std::process::id(),
        install_root.display(),
        staged_path.display(),
        relaunch_line,
    );
    fs::write(&script_path, script)
        .with_context(|| format!("writing {}", script_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("setting permissions for {}", script_path.display()))?;
    }
    Command::new("/bin/sh")
        .arg(script_path)
        .spawn()
        .context("spawning update install helper")?;
    std::process::exit(0);
}

#[cfg(target_os = "windows")]
fn spawn_windows_install_helper(
    install_root: &Path,
    staged_path: &Path,
    updates_root: &Path,
) -> Result<()> {
    let script_path = updates_root.join("apply_update.cmd");
    let executable = install_root.join("PuppyTerm.exe");
    let script = format!(
        "@echo off\r\nset PID={}\r\n:wait\r\ntasklist /FI \"PID eq %PID%\" | findstr /I \"%PID%\" >nul\r\nif not errorlevel 1 (\r\n  timeout /t 1 /nobreak >nul\r\n  goto wait\r\n)\r\nif exist \"{}\\.old\" rmdir /S /Q \"{}\\.old\"\r\nif exist \"{}\" move \"{}\" \"{}\\.old\"\r\nmove \"{}\" \"{}\"\r\nstart \"\" \"{}\"\r\n",
        std::process::id(),
        install_root.display(),
        install_root.display(),
        install_root.display(),
        install_root.display(),
        install_root.display(),
        staged_path.display(),
        install_root.display(),
        executable.display(),
    );
    fs::write(&script_path, script)
        .with_context(|| format!("writing {}", script_path.display()))?;
    Command::new("cmd")
        .arg("/C")
        .arg(script_path)
        .spawn()
        .context("spawning Windows update helper")?;
    std::process::exit(0);
}

pub fn derive_public_key_base64(secret_key_b64: &str) -> Result<String> {
    let secret_key = decode_signing_key(secret_key_b64)?;
    let signing_key = SigningKey::from_bytes(&secret_key);
    Ok(STANDARD.encode(signing_key.verifying_key().to_bytes()))
}

pub fn sign_payload(secret_key_b64: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let secret_key = decode_signing_key(secret_key_b64)?;
    let signing_key = SigningKey::from_bytes(&secret_key);
    Ok(ed25519_dalek::Signer::sign(&signing_key, payload)
        .to_bytes()
        .to_vec())
}

fn decode_signing_key(secret_key_b64: &str) -> Result<[u8; 32]> {
    let secret_key = STANDARD
        .decode(secret_key_b64.trim())
        .context("decoding update signing key")?;
    secret_key
        .try_into()
        .map_err(|_| anyhow!("update signing key must decode to exactly 32 bytes"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        GitHubReleaseAssetResponse, GitHubReleaseResponse, InstalledBuild,
        derive_public_key_base64, parse_asset_platform, release_from_responses,
        select_release_asset, should_check_updates, sign_payload, verify_signature_with_public_key,
    };
    use crate::domain::{ReleaseAsset, ReleaseInfo};

    #[test]
    fn selects_release_asset_for_platform() {
        let release = ReleaseInfo {
            id: 1,
            tag_name: "nightly-1".into(),
            published_at: "2026-03-09T10:00:00Z".into(),
            html_url: "https://example.com".into(),
            notes: String::new(),
            assets: vec![
                ReleaseAsset {
                    name: "PuppyTerm-macos-aarch64.zip".into(),
                    download_url: "https://example.com/mac.zip".into(),
                    signature_url: "https://example.com/mac.zip.sig".into(),
                    os: "macos".into(),
                    arch: "aarch64".into(),
                },
                ReleaseAsset {
                    name: "PuppyTerm-linux-x86_64.zip".into(),
                    download_url: "https://example.com/linux.zip".into(),
                    signature_url: "https://example.com/linux.zip.sig".into(),
                    os: "linux".into(),
                    arch: "x86_64".into(),
                },
            ],
        };

        let asset = select_release_asset(&release, "linux", "x86_64").unwrap();
        assert_eq!(asset.name, "PuppyTerm-linux-x86_64.zip");
    }

    #[test]
    fn parses_asset_platform_suffix() {
        assert_eq!(
            parse_asset_platform("PuppyTerm-macos-aarch64.zip"),
            Some(("macos".into(), "aarch64".into()))
        );
    }

    #[test]
    fn throttle_respects_daily_interval() {
        assert!(!should_check_updates(Some("2999-01-01T00:00:00Z")));
        assert!(should_check_updates(Some("2020-01-01T00:00:00Z")));
    }

    #[test]
    fn signs_and_verifies_payload() {
        let secret = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let public = derive_public_key_base64(secret).unwrap();
        let payload = b"puppyterm update";
        let signature = sign_payload(secret, payload).unwrap();

        verify_signature_with_public_key(payload, &signature, &public).unwrap();
    }

    #[test]
    fn empty_public_key_is_rejected() {
        let payload = b"puppyterm update";
        let signature = vec![0_u8; 64];
        let error = verify_signature_with_public_key(payload, &signature, "").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("updater public key must be 32 bytes")
        );
    }

    #[test]
    fn chooses_latest_release_by_publish_time() {
        let releases = vec![
            GitHubReleaseResponse {
                id: 1,
                tag_name: "alpha-build".into(),
                html_url: "https://example.com/1".into(),
                body: Some("older".into()),
                published_at: Some("2026-03-07T10:00:00Z".into()),
                draft: false,
                prerelease: false,
                assets: vec![
                    GitHubReleaseAssetResponse {
                        name: "PuppyTerm-linux-x86_64.zip".into(),
                        browser_download_url: "https://example.com/linux.zip".into(),
                    },
                    GitHubReleaseAssetResponse {
                        name: "PuppyTerm-linux-x86_64.zip.sig".into(),
                        browser_download_url: "https://example.com/linux.zip.sig".into(),
                    },
                ],
            },
            GitHubReleaseResponse {
                id: 2,
                tag_name: "weird-tag".into(),
                html_url: "https://example.com/2".into(),
                body: Some("newer".into()),
                published_at: Some("2026-03-09T10:00:00Z".into()),
                draft: false,
                prerelease: false,
                assets: vec![
                    GitHubReleaseAssetResponse {
                        name: "PuppyTerm-linux-x86_64.zip".into(),
                        browser_download_url: "https://example.com/new-linux.zip".into(),
                    },
                    GitHubReleaseAssetResponse {
                        name: "PuppyTerm-linux-x86_64.zip.sig".into(),
                        browser_download_url: "https://example.com/new-linux.zip.sig".into(),
                    },
                ],
            },
        ];

        let latest = release_from_responses(&releases).unwrap();
        assert_eq!(latest.id, 2);
        assert_eq!(latest.tag_name, "weird-tag");
    }

    #[test]
    fn packaged_build_detection_requires_packaged_layout() {
        let build = InstalledBuild {
            tag_name: "dev".into(),
            version: "0.1.0".into(),
            can_apply_update: false,
            install_root: None,
            executable_path: PathBuf::from("/tmp/target/debug/puppyterm"),
            os: "linux".into(),
            arch: "x86_64".into(),
        };
        assert!(!build.can_apply_update);
    }
}

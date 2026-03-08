use std::{borrow::Cow, collections::BTreeSet, fs, path::PathBuf, sync::Arc};

use anyhow::Result;
use gpui::{
    App, AppContext, Application, AssetSource, Bounds, SharedString, WindowBounds, WindowOptions,
    px, size,
};

use crate::{
    domain::{SessionRecord, StoredKey, SystemProfileIndex, TunnelSpec},
    interop::scan_default_ssh_assets,
    platform::{AppPaths, HybridSecretStore, SecretStore},
    ssh::{BinaryStatus, OpenSshBackend, SshBackend},
    storage::{ProfileRepository, SqliteProfileRepository},
    ui::PuppyTermView,
};

const APP_ICON_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/puppyterm.png");

#[derive(Clone)]
pub struct PuppyTermServices {
    pub paths: AppPaths,
    pub secret_store: Arc<dyn SecretStore>,
    pub repository: Arc<dyn ProfileRepository>,
    pub ssh_backend: Arc<dyn SshBackend>,
}

pub struct BootState {
    pub services: Arc<PuppyTermServices>,
    pub system_index: SystemProfileIndex,
    pub app_profiles: Vec<crate::domain::HostProfile>,
    pub app_keys: Vec<StoredKey>,
    pub tunnels: Vec<TunnelSpec>,
    pub recent_sessions: Vec<SessionRecord>,
    pub binary_status: BinaryStatus,
    pub startup_error: Option<String>,
}

impl BootState {
    pub fn load() -> Self {
        match load_boot_state() {
            Ok(state) => state,
            Err(error) => {
                let paths = AppPaths::discover().unwrap_or(AppPaths {
                    root: std::env::temp_dir().join("puppyterm"),
                    database: std::env::temp_dir().join("puppyterm.sqlite3"),
                    known_hosts: std::env::temp_dir().join("known_hosts"),
                    key_blobs: std::env::temp_dir().join("key_blobs"),
                    secrets: std::env::temp_dir().join("puppyterm-secrets"),
                });
                let secret_store: Arc<dyn SecretStore> =
                    Arc::new(HybridSecretStore::new("com.puppyterm.app", &paths).expect(
                        "boot fallback secret store should be creatable",
                    ));
                let repository: Arc<dyn ProfileRepository> = Arc::new(
                    SqliteProfileRepository::open(&paths.database)
                        .expect("boot fallback repository should be creatable"),
                );
                let backend: Arc<dyn SshBackend> = Arc::new(OpenSshBackend::new(paths.clone()));
                let services = Arc::new(PuppyTermServices {
                    paths,
                    secret_store,
                    repository,
                    ssh_backend: Arc::clone(&backend),
                });
                Self {
                    services,
                    system_index: SystemProfileIndex {
                        profiles: Vec::new(),
                        keys: Vec::new(),
                        known_hosts: Vec::new(),
                    },
                    app_profiles: Vec::new(),
                    app_keys: Vec::new(),
                    tunnels: Vec::new(),
                    recent_sessions: Vec::new(),
                    binary_status: backend.ssh_status(),
                    startup_error: Some(error.to_string()),
                }
            }
        }
    }
}

struct FilesystemAssets {
    base: PathBuf,
}

impl AssetSource for FilesystemAssets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        Ok(Some(Cow::Owned(fs::read(self.base.join(path))?)))
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        Ok(fs::read_dir(self.base.join(path))?
            .filter_map(|entry| {
                entry.ok().map(|entry| {
                    SharedString::from(entry.file_name().to_string_lossy().into_owned())
                })
            })
            .collect())
    }
}

fn load_boot_state() -> Result<BootState> {
    let paths = AppPaths::discover()?;
    let secret_store: Arc<dyn SecretStore> =
        Arc::new(HybridSecretStore::new("com.puppyterm.app", &paths)?);
    let repository: Arc<dyn ProfileRepository> =
        Arc::new(SqliteProfileRepository::open(&paths.database)?);
    let backend: Arc<dyn SshBackend> = Arc::new(OpenSshBackend::new(paths.clone()));
    let services = Arc::new(PuppyTermServices {
        paths: paths.clone(),
        secret_store,
        repository: Arc::clone(&repository),
        ssh_backend: Arc::clone(&backend),
    });

    let system_index = scan_default_ssh_assets().unwrap_or(SystemProfileIndex {
        profiles: Vec::new(),
        keys: Vec::new(),
        known_hosts: Vec::new(),
    });
    merge_known_hosts(&paths.known_hosts, &system_index.known_hosts)?;

    Ok(BootState {
        services,
        app_profiles: repository.load_app_profiles()?,
        app_keys: repository.list_keys()?,
        tunnels: repository.list_tunnels()?,
        recent_sessions: repository.recent_sessions()?,
        binary_status: backend.ssh_status(),
        system_index,
        startup_error: None,
    })
}

fn merge_known_hosts(
    path: &std::path::Path,
    known_hosts: &[crate::domain::KnownHostEntry],
) -> Result<()> {
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let mut lines = existing
        .lines()
        .map(ToOwned::to_owned)
        .filter(|line| !line.trim().is_empty())
        .collect::<BTreeSet<_>>();
    for entry in known_hosts {
        lines.insert(format!(
            "{} {} {}",
            entry.hosts.join(","),
            entry.key_type,
            entry.key
        ));
    }
    std::fs::write(
        path,
        lines.into_iter().collect::<Vec<_>>().join("\n") + "\n",
    )?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn set_macos_app_icon() {
    use cocoa::{
        appkit::{NSApp, NSApplication, NSImage},
        base::{id, nil},
        foundation::NSString,
    };

    unsafe {
        let path = NSString::alloc(nil).init_str(APP_ICON_PATH);
        let image: id = NSImage::alloc(nil).initByReferencingFile_(path);
        if image != nil {
            let app = NSApp();
            if app != nil {
                app.setApplicationIconImage_(image);
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn set_macos_app_icon() {}

pub fn run() {
    Application::new()
        .with_assets(FilesystemAssets {
            base: PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        })
        .run(|cx: &mut App| {
            set_macos_app_icon();
            let boot = BootState::load();
            let bounds = Bounds::centered(None, size(px(1480.0), px(920.0)), cx);
            cx.open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(bounds)),
                    ..Default::default()
                },
                move |window, cx| {
                    cx.new(|cx| {
                        let terminal_focus = cx.focus_handle();
                        terminal_focus.focus(window);
                        PuppyTermView::new(boot, terminal_focus, cx)
                    })
                },
            )
            .expect("window should open");
            cx.activate(true);
        });
}

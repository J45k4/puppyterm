use std::{collections::HashMap, process::Command, sync::Arc, time::Duration};

use gpui::{
    App, ClipboardItem, Context, CursorStyle, FocusHandle, Focusable, FontWeight, KeyDownEvent,
    MouseButton, MouseDownEvent, MouseMoveEvent, MouseUpEvent, PathPromptOptions, Pixels, Point,
    Render, ScrollWheelEvent, SharedString, StyledText, TextRun, Timer, Window, div, font, img,
    prelude::*, px, rgb,
};
use uuid::Uuid;

use crate::{
    app::{BootState, PuppyTermServices},
    domain::{AuthMethod, HostProfile, ProfileSource, StoredKey, SystemProfileIndex, TunnelMode, TunnelSpec},
    interop::scan_default_ssh_assets,
    ssh::{ManagedTunnel, SftpOperation},
    terminal::TerminalSessionHandle,
};

const SIDEBAR_LOGO_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/puppyterm.png");

#[derive(Clone)]
enum WorkspaceTabKind {
    Menu,
    Profile { profile_id: String },
    SftpBrowser { profile_id: String },
    ProfileEditor { editor_id: String },
    IdentityEditor { editor_id: String },
    Session { session_id: String },
    TunnelEditor { editor_id: String },
    TextPreview { title: String, body: String },
}

#[derive(Clone)]
struct WorkspaceTab {
    id: String,
    title: String,
    kind: WorkspaceTabKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActivePaneResize {
    Sidebar,
    Detail,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MenuSection {
    Hosts,
    Identities,
    PortForwarding,
    Sftp,
}

pub struct PuppyTermView {
    services: Arc<PuppyTermServices>,
    system_index: SystemProfileIndex,
    app_profiles: Vec<HostProfile>,
    app_keys: Vec<StoredKey>,
    tunnels: Vec<TunnelSpec>,
    recent_sessions: Vec<crate::domain::SessionRecord>,
    binary_status: crate::ssh::BinaryStatus,
    startup_error: Option<String>,
    tabs: Vec<WorkspaceTab>,
    active_tab: usize,
    log_lines: Vec<String>,
    live_sessions: HashMap<String, TerminalSessionHandle>,
    live_tunnels: HashMap<String, ManagedTunnel>,
    selected_profile_id: Option<String>,
    profile_editor_focus: FocusHandle,
    profile_editors: HashMap<String, ProfileEditorState>,
    identity_editor_focus: FocusHandle,
    identity_editors: HashMap<String, IdentityEditorState>,
    tunnel_editor_focus: FocusHandle,
    tunnel_editors: HashMap<String, TunnelEditorState>,
    tunnel_context_menu: Option<TunnelContextMenuState>,
    profile_context_menu: Option<ProfileContextMenuState>,
    terminal_selection_session_id: Option<String>,
    terminal_selection_anchor: Option<TerminalGridPoint>,
    terminal_selection_focus: Option<TerminalGridPoint>,
    terminal_is_selecting: bool,
    terminal_focus: FocusHandle,
    sidebar_width: Pixels,
    detail_width: Pixels,
    active_resize: Option<ActivePaneResize>,
    selected_menu_section: MenuSection,
    sftp_browsers: HashMap<String, SftpBrowserState>,
}

#[derive(Clone, Debug)]
struct SftpBrowserEntry {
    name: String,
    is_dir: bool,
    detail: String,
}

#[derive(Clone, Debug)]
struct SftpBrowserState {
    profile_id: String,
    path: String,
    entries: Vec<SftpBrowserEntry>,
    error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TerminalGridPoint {
    row: usize,
    col: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TunnelFormField {
    Name,
    BindHost,
    BindPort,
    TargetHost,
    TargetPort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TunnelEditorStep {
    SelectProfile,
    Configure,
}

#[derive(Clone, Debug)]
struct TunnelEditorState {
    tunnel_id: String,
    existing_tunnel_id: Option<String>,
    step: TunnelEditorStep,
    name: String,
    profile_id: String,
    mode: TunnelMode,
    bind_host: String,
    bind_port: String,
    target_host: String,
    target_port: String,
    focused_field: TunnelFormField,
    cursor_offset: usize,
    select_all: bool,
    error: Option<String>,
}

#[derive(Clone, Debug)]
struct TunnelContextMenuState {
    tunnel_id: String,
}

#[derive(Clone, Debug)]
struct ProfileContextMenuState {
    profile_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProfileFormField {
    DisplayName,
    Hostname,
    Username,
    Port,
    IdentityPath,
    Password,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProfileAuthMode {
    Identity,
    Password,
}

#[derive(Clone, Debug)]
struct ProfileEditorState {
    editor_id: String,
    profile_id: String,
    display_name: String,
    hostname: String,
    username: String,
    port: String,
    auth_mode: ProfileAuthMode,
    identity_path: String,
    password: String,
    password_secret_id: Option<String>,
    password_revealed: bool,
    focused_field: ProfileFormField,
    cursor_offset: usize,
    select_all: bool,
    error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentityFormField {
    Name,
    PrivateKeyPath,
    PublicKeyPath,
    Fingerprint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentityInputMode {
    Existing,
    CreateNew,
}

#[derive(Clone, Debug)]
struct IdentityEditorState {
    editor_id: String,
    key_id: String,
    input_mode: IdentityInputMode,
    name: String,
    private_key_path: String,
    public_key_path: String,
    fingerprint: String,
    focused_field: IdentityFormField,
    cursor_offset: usize,
    select_all: bool,
    error: Option<String>,
}

impl PuppyTermView {
    pub fn new(boot: BootState, terminal_focus: FocusHandle, cx: &mut Context<Self>) -> Self {
        let selected_profile_id = boot
            .system_index
            .profiles
            .first()
            .or_else(|| boot.app_profiles.first())
            .map(|profile| profile.id.clone());
        let profile_editor_focus = cx.focus_handle();
        let identity_editor_focus = cx.focus_handle();
        let tunnel_editor_focus = cx.focus_handle();

        let this = Self {
            services: boot.services,
            system_index: boot.system_index,
            app_profiles: boot.app_profiles,
            app_keys: boot.app_keys,
            tunnels: boot.tunnels,
            recent_sessions: boot.recent_sessions,
            binary_status: boot.binary_status,
            startup_error: boot.startup_error,
            tabs: vec![WorkspaceTab {
                id: "menu".into(),
                title: "Menu".into(),
                kind: WorkspaceTabKind::Menu,
            }],
            active_tab: 0,
            log_lines: vec!["PuppyTerm initialized.".into()],
            live_sessions: HashMap::new(),
            live_tunnels: HashMap::new(),
            selected_profile_id: selected_profile_id.clone(),
            profile_editor_focus,
            profile_editors: HashMap::new(),
            identity_editor_focus,
            identity_editors: HashMap::new(),
            tunnel_editor_focus,
            tunnel_editors: HashMap::new(),
            tunnel_context_menu: None,
            profile_context_menu: None,
            terminal_selection_session_id: None,
            terminal_selection_anchor: None,
            terminal_selection_focus: None,
            terminal_is_selecting: false,
            terminal_focus,
            sidebar_width: px(300.0),
            detail_width: px(340.0),
            active_resize: None,
            selected_menu_section: MenuSection::Hosts,
            sftp_browsers: HashMap::new(),
        };

        cx.spawn(async move |this_entity, cx| {
            loop {
                Timer::after(Duration::from_millis(33)).await;
                let keep_running = this_entity
                    .update(cx, |this, cx| {
                        if !this.live_sessions.is_empty() {
                            cx.notify();
                        }
                    })
                    .is_ok();
                if !keep_running {
                    break;
                }
            }
        })
        .detach();

        this
    }

    fn all_profiles(&self) -> Vec<&HostProfile> {
        self.system_index
            .profiles
            .iter()
            .chain(self.app_profiles.iter())
            .collect()
    }

    fn selected_profile(&self) -> Option<&HostProfile> {
        let selected = self.selected_profile_id.as_deref()?;
        self.all_profiles()
            .into_iter()
            .find(|profile| profile.id == selected)
    }

    fn active_session_handle(&self) -> Option<TerminalSessionHandle> {
        let tab = self.tabs.get(self.active_tab)?;
        match &tab.kind {
            WorkspaceTabKind::Session { session_id } => self.live_sessions.get(session_id).cloned(),
            _ => None,
        }
    }

    fn active_session_id(&self) -> Option<&str> {
        let tab = self.tabs.get(self.active_tab)?;
        match &tab.kind {
            WorkspaceTabKind::Session { session_id } => Some(session_id.as_str()),
            _ => None,
        }
    }

    fn add_log(&mut self, message: impl Into<String>) {
        self.log_lines.push(message.into());
        if self.log_lines.len() > 200 {
            let overflow = self.log_lines.len().saturating_sub(200);
            self.log_lines.drain(..overflow);
        }
    }

    fn default_tunnel_editor(&self) -> Option<TunnelEditorState> {
        let profile = self
            .selected_profile()
            .cloned()
            .or_else(|| self.all_profiles().into_iter().next().cloned())?;
        Some(TunnelEditorState {
            tunnel_id: Uuid::new_v4().to_string(),
            existing_tunnel_id: None,
            step: TunnelEditorStep::SelectProfile,
            name: String::new(),
            profile_id: profile.id.clone(),
            mode: TunnelMode::Local,
            bind_host: "127.0.0.1".into(),
            bind_port: "8080".into(),
            target_host: "127.0.0.1".into(),
            target_port: "80".into(),
            focused_field: TunnelFormField::Name,
            cursor_offset: profile.display_name.chars().count() + " Tunnel".chars().count(),
            select_all: false,
            error: None,
        })
    }

    fn default_profile_editor(&self) -> ProfileEditorState {
        ProfileEditorState {
            editor_id: Uuid::new_v4().to_string(),
            profile_id: Uuid::new_v4().to_string(),
            display_name: String::new(),
            hostname: String::new(),
            username: String::new(),
            port: "22".into(),
            auth_mode: ProfileAuthMode::Identity,
            identity_path: String::new(),
            password: String::new(),
            password_secret_id: None,
            password_revealed: false,
            focused_field: ProfileFormField::DisplayName,
            cursor_offset: 0,
            select_all: false,
            error: None,
        }
    }

    fn default_identity_editor(&self) -> IdentityEditorState {
        IdentityEditorState {
            editor_id: Uuid::new_v4().to_string(),
            key_id: Uuid::new_v4().to_string(),
            input_mode: IdentityInputMode::Existing,
            name: String::new(),
            private_key_path: String::new(),
            public_key_path: String::new(),
            fingerprint: String::new(),
            focused_field: IdentityFormField::Name,
            cursor_offset: 0,
            select_all: false,
            error: None,
        }
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        match scan_default_ssh_assets() {
            Ok(index) => {
                self.system_index = index;
                if let Ok(app_profiles) = self.services.repository.load_app_profiles() {
                    self.app_profiles = app_profiles;
                }
                if let Ok(keys) = self.services.repository.list_keys() {
                    self.app_keys = keys;
                }
                if let Ok(tunnels) = self.services.repository.list_tunnels() {
                    self.tunnels = tunnels;
                }
                if let Ok(sessions) = self.services.repository.recent_sessions() {
                    self.recent_sessions = sessions;
                }
                self.binary_status = self.services.ssh_backend.ssh_status();
                self.add_log("Refreshed OpenSSH discovery and local state.");
            }
            Err(error) => self.add_log(format!("Refresh failed: {error}")),
        }
        cx.notify();
    }

    fn import_selected_profile(&mut self, cx: &mut Context<Self>) {
        let Some(profile) = self.selected_profile().cloned() else {
            return;
        };
        if profile.source != ProfileSource::SystemDiscovered {
            self.add_log("Selected profile is already app-managed.");
            cx.notify();
            return;
        }

        match self.services.repository.duplicate_system_profile(&profile) {
            Ok(imported) => {
                self.app_profiles.insert(0, imported.clone());
                self.selected_profile_id = Some(imported.id.clone());
                self.add_log(format!(
                    "Imported {} into app-managed profiles.",
                    profile.display_name
                ));
            }
            Err(error) => self.add_log(format!("Import failed: {error}")),
        }
        cx.notify();
    }

    fn open_profile_tab(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        if let Some((index, _)) = self.tabs.iter().enumerate().find(|(_, tab)| {
            matches!(&tab.kind, WorkspaceTabKind::Profile { profile_id: existing } if existing == profile_id)
        }) {
            self.active_tab = index;
            cx.notify();
            return;
        }

        let title = self
            .all_profiles()
            .into_iter()
            .find(|profile| profile.id == profile_id)
            .map(|profile| profile.display_name.clone())
            .unwrap_or_else(|| "Profile".into());
        self.tabs.push(WorkspaceTab {
            id: Uuid::new_v4().to_string(),
            title,
            kind: WorkspaceTabKind::Profile {
                profile_id: profile_id.into(),
            },
        });
        self.active_tab = self.tabs.len().saturating_sub(1);
        cx.notify();
    }

    fn tab_is_closable(tab: &WorkspaceTab) -> bool {
        !matches!(tab.kind, WorkspaceTabKind::Menu)
    }

    fn close_tab(&mut self, tab_index: usize, cx: &mut Context<Self>) {
        if tab_index >= self.tabs.len() {
            return;
        }

        let tab = self.tabs[tab_index].clone();
        if !Self::tab_is_closable(&tab) {
            return;
        }

        if let WorkspaceTabKind::Session { session_id } = &tab.kind {
            if let Some(handle) = self.live_sessions.remove(session_id) {
                if let Err(error) = handle.terminate() {
                    self.add_log(format!("Session shutdown failed: {error}"));
                }
            }
            if self.terminal_selection_session_id.as_deref() == Some(session_id.as_str()) {
                self.clear_terminal_selection();
            }
        }
        if let WorkspaceTabKind::TunnelEditor { editor_id } = &tab.kind {
            self.tunnel_editors.remove(editor_id);
        }
        if let WorkspaceTabKind::ProfileEditor { editor_id } = &tab.kind {
            self.profile_editors.remove(editor_id);
        }
        if let WorkspaceTabKind::IdentityEditor { editor_id } = &tab.kind {
            self.identity_editors.remove(editor_id);
        }

        self.tabs.remove(tab_index);

        if self.tabs.is_empty() {
            self.tabs.push(WorkspaceTab {
                id: "menu".into(),
                title: "Menu".into(),
                kind: WorkspaceTabKind::Menu,
            });
            self.active_tab = 0;
        } else if self.active_tab > tab_index {
            self.active_tab -= 1;
        } else if self.active_tab >= self.tabs.len() {
            self.active_tab = self.tabs.len().saturating_sub(1);
        }

        self.add_log(format!("Closed tab {}.", tab.title));
        cx.notify();
    }

    fn open_menu(&mut self, section: MenuSection, cx: &mut Context<Self>) {
        self.selected_menu_section = section;
        if let Some((index, _)) = self
            .tabs
            .iter()
            .enumerate()
            .find(|(_, tab)| matches!(tab.kind, WorkspaceTabKind::Menu))
        {
            self.active_tab = index;
            cx.notify();
            return;
        }

        self.tabs.insert(
            0,
            WorkspaceTab {
                id: "menu".into(),
                title: "Menu".into(),
                kind: WorkspaceTabKind::Menu,
            },
        );
        self.active_tab = 0;
        cx.notify();
    }

    fn active_sftp_profile_id(&self) -> Option<&str> {
        let tab = self.tabs.get(self.active_tab)?;
        match &tab.kind {
            WorkspaceTabKind::SftpBrowser { profile_id } => Some(profile_id.as_str()),
            _ => None,
        }
    }

    fn open_sftp_browser(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        if let Some((index, _)) = self.tabs.iter().enumerate().find(|(_, tab)| {
            matches!(&tab.kind, WorkspaceTabKind::SftpBrowser { profile_id: existing } if existing == profile_id)
        }) {
            self.active_tab = index;
            cx.notify();
            return;
        }

        let title = self
            .all_profiles()
            .into_iter()
            .find(|profile| profile.id == profile_id)
            .map(|profile| format!("SFTP {}", profile.display_name))
            .unwrap_or_else(|| "SFTP".into());
        self.tabs.push(WorkspaceTab {
            id: Uuid::new_v4().to_string(),
            title,
            kind: WorkspaceTabKind::SftpBrowser {
                profile_id: profile_id.to_string(),
            },
        });
        self.active_tab = self.tabs.len().saturating_sub(1);
        self.sftp_browsers
            .entry(profile_id.to_string())
            .or_insert_with(|| SftpBrowserState {
                profile_id: profile_id.to_string(),
                path: ".".into(),
                entries: Vec::new(),
                error: None,
            });
        self.refresh_sftp_browser(profile_id, cx);
    }

    fn refresh_sftp_browser(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(profile) = self
            .all_profiles()
            .into_iter()
            .find(|profile| profile.id == profile_id)
            .cloned()
        else {
            return;
        };

        let browser = self
            .sftp_browsers
            .entry(profile_id.to_string())
            .or_insert_with(|| SftpBrowserState {
                profile_id: profile_id.to_string(),
                path: ".".into(),
                entries: Vec::new(),
                error: None,
            });

        let operation = SftpOperation::ListDirectory {
            path: browser.path.clone(),
        };

        match self.services.ssh_backend.run_sftp_op(&profile, &operation) {
            Ok(result) => {
                browser.entries = parse_sftp_entries(&result.stdout);
                browser.error = if result.success {
                    None
                } else {
                    Some(result.stderr)
                };
            }
            Err(error) => {
                browser.entries.clear();
                browser.error = Some(error.to_string());
            }
        }
        cx.notify();
    }

    fn open_sftp_entry(&mut self, profile_id: &str, name: &str, cx: &mut Context<Self>) {
        if name == "." {
            return;
        }
        if name == ".." {
            self.go_up_sftp_directory(profile_id, cx);
            return;
        }

        if let Some(browser) = self.sftp_browsers.get_mut(profile_id) {
            browser.path = join_remote_path(&browser.path, name);
        }
        self.refresh_sftp_browser(profile_id, cx);
    }

    fn go_up_sftp_directory(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        if let Some(browser) = self.sftp_browsers.get_mut(profile_id) {
            browser.path = parent_remote_path(&browser.path);
        }
        self.refresh_sftp_browser(profile_id, cx);
    }

    fn open_profile_editor(&mut self, cx: &mut Context<Self>) {
        let editor = self.default_profile_editor();
        let editor_id = editor.editor_id.clone();
        self.profile_editors.insert(editor_id.clone(), editor);
        self.tabs.push(WorkspaceTab {
            id: Uuid::new_v4().to_string(),
            title: "New SSH".into(),
            kind: WorkspaceTabKind::ProfileEditor { editor_id },
        });
        self.active_tab = self.tabs.len().saturating_sub(1);
        cx.notify();
    }

    fn open_profile_context_menu(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        self.profile_context_menu = Some(ProfileContextMenuState {
            profile_id: profile_id.to_string(),
        });
        cx.notify();
    }

    fn edit_profile_config(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        let Some(profile) = self
            .app_profiles
            .iter()
            .find(|profile| profile.id == profile_id)
            .cloned()
        else {
            return;
        };

        let (auth_mode, password_secret_id, password) = match &profile.auth_method {
            AuthMethod::Password { secret_id } => (
                ProfileAuthMode::Password,
                Some(secret_id.clone()),
                String::new(),
            ),
            _ => (ProfileAuthMode::Identity, None, String::new()),
        };

        let editor = ProfileEditorState {
            editor_id: Uuid::new_v4().to_string(),
            profile_id: profile.id.clone(),
            display_name: profile.display_name.clone(),
            hostname: profile.hostname.clone(),
            username: profile.username.clone().unwrap_or_default(),
            port: profile.port.to_string(),
            auth_mode,
            identity_path: profile
                .identity_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            password,
            password_secret_id,
            password_revealed: false,
            focused_field: ProfileFormField::DisplayName,
            cursor_offset: profile.display_name.chars().count(),
            select_all: false,
            error: None,
        };
        let editor_id = editor.editor_id.clone();
        self.profile_editors.insert(editor_id.clone(), editor);
        self.profile_context_menu = None;
        self.tabs.push(WorkspaceTab {
            id: Uuid::new_v4().to_string(),
            title: format!("Edit {}", profile.display_name),
            kind: WorkspaceTabKind::ProfileEditor { editor_id },
        });
        self.active_tab = self.tabs.len().saturating_sub(1);
        cx.notify();
    }

    fn open_identity_editor(&mut self, cx: &mut Context<Self>) {
        let editor = self.default_identity_editor();
        let editor_id = editor.editor_id.clone();
        self.identity_editors.insert(editor_id.clone(), editor);
        self.tabs.push(WorkspaceTab {
            id: Uuid::new_v4().to_string(),
            title: "New Identity".into(),
            kind: WorkspaceTabKind::IdentityEditor { editor_id },
        });
        self.active_tab = self.tabs.len().saturating_sub(1);
        cx.notify();
    }

    fn open_identity_public_key_preview(&mut self, key_id: &str, cx: &mut Context<Self>) {
        let key = self
            .system_index
            .keys
            .iter()
            .chain(self.app_keys.iter())
            .find(|key| key.id == key_id)
            .cloned();
        let Some(key) = key else {
            return;
        };

        let title = format!("Public Key {}", key.name);
        if let Some((index, _)) = self.tabs.iter().enumerate().find(|(_, tab)| {
            matches!(&tab.kind, WorkspaceTabKind::TextPreview { title: existing, .. } if existing == &title)
        }) {
            self.active_tab = index;
            cx.notify();
            return;
        }

        let body = identity_public_key_preview_body(&key);
        self.tabs.push(WorkspaceTab {
            id: Uuid::new_v4().to_string(),
            title: key.name.clone(),
            kind: WorkspaceTabKind::TextPreview { title, body },
        });
        self.active_tab = self.tabs.len().saturating_sub(1);
        cx.notify();
    }

    fn copy_identity_public_key(&mut self, key_id: &str, cx: &mut Context<Self>) {
        let key = self
            .system_index
            .keys
            .iter()
            .chain(self.app_keys.iter())
            .find(|key| key.id == key_id)
            .cloned();
        let Some(key) = key else {
            return;
        };

        let body = identity_public_key_preview_body(&key);
        if body.starts_with("Could not read public key.")
            || body == "No public key file is associated with this identity."
        {
            self.add_log(format!("Public key copy failed for {}.", key.name));
            cx.notify();
            return;
        }

        cx.write_to_clipboard(ClipboardItem::new_string(body));
        self.add_log(format!("Copied public key for {}.", key.name));
        cx.notify();
    }

    fn select_profile(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        self.selected_profile_id = Some(profile_id.to_string());
        self.open_profile_tab(profile_id, cx);
    }

    fn focus_profile_field(
        &mut self,
        editor_id: &str,
        field: ProfileFormField,
        cx: &mut Context<Self>,
    ) {
        if let Some(editor) = self.profile_editors.get_mut(editor_id) {
            editor.focused_field = field;
            editor.select_all = false;
            editor.cursor_offset = profile_field_value(editor, field).chars().count();
            cx.notify();
        }
    }

    fn focus_profile_field_at(
        &mut self,
        editor_id: &str,
        field: ProfileFormField,
        position: Point<Pixels>,
        window: &Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(editor) = self.profile_editors.get_mut(editor_id) {
            let value = profile_field_value(editor, field).to_string();
            let cursor_offset = Self::editor_cursor_offset_for_mouse(position.x, &value, window);
            editor.focused_field = field;
            editor.select_all = false;
            editor.cursor_offset =
                cursor_offset.min(profile_field_value(editor, field).chars().count());
            cx.notify();
        }
    }

    fn focus_identity_field_at(
        &mut self,
        editor_id: &str,
        field: IdentityFormField,
        position: Point<Pixels>,
        window: &Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(editor) = self.identity_editors.get_mut(editor_id) {
            let value = identity_field_value(editor, field).to_string();
            let cursor_offset = Self::editor_cursor_offset_for_mouse(position.x, &value, window);
            editor.focused_field = field;
            editor.select_all = false;
            editor.cursor_offset =
                cursor_offset.min(identity_field_value(editor, field).chars().count());
            cx.notify();
        }
    }

    fn choose_profile_identity(
        &mut self,
        editor_id: &str,
        identity_path: Option<String>,
        cx: &mut Context<Self>,
    ) {
        if let Some(editor) = self.profile_editors.get_mut(editor_id) {
            editor.auth_mode = ProfileAuthMode::Identity;
            editor.identity_path = identity_path.unwrap_or_default();
            editor.focused_field = ProfileFormField::IdentityPath;
            editor.select_all = false;
            editor.cursor_offset = editor.identity_path.chars().count();
            editor.error = None;
            cx.notify();
        }
    }

    fn select_profile_auth_mode(
        &mut self,
        editor_id: &str,
        auth_mode: ProfileAuthMode,
        cx: &mut Context<Self>,
    ) {
        if let Some(editor) = self.profile_editors.get_mut(editor_id) {
            editor.auth_mode = auth_mode;
            editor.focused_field = match auth_mode {
                ProfileAuthMode::Identity => ProfileFormField::IdentityPath,
                ProfileAuthMode::Password => ProfileFormField::Password,
            };
            editor.password_revealed = false;
            editor.select_all = false;
            editor.cursor_offset = profile_field_value(editor, editor.focused_field)
                .chars()
                .count();
            editor.error = None;
            cx.notify();
        }
    }

    fn toggle_profile_password_reveal(&mut self, editor_id: &str, cx: &mut Context<Self>) {
        let Some(editor) = self.profile_editors.get_mut(editor_id) else {
            return;
        };

        if editor.password_revealed {
            editor.password_revealed = false;
            editor.error = None;
            cx.notify();
            return;
        }

        if editor.password.is_empty() {
            if let Some(secret_id) = editor.password_secret_id.clone() {
                match self.services.secret_store.get_secret(&secret_id) {
                    Ok(Some(password)) => {
                        editor.password = password;
                    }
                    Ok(None) => {
                        editor.error =
                            Some("No saved password was found in the system keychain.".into());
                        cx.notify();
                        return;
                    }
                    Err(error) => {
                        editor.error = Some(format!("Could not load saved password: {error}"));
                        cx.notify();
                        return;
                    }
                }
            }
        }

        editor.password_revealed = true;
        editor.focused_field = ProfileFormField::Password;
        editor.cursor_offset = editor.password.chars().count();
        editor.select_all = false;
        editor.error = None;
        cx.notify();
    }

    fn apply_profile_editor_keystroke(
        &mut self,
        editor_id: &str,
        event: &KeyDownEvent,
        cx: &mut Context<Self>,
    ) -> bool {
        let Some(editor) = self.profile_editors.get_mut(editor_id) else {
            return false;
        };
        let key = event.keystroke.key.to_lowercase();

        if (event.keystroke.modifiers.platform || event.keystroke.modifiers.control) && key == "a" {
            editor.select_all = true;
            editor.cursor_offset = profile_field_value(editor, editor.focused_field)
                .chars()
                .count();
            cx.notify();
            return true;
        }

        match key.as_str() {
            "tab" => {
                let identity_fields = [
                    ProfileFormField::DisplayName,
                    ProfileFormField::Hostname,
                    ProfileFormField::Username,
                    ProfileFormField::Port,
                ];
                let password_fields = [
                    ProfileFormField::DisplayName,
                    ProfileFormField::Hostname,
                    ProfileFormField::Username,
                    ProfileFormField::Port,
                    ProfileFormField::Password,
                ];
                let fields: &[ProfileFormField] = match editor.auth_mode {
                    ProfileAuthMode::Identity => &identity_fields,
                    ProfileAuthMode::Password => &password_fields,
                };
                let current_index = fields
                    .iter()
                    .position(|field| *field == editor.focused_field)
                    .unwrap_or(0);
                let next_index = if event.keystroke.modifiers.shift {
                    current_index
                        .checked_sub(1)
                        .unwrap_or(fields.len().saturating_sub(1))
                } else {
                    (current_index + 1) % fields.len()
                };
                editor.focused_field = fields[next_index];
                editor.select_all = false;
                editor.cursor_offset = profile_field_value(editor, editor.focused_field)
                    .chars()
                    .count();
                cx.notify();
                return true;
            }
            "left" => {
                if editor.select_all {
                    editor.select_all = false;
                    editor.cursor_offset = 0;
                } else {
                    editor.cursor_offset = editor.cursor_offset.saturating_sub(1);
                }
                cx.notify();
                return true;
            }
            "right" => {
                let len = profile_field_value(editor, editor.focused_field)
                    .chars()
                    .count();
                if editor.select_all {
                    editor.select_all = false;
                    editor.cursor_offset = len;
                } else {
                    editor.cursor_offset = (editor.cursor_offset + 1).min(len);
                }
                cx.notify();
                return true;
            }
            "home" => {
                editor.select_all = false;
                editor.cursor_offset = 0;
                cx.notify();
                return true;
            }
            "end" => {
                editor.select_all = false;
                editor.cursor_offset = profile_field_value(editor, editor.focused_field)
                    .chars()
                    .count();
                cx.notify();
                return true;
            }
            "backspace" => {
                let replace_all = editor.select_all;
                if replace_all {
                    editor.select_all = false;
                }
                let mut cursor_offset = editor.cursor_offset;
                let value = profile_field_value_mut(editor, editor.focused_field);
                if replace_all {
                    value.clear();
                    cursor_offset = 0;
                } else {
                    delete_char_before_cursor(value, &mut cursor_offset);
                }
                editor.cursor_offset = cursor_offset;
                cx.notify();
                return true;
            }
            _ => {}
        }

        if event.keystroke.modifiers.control
            || event.keystroke.modifiers.alt
            || event.keystroke.modifiers.platform
        {
            return false;
        }

        if let Some(text) = event.keystroke.key_char.as_ref() {
            if !text.chars().all(|ch| !ch.is_control()) {
                return false;
            }
            let replace_all = editor.select_all;
            if replace_all {
                editor.select_all = false;
            }
            let mut cursor_offset = editor.cursor_offset;
            let value = profile_field_value_mut(editor, editor.focused_field);
            if replace_all {
                value.clear();
                cursor_offset = 0;
            }
            insert_text_at_cursor(value, &mut cursor_offset, text);
            editor.cursor_offset = cursor_offset;
            cx.notify();
            return true;
        }

        false
    }

    fn save_profile_editor(&mut self, editor_id: &str, cx: &mut Context<Self>) {
        let Some(editor) = self.profile_editors.get_mut(editor_id) else {
            return;
        };

        let display_name = editor.display_name.trim();
        let hostname = editor.hostname.trim();
        if display_name.is_empty() || hostname.is_empty() {
            editor.error = Some("Name and host are required.".into());
            cx.notify();
            return;
        }

        let port = match editor.port.trim().parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                editor.error = Some("Port must be a valid number.".into());
                cx.notify();
                return;
            }
        };

        let mut profile = HostProfile::new_app(display_name, hostname);
        profile.id = editor.profile_id.clone();
        profile.port = port;
        profile.username =
            (!editor.username.trim().is_empty()).then_some(editor.username.trim().to_string());
        profile.auth_method = AuthMethod::AgentOnly;

        match editor.auth_mode {
            ProfileAuthMode::Identity => {
                if editor.identity_path.trim().is_empty() {
                    editor.error = Some("Choose an identity for identity-based auth.".into());
                    cx.notify();
                    return;
                }
                profile.identity_path = (!editor.identity_path.trim().is_empty())
                    .then_some(std::path::PathBuf::from(editor.identity_path.trim()));
                if let Some(secret_id) = editor.password_secret_id.clone() {
                    if let Err(error) = self.services.secret_store.delete_secret(&secret_id) {
                        editor.error = Some(format!("Could not clear saved password: {error}"));
                        cx.notify();
                        return;
                    }
                    editor.password_secret_id = None;
                }
            }
            ProfileAuthMode::Password => {
                let password = editor.password.trim().to_string();
                profile.identity_path = None;
                if password.is_empty() {
                    let Some(secret_id) = editor.password_secret_id.clone() else {
                        editor.error =
                            Some("Password is required when password auth is selected.".into());
                        cx.notify();
                        return;
                    };
                    profile.auth_method = AuthMethod::Password { secret_id };
                } else {
                    let secret_id = editor
                        .password_secret_id
                        .clone()
                        .unwrap_or_else(|| format!("profile-password-{}", profile.id));
                    if let Err(error) =
                        self.services.secret_store.put_secret(&secret_id, &password)
                    {
                        editor.error = Some(format!("Could not save password: {error}"));
                        cx.notify();
                        return;
                    }
                    editor.password_secret_id = Some(secret_id.clone());
                    profile.auth_method = AuthMethod::Password { secret_id };
                }
            }
        }

        match self.services.repository.upsert_profile(&profile) {
            Ok(()) => {
                if let Some(existing) = self.app_profiles.iter_mut().find(|item| item.id == profile.id)
                {
                    *existing = profile.clone();
                } else {
                    self.app_profiles.insert(0, profile.clone());
                }
                self.selected_profile_id = Some(profile.id.clone());
                editor.error = None;
                self.add_log(format!("Saved SSH profile {}.", profile.display_name));
                self.close_profile_editor_tab(editor_id, cx);
            }
            Err(error) => {
                editor.error = Some(error.to_string());
                cx.notify();
            }
        }
    }

    fn apply_identity_editor_keystroke(
        &mut self,
        editor_id: &str,
        event: &KeyDownEvent,
        cx: &mut Context<Self>,
    ) -> bool {
        let Some(editor) = self.identity_editors.get_mut(editor_id) else {
            return false;
        };
        let key = event.keystroke.key.to_lowercase();

        if (event.keystroke.modifiers.platform || event.keystroke.modifiers.control) && key == "a" {
            editor.select_all = true;
            editor.cursor_offset = identity_field_value(editor, editor.focused_field)
                .chars()
                .count();
            cx.notify();
            return true;
        }

        match key.as_str() {
            "tab" => {
                let fields = identity_editor_fields(editor.input_mode);
                let current_index = fields
                    .iter()
                    .position(|field| *field == editor.focused_field)
                    .unwrap_or(0);
                let next_index = if event.keystroke.modifiers.shift {
                    current_index
                        .checked_sub(1)
                        .unwrap_or(fields.len().saturating_sub(1))
                } else {
                    (current_index + 1) % fields.len()
                };
                editor.focused_field = fields[next_index];
                editor.select_all = false;
                editor.cursor_offset = identity_field_value(editor, editor.focused_field)
                    .chars()
                    .count();
                cx.notify();
                return true;
            }
            "left" => {
                if editor.select_all {
                    editor.select_all = false;
                    editor.cursor_offset = 0;
                } else {
                    editor.cursor_offset = editor.cursor_offset.saturating_sub(1);
                }
                cx.notify();
                return true;
            }
            "right" => {
                let len = identity_field_value(editor, editor.focused_field)
                    .chars()
                    .count();
                if editor.select_all {
                    editor.select_all = false;
                    editor.cursor_offset = len;
                } else {
                    editor.cursor_offset = (editor.cursor_offset + 1).min(len);
                }
                cx.notify();
                return true;
            }
            "home" => {
                editor.select_all = false;
                editor.cursor_offset = 0;
                cx.notify();
                return true;
            }
            "end" => {
                editor.select_all = false;
                editor.cursor_offset = identity_field_value(editor, editor.focused_field)
                    .chars()
                    .count();
                cx.notify();
                return true;
            }
            "backspace" => {
                let replace_all = editor.select_all;
                if replace_all {
                    editor.select_all = false;
                }
                let mut cursor_offset = editor.cursor_offset;
                let value = identity_field_value_mut(editor, editor.focused_field);
                if replace_all {
                    value.clear();
                    cursor_offset = 0;
                } else {
                    delete_char_before_cursor(value, &mut cursor_offset);
                }
                editor.cursor_offset = cursor_offset;
                cx.notify();
                return true;
            }
            _ => {}
        }

        if event.keystroke.modifiers.control
            || event.keystroke.modifiers.alt
            || event.keystroke.modifiers.platform
        {
            return false;
        }

        if let Some(text) = event.keystroke.key_char.as_ref() {
            if !text.chars().all(|ch| !ch.is_control()) {
                return false;
            }
            let replace_all = editor.select_all;
            if replace_all {
                editor.select_all = false;
            }
            let mut cursor_offset = editor.cursor_offset;
            let value = identity_field_value_mut(editor, editor.focused_field);
            if replace_all {
                value.clear();
                cursor_offset = 0;
            }
            insert_text_at_cursor(value, &mut cursor_offset, text);
            editor.cursor_offset = cursor_offset;
            cx.notify();
            return true;
        }

        false
    }

    fn save_identity_editor(&mut self, editor_id: &str, cx: &mut Context<Self>) {
        let Some(editor) = self.identity_editors.get_mut(editor_id) else {
            return;
        };

        let name = editor.name.trim();
        if name.is_empty() {
            editor.error = Some("Name is required.".into());
            cx.notify();
            return;
        }

        let key = match editor.input_mode {
            IdentityInputMode::Existing => {
                let private_key_path = editor.private_key_path.trim();
                if private_key_path.is_empty() {
                    editor.error = Some("Private key path is required.".into());
                    cx.notify();
                    return;
                }
                StoredKey {
                    id: editor.key_id.clone(),
                    source: ProfileSource::AppManaged,
                    name: name.to_string(),
                    path: Some(std::path::PathBuf::from(private_key_path)),
                    public_key_path: (!editor.public_key_path.trim().is_empty())
                        .then_some(std::path::PathBuf::from(editor.public_key_path.trim())),
                    fingerprint: (!editor.fingerprint.trim().is_empty())
                        .then_some(editor.fingerprint.trim().to_string()),
                    encrypted_blob_path: None,
                    meta: crate::domain::RecordMeta::new(),
                }
            }
            IdentityInputMode::CreateNew => {
                let key_blobs = self.services.paths.key_blobs.clone();
                let key_id = editor.key_id.clone();
                let key_name = editor.name.trim().to_string();
                match generate_new_identity_key(&key_blobs, &key_id, &key_name) {
                    Ok(key) => key,
                    Err(error) => {
                        editor.error = Some(error.to_string());
                        cx.notify();
                        return;
                    }
                }
            }
        };

        match self.services.repository.upsert_key(&key) {
            Ok(()) => {
                self.app_keys.insert(0, key.clone());
                editor.error = None;
                self.add_log(format!("Saved identity {}.", key.name));
                self.close_identity_editor_tab(editor_id, cx);
            }
            Err(error) => {
                editor.error = Some(error.to_string());
                cx.notify();
            }
        }
    }

    fn set_identity_field_value(
        &mut self,
        editor_id: &str,
        field: IdentityFormField,
        value: String,
        cx: &mut Context<Self>,
    ) {
        if let Some(editor) = self.identity_editors.get_mut(editor_id) {
            *identity_field_value_mut(editor, field) = value;
            editor.focused_field = field;
            editor.select_all = false;
            editor.cursor_offset = identity_field_value(editor, field).chars().count();
            editor.error = None;
            cx.notify();
        }
    }

    fn set_identity_input_mode(
        &mut self,
        editor_id: &str,
        mode: IdentityInputMode,
        cx: &mut Context<Self>,
    ) {
        if let Some(editor) = self.identity_editors.get_mut(editor_id) {
            editor.input_mode = mode;
            editor.error = None;
            editor.focused_field = IdentityFormField::Name;
            editor.select_all = false;
            editor.cursor_offset = editor.name.chars().count();
            cx.notify();
        }
    }

    fn pick_identity_file(
        &mut self,
        editor_id: &str,
        field: IdentityFormField,
        cx: &mut Context<Self>,
    ) {
        let editor_id = editor_id.to_string();
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("Select key file".into()),
        });
        cx.spawn(async move |this_entity, cx| {
            let Ok(result) = receiver.await else {
                return;
            };
            let Ok(selection) = result else {
                let _ = this_entity.update(cx, |this, cx| {
                    if let Some(editor) = this.identity_editors.get_mut(editor_id.as_str()) {
                        editor.error = Some("Could not open file picker.".into());
                        cx.notify();
                    }
                });
                return;
            };
            let Some(path) = selection.and_then(|mut paths| paths.drain(..).next()) else {
                return;
            };
            let path_text = path.to_string_lossy().to_string();
            let _ = this_entity.update(cx, |this, cx| {
                this.set_identity_field_value(&editor_id, field, path_text, cx);
            });
        })
        .detach();
    }

    fn close_profile_editor_tab(&mut self, editor_id: &str, cx: &mut Context<Self>) {
        if let Some((index, _)) = self.tabs.iter().enumerate().find(|(_, tab)| {
            matches!(&tab.kind, WorkspaceTabKind::ProfileEditor { editor_id: existing } if existing == editor_id)
        }) {
            self.tabs.remove(index);
            self.profile_editors.remove(editor_id);
            if self.active_tab >= self.tabs.len() {
                self.active_tab = self.tabs.len().saturating_sub(1);
            }
            cx.notify();
        }
    }

    fn close_identity_editor_tab(&mut self, editor_id: &str, cx: &mut Context<Self>) {
        if let Some((index, _)) = self.tabs.iter().enumerate().find(|(_, tab)| {
            matches!(&tab.kind, WorkspaceTabKind::IdentityEditor { editor_id: existing } if existing == editor_id)
        }) {
            self.tabs.remove(index);
            self.identity_editors.remove(editor_id);
            if self.active_tab >= self.tabs.len() {
                self.active_tab = self.tabs.len().saturating_sub(1);
            }
            cx.notify();
        }
    }

    fn create_tunnel_rule(&mut self, cx: &mut Context<Self>) {
        let Some(editor) = self.default_tunnel_editor() else {
            self.add_log("No SSH profile available for a new tunnel.");
            cx.notify();
            return;
        };
        self.open_tunnel_editor(editor, "New Forward", cx);
    }

    fn open_tunnel_editor(
        &mut self,
        editor: TunnelEditorState,
        title: impl Into<String>,
        cx: &mut Context<Self>,
    ) {
        let editor_id = editor.tunnel_id.clone();
        self.tunnel_editors.insert(editor_id.clone(), editor);
        self.tabs.push(WorkspaceTab {
            id: Uuid::new_v4().to_string(),
            title: title.into(),
            kind: WorkspaceTabKind::TunnelEditor {
                editor_id: editor_id.clone(),
            },
        });
        self.active_tab = self.tabs.len().saturating_sub(1);
        self.tunnel_context_menu = None;
        cx.notify();
    }

    fn edit_tunnel_rule(&mut self, tunnel_id: &str, cx: &mut Context<Self>) {
        let Some(tunnel) = self
            .tunnels
            .iter()
            .find(|tunnel| tunnel.id == tunnel_id)
            .cloned()
        else {
            return;
        };

        let editor_id = format!("edit-tunnel-{}", tunnel.id);
        if let Some((index, _)) = self.tabs.iter().enumerate().find(|(_, tab)| {
            matches!(&tab.kind, WorkspaceTabKind::TunnelEditor { editor_id: existing } if existing == &editor_id)
        }) {
            self.active_tab = index;
            self.tunnel_context_menu = None;
            cx.notify();
            return;
        }

        let editor = TunnelEditorState {
            tunnel_id: editor_id,
            existing_tunnel_id: Some(tunnel.id.clone()),
            step: TunnelEditorStep::Configure,
            name: tunnel.name.clone(),
            profile_id: tunnel.profile_id.clone(),
            mode: tunnel.mode,
            bind_host: tunnel.bind_host.clone(),
            bind_port: tunnel.bind_port.to_string(),
            target_host: tunnel.target_host.unwrap_or_default(),
            target_port: tunnel
                .target_port
                .map(|port| port.to_string())
                .unwrap_or_default(),
            focused_field: TunnelFormField::Name,
            cursor_offset: tunnel.name.chars().count(),
            select_all: false,
            error: None,
        };
        self.open_tunnel_editor(editor, format!("Edit {}", tunnel.name), cx);
    }

    fn delete_tunnel_rule(&mut self, tunnel_id: &str, cx: &mut Context<Self>) {
        match self.services.repository.delete_tunnel(tunnel_id) {
            Ok(()) => {
                self.tunnels.retain(|tunnel| tunnel.id != tunnel_id);
                let editor_ids = self
                    .tunnel_editors
                    .iter()
                    .filter_map(|(editor_id, editor)| {
                        (editor.existing_tunnel_id.as_deref() == Some(tunnel_id))
                            .then_some(editor_id.clone())
                    })
                    .collect::<Vec<_>>();
                for editor_id in editor_ids {
                    self.close_tunnel_editor_tab(&editor_id, cx);
                }
                self.tunnel_context_menu = None;
                self.add_log(format!("Deleted tunnel {}.", tunnel_id));
                cx.notify();
            }
            Err(error) => {
                self.add_log(format!("Tunnel deletion failed: {error}"));
                cx.notify();
            }
        }
    }

    fn open_tunnel_context_menu(&mut self, tunnel_id: &str, cx: &mut Context<Self>) {
        self.tunnel_context_menu = Some(TunnelContextMenuState {
            tunnel_id: tunnel_id.to_string(),
        });
        cx.notify();
    }

    fn open_tunnel_preview(&mut self, tunnel_id: &str, cx: &mut Context<Self>) {
        let Some(tunnel) = self
            .tunnels
            .iter()
            .find(|tunnel| tunnel.id == tunnel_id)
            .cloned()
        else {
            return;
        };
        let Some(profile) = self
            .all_profiles()
            .into_iter()
            .find(|profile| profile.id == tunnel.profile_id)
            .cloned()
        else {
            self.add_log(format!("Tunnel {} has no matching profile.", tunnel.name));
            cx.notify();
            return;
        };

        let body = self
            .services
            .ssh_backend
            .preview_tunnel_command(&profile, &tunnel);
        self.tabs.push(WorkspaceTab {
            id: Uuid::new_v4().to_string(),
            title: tunnel.name.clone(),
            kind: WorkspaceTabKind::TextPreview {
                title: tunnel.name.clone(),
                body,
            },
        });
        self.active_tab = self.tabs.len().saturating_sub(1);
        cx.notify();
    }

    fn focus_tunnel_field(
        &mut self,
        editor_id: &str,
        field: TunnelFormField,
        cx: &mut Context<Self>,
    ) {
        if let Some(editor) = self.tunnel_editors.get_mut(editor_id) {
            editor.focused_field = field;
            editor.select_all = false;
            editor.cursor_offset = tunnel_field_value(editor, field).chars().count();
            cx.notify();
        }
    }

    fn focus_tunnel_field_at(
        &mut self,
        editor_id: &str,
        field: TunnelFormField,
        position: Point<Pixels>,
        window: &Window,
        cx: &mut Context<Self>,
    ) {
        if let Some(editor) = self.tunnel_editors.get_mut(editor_id) {
            let value = tunnel_field_value(editor, field).to_string();
            let cursor_offset = Self::editor_cursor_offset_for_mouse(position.x, &value, window);
            editor.focused_field = field;
            editor.select_all = false;
            editor.cursor_offset =
                cursor_offset.min(tunnel_field_value(editor, field).chars().count());
            cx.notify();
        }
    }

    fn editor_cursor_offset_for_mouse(mouse_x: Pixels, value: &str, window: &Window) -> usize {
        // Mouse events for these custom inputs are delivered relative to the input box,
        // so only subtract the field's own horizontal padding before mapping to a glyph.
        let input_padding_x = px(12.0);
        let relative_x = (mouse_x - input_padding_x).max(px(0.0));
        let font_size = window.text_style().font_size.to_pixels(window.rem_size());
        let sample = "0".repeat(value.chars().count().max(1) + 1);
        let run = TextRun {
            len: sample.len(),
            font: font(".SystemUIFontMonospaced"),
            color: window.text_style().color,
            background_color: None,
            underline: None,
            strikethrough: None,
        };
        window
            .text_system()
            .shape_line(SharedString::from(sample), font_size, &[run], None)
            .closest_index_for_x(relative_x)
    }

    fn select_tunnel_profile(&mut self, editor_id: &str, profile_id: &str, cx: &mut Context<Self>) {
        let selected_profile_name = self
            .all_profiles()
            .into_iter()
            .find(|profile| profile.id == profile_id)
            .map(|profile| profile.display_name.clone());
        if let Some(editor) = self.tunnel_editors.get_mut(editor_id) {
            editor.profile_id = profile_id.to_string();
            if editor.existing_tunnel_id.is_none() {
                if let Some(profile_name) = selected_profile_name {
                    editor.name = format!("{} Tunnel", profile_name);
                    editor.cursor_offset = editor.name.chars().count();
                }
                editor.step = TunnelEditorStep::Configure;
                editor.focused_field = TunnelFormField::BindHost;
                editor.select_all = false;
            }
            cx.notify();
        }
    }

    fn go_to_tunnel_profile_step(&mut self, editor_id: &str, cx: &mut Context<Self>) {
        if let Some(editor) = self.tunnel_editors.get_mut(editor_id) {
            if editor.existing_tunnel_id.is_none() {
                editor.step = TunnelEditorStep::SelectProfile;
                editor.error = None;
                cx.notify();
            }
        }
    }

    fn select_tunnel_mode(&mut self, editor_id: &str, mode: TunnelMode, cx: &mut Context<Self>) {
        if let Some(editor) = self.tunnel_editors.get_mut(editor_id) {
            editor.mode = mode;
            if matches!(mode, TunnelMode::DynamicSocks) {
                editor.target_host.clear();
                editor.target_port.clear();
            }
            cx.notify();
        }
    }

    fn cycle_tunnel_field(&mut self, editor_id: &str, reverse: bool, cx: &mut Context<Self>) {
        let Some(editor) = self.tunnel_editors.get_mut(editor_id) else {
            return;
        };
        let fields = if matches!(editor.mode, TunnelMode::DynamicSocks) {
            vec![
                TunnelFormField::Name,
                TunnelFormField::BindHost,
                TunnelFormField::BindPort,
            ]
        } else {
            vec![
                TunnelFormField::Name,
                TunnelFormField::BindHost,
                TunnelFormField::BindPort,
                TunnelFormField::TargetHost,
                TunnelFormField::TargetPort,
            ]
        };
        let current_index = fields
            .iter()
            .position(|field| *field == editor.focused_field)
            .unwrap_or(0);
        let next_index = if reverse {
            current_index
                .checked_sub(1)
                .unwrap_or(fields.len().saturating_sub(1))
        } else {
            (current_index + 1) % fields.len()
        };
        editor.focused_field = fields[next_index];
        editor.select_all = false;
        editor.cursor_offset = tunnel_field_value(editor, editor.focused_field)
            .chars()
            .count();
        cx.notify();
    }

    fn apply_tunnel_editor_keystroke(
        &mut self,
        editor_id: &str,
        event: &KeyDownEvent,
        cx: &mut Context<Self>,
    ) -> bool {
        let Some(editor) = self.tunnel_editors.get_mut(editor_id) else {
            return false;
        };

        let key = event.keystroke.key.to_lowercase();
        if editor.step == TunnelEditorStep::SelectProfile {
            if key == "escape" {
                editor.error = None;
                self.tunnel_context_menu = None;
                cx.notify();
                return true;
            }
            return false;
        }

        if (event.keystroke.modifiers.platform || event.keystroke.modifiers.control) && key == "a" {
            editor.select_all = true;
            editor.cursor_offset = tunnel_field_value(editor, editor.focused_field)
                .chars()
                .count();
            cx.notify();
            return true;
        }

        match key.as_str() {
            "tab" => {
                let reverse = event.keystroke.modifiers.shift;
                let _ = editor;
                self.cycle_tunnel_field(editor_id, reverse, cx);
                return true;
            }
            "left" => {
                if editor.select_all {
                    editor.select_all = false;
                    editor.cursor_offset = 0;
                } else {
                    editor.cursor_offset = editor.cursor_offset.saturating_sub(1);
                }
                cx.notify();
                return true;
            }
            "right" => {
                let len = tunnel_field_value(editor, editor.focused_field)
                    .chars()
                    .count();
                if editor.select_all {
                    editor.select_all = false;
                    editor.cursor_offset = len;
                } else {
                    editor.cursor_offset = (editor.cursor_offset + 1).min(len);
                }
                cx.notify();
                return true;
            }
            "home" => {
                editor.select_all = false;
                editor.cursor_offset = 0;
                cx.notify();
                return true;
            }
            "end" => {
                editor.select_all = false;
                editor.cursor_offset = tunnel_field_value(editor, editor.focused_field)
                    .chars()
                    .count();
                cx.notify();
                return true;
            }
            "backspace" => {
                let replace_all = editor.select_all;
                if replace_all {
                    editor.select_all = false;
                }
                let mut cursor_offset = editor.cursor_offset;
                let value = tunnel_field_value_mut(editor, editor.focused_field);
                if replace_all {
                    value.clear();
                    cursor_offset = 0;
                } else {
                    delete_char_before_cursor(value, &mut cursor_offset);
                }
                editor.cursor_offset = cursor_offset;
                cx.notify();
                return true;
            }
            "escape" => {
                editor.error = None;
                editor.select_all = false;
                self.tunnel_context_menu = None;
                cx.notify();
                return true;
            }
            _ => {}
        }

        if event.keystroke.modifiers.control
            || event.keystroke.modifiers.alt
            || event.keystroke.modifiers.platform
        {
            return false;
        }

        if let Some(text) = event.keystroke.key_char.as_ref() {
            if !text.chars().all(|ch| !ch.is_control()) {
                return false;
            }
            let replace_all = editor.select_all;
            if replace_all {
                editor.select_all = false;
            }
            let mut cursor_offset = editor.cursor_offset;
            let value = tunnel_field_value_mut(editor, editor.focused_field);
            if replace_all {
                value.clear();
                cursor_offset = 0;
            }
            insert_text_at_cursor(value, &mut cursor_offset, text);
            editor.cursor_offset = cursor_offset;
            cx.notify();
            return true;
        }

        false
    }

    fn save_tunnel_editor(&mut self, editor_id: &str, cx: &mut Context<Self>) {
        let Some(editor) = self.tunnel_editors.get_mut(editor_id) else {
            return;
        };

        let bind_port = match editor.bind_port.trim().parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                editor.error = Some("Bind port must be a valid number.".into());
                cx.notify();
                return;
            }
        };

        let (target_host, target_port) = if matches!(editor.mode, TunnelMode::DynamicSocks) {
            (None, None)
        } else {
            let host = editor.target_host.trim();
            if host.is_empty() {
                editor.error =
                    Some("Target host is required for local and remote forwarding.".into());
                cx.notify();
                return;
            }
            let port = match editor.target_port.trim().parse::<u16>() {
                Ok(port) => port,
                Err(_) => {
                    editor.error = Some("Target port must be a valid number.".into());
                    cx.notify();
                    return;
                }
            };
            (Some(host.to_string()), Some(port))
        };

        let tunnel = TunnelSpec {
            id: editor
                .existing_tunnel_id
                .clone()
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
            profile_id: editor.profile_id.clone(),
            name: editor.name.trim().to_string(),
            mode: editor.mode,
            bind_host: editor.bind_host.trim().to_string(),
            bind_port,
            target_host,
            target_port,
            meta: crate::domain::RecordMeta::new(),
        };

        if tunnel.name.is_empty() || tunnel.bind_host.is_empty() {
            editor.error = Some("Name and bind host are required.".into());
            cx.notify();
            return;
        }

        match self.services.repository.upsert_tunnel(&tunnel) {
            Ok(()) => {
                if let Some(existing) = self.tunnels.iter_mut().find(|item| item.id == tunnel.id) {
                    *existing = tunnel.clone();
                } else {
                    self.tunnels.insert(0, tunnel.clone());
                }
                editor.error = None;
                self.add_log(format!("Saved tunnel {}.", tunnel.name));
                self.close_tunnel_editor_tab(editor_id, cx);
            }
            Err(error) => {
                editor.error = Some(error.to_string());
                cx.notify();
            }
        }
    }

    fn close_tunnel_editor_tab(&mut self, editor_id: &str, cx: &mut Context<Self>) {
        if let Some((index, _)) = self.tabs.iter().enumerate().find(|(_, tab)| {
            matches!(&tab.kind, WorkspaceTabKind::TunnelEditor { editor_id: existing } if existing == editor_id)
        }) {
            self.tabs.remove(index);
            self.tunnel_editors.remove(editor_id);
            if self.active_tab >= self.tabs.len() {
                self.active_tab = self.tabs.len().saturating_sub(1);
            }
            cx.notify();
        }
    }

    fn start_session_for_profile(
        &mut self,
        profile: HostProfile,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.selected_profile_id = Some(profile.id.clone());
        let saved_password = match &profile.auth_method {
            AuthMethod::Password { secret_id } => self
                .services
                .secret_store
                .get_secret(secret_id)
                .ok()
                .flatten(),
            _ => None,
        };
        match self.services.ssh_backend.open_terminal_session(&profile) {
            Ok(handle) => {
                if let Some(password) = saved_password {
                    self.spawn_saved_password_autofill(handle.clone(), password);
                }
                let snapshot = handle.snapshot();
                let session_id = snapshot.id.clone();
                self.tabs.push(WorkspaceTab {
                    id: Uuid::new_v4().to_string(),
                    title: snapshot.title.clone(),
                    kind: WorkspaceTabKind::Session {
                        session_id: session_id.clone(),
                    },
                });
                self.active_tab = self.tabs.len().saturating_sub(1);
                self.live_sessions.insert(session_id, handle);
                self.terminal_focus.focus(window);
                self.add_log(format!("Started PTY session for {}.", profile.display_name));
            }
            Err(error) => self.add_log(format!("Session launch failed: {error}")),
        }
        cx.notify();
    }

    fn spawn_saved_password_autofill(&self, handle: TerminalSessionHandle, password: String) {
        std::thread::spawn(move || {
            for _ in 0..300 {
                let snapshot = handle.snapshot();
                if snapshot.exit_status.is_some() {
                    break;
                }
                if session_requests_password(&snapshot.rendered_screen)
                    || session_requests_password(&snapshot.raw_output)
                {
                    let _ = handle.send_input(&(password.clone() + "\n"));
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
    }

    fn preview_sftp(&mut self, cx: &mut Context<Self>) {
        let Some(profile) = self.selected_profile().cloned() else {
            return;
        };
        let operation = SftpOperation::ListDirectory {
            path: profile
                .remote_directory
                .clone()
                .unwrap_or_else(|| ".".into()),
        };
        let body = match self.services.ssh_backend.run_sftp_op(&profile, &operation) {
            Ok(result) => {
                let mut body = result.command_preview;
                if !result.stdout.is_empty() {
                    body.push_str("\n\nstdout:\n");
                    body.push_str(&result.stdout);
                }
                if !result.stderr.is_empty() {
                    body.push_str("\n\nstderr:\n");
                    body.push_str(&result.stderr);
                }
                if result.stdout.is_empty() && result.stderr.is_empty() {
                    body.push_str("\n\n(no output)");
                }
                body
            }
            Err(error) => format!("SFTP preview failed: {error}"),
        };

        self.tabs.push(WorkspaceTab {
            id: Uuid::new_v4().to_string(),
            title: format!("SFTP {}", profile.display_name),
            kind: WorkspaceTabKind::TextPreview {
                title: format!("SFTP {}", profile.display_name),
                body,
            },
        });
        self.active_tab = self.tabs.len().saturating_sub(1);
        self.add_log(format!("Opened SFTP preview for {}.", profile.display_name));
        cx.notify();
    }

    fn start_session(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(profile) = self.selected_profile().cloned() else {
            return;
        };
        self.start_session_for_profile(profile, window, cx);
    }

    fn preview_tunnel(&mut self, cx: &mut Context<Self>) {
        let Some(profile) = self.selected_profile().cloned() else {
            return;
        };

        let tunnel = TunnelSpec {
            id: Uuid::new_v4().to_string(),
            profile_id: profile.id.clone(),
            name: format!("{} SOCKS", profile.display_name),
            mode: TunnelMode::DynamicSocks,
            bind_host: "127.0.0.1".into(),
            bind_port: 1080,
            target_host: None,
            target_port: None,
            meta: crate::domain::RecordMeta::new(),
        };
        let body = self
            .services
            .ssh_backend
            .preview_tunnel_command(&profile, &tunnel);
        self.tabs.push(WorkspaceTab {
            id: Uuid::new_v4().to_string(),
            title: format!("Tunnel {}", profile.display_name),
            kind: WorkspaceTabKind::TextPreview {
                title: tunnel.name.clone(),
                body,
            },
        });
        self.tunnels.insert(0, tunnel);
        self.active_tab = self.tabs.len().saturating_sub(1);
        self.add_log(format!(
            "Prepared tunnel preview for {}.",
            profile.display_name
        ));
        cx.notify();
    }

    fn refresh_session_output(&mut self, cx: &mut Context<Self>) {
        self.add_log("Refreshed session snapshots.");
        cx.notify();
    }

    fn begin_sidebar_resize(&mut self, _: &MouseDownEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.active_resize = Some(ActivePaneResize::Sidebar);
        cx.stop_propagation();
        cx.notify();
    }

    fn begin_detail_resize(&mut self, _: &MouseDownEvent, _: &mut Window, cx: &mut Context<Self>) {
        self.active_resize = Some(ActivePaneResize::Detail);
        cx.stop_propagation();
        cx.notify();
    }

    fn end_resize(&mut self, _: &MouseUpEvent, _: &mut Window, cx: &mut Context<Self>) {
        if self.active_resize.take().is_some() {
            cx.notify();
        }
    }

    fn on_root_mouse_move(
        &mut self,
        event: &MouseMoveEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(active_resize) = self.active_resize else {
            return;
        };
        if !event.dragging() {
            self.active_resize = None;
            cx.notify();
            return;
        }

        let viewport_width = window.viewport_size().width;
        match active_resize {
            ActivePaneResize::Sidebar => {
                self.sidebar_width = clamp_pixels(event.position.x, px(220.0), px(520.0));
            }
            ActivePaneResize::Detail => {
                let width = viewport_width - event.position.x;
                self.detail_width = clamp_pixels(width, px(260.0), px(560.0));
            }
        }
        cx.notify();
    }

    fn on_terminal_mouse_down(
        &mut self,
        _: &gpui::MouseDownEvent,
        window: &mut Window,
        _: &mut Context<Self>,
    ) {
        self.terminal_focus.focus(window);
    }

    fn on_terminal_text_mouse_down(
        &mut self,
        event: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.terminal_focus.focus(window);
        let Some(handle) = self.active_session_handle() else {
            return;
        };
        let snapshot = handle.snapshot();
        let screen = if snapshot.rendered_screen.trim().is_empty() {
            snapshot.raw_output
        } else {
            snapshot.rendered_screen
        };
        let point = self.terminal_grid_point_for_mouse(event.position, window, &screen);
        self.terminal_selection_session_id = Some(snapshot.id);
        self.terminal_selection_anchor = Some(point);
        self.terminal_selection_focus = Some(point);
        self.terminal_is_selecting = true;
        cx.stop_propagation();
        cx.notify();
    }

    fn on_terminal_text_mouse_move(
        &mut self,
        event: &MouseMoveEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.terminal_is_selecting {
            return;
        }
        let Some(handle) = self.active_session_handle() else {
            return;
        };
        let snapshot = handle.snapshot();
        let screen = if snapshot.rendered_screen.trim().is_empty() {
            snapshot.raw_output
        } else {
            snapshot.rendered_screen
        };
        let point = self.terminal_grid_point_for_mouse(event.position, window, &screen);
        self.terminal_selection_focus = Some(point);
        cx.stop_propagation();
        cx.notify();
    }

    fn on_terminal_text_mouse_up(
        &mut self,
        _: &MouseUpEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.terminal_is_selecting {
            self.terminal_is_selecting = false;
            cx.stop_propagation();
            cx.notify();
        }
    }

    fn on_terminal_key_down(
        &mut self,
        event: &KeyDownEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let key = event.keystroke.key.to_lowercase();
        if (event.keystroke.modifiers.platform || event.keystroke.modifiers.control)
            && key == "c"
            && self.copy_terminal_selection(cx)
        {
            cx.stop_propagation();
            return;
        }

        let Some(payload) = terminal_bytes_for_keystroke(event) else {
            return;
        };
        let Some(handle) = self.active_session_handle() else {
            return;
        };

        match handle.send_input(&payload) {
            Ok(()) => {
                self.clear_terminal_selection();
                cx.stop_propagation();
            }
            Err(error) => {
                self.add_log(format!("Terminal input failed: {error}"));
                cx.notify();
            }
        }
    }

    fn on_terminal_scroll_wheel(
        &mut self,
        event: &ScrollWheelEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(handle) = self.active_session_handle() else {
            return;
        };

        let pixels = event.delta.pixel_delta(window.line_height());
        let rows = (pixels.y / window.line_height()).round() as isize;
        if rows == 0 {
            return;
        }

        handle.scroll_scrollback_by(rows);
        cx.stop_propagation();
        cx.notify();
    }

    fn clear_terminal_selection(&mut self) {
        self.terminal_selection_session_id = None;
        self.terminal_selection_anchor = None;
        self.terminal_selection_focus = None;
        self.terminal_is_selecting = false;
    }

    fn terminal_grid_point_for_mouse(
        &self,
        position: Point<Pixels>,
        window: &Window,
        screen: &str,
    ) -> TerminalGridPoint {
        let line_height = window.line_height();
        let line_height_value = f32::from(line_height);
        let char_width = px(line_height_value * 0.55);
        let origin = self.terminal_text_origin(window);
        let lines = screen.lines().collect::<Vec<_>>();
        let max_row = lines.len().saturating_sub(1);
        let y = (position.y - origin.y).max(px(0.0));
        let x = (position.x - origin.x).max(px(0.0));
        let row = ((f32::from(y) / line_height_value).floor() as usize).min(max_row);
        let line_len = lines
            .get(row)
            .map(|line: &&str| line.chars().count())
            .unwrap_or_default();
        let col = ((f32::from(x) / f32::from(char_width)).floor() as usize).min(line_len);

        TerminalGridPoint { row, col }
    }

    fn terminal_text_origin(&self, window: &Window) -> Point<Pixels> {
        let line_height = window.line_height();
        Point {
            x: self.sidebar_width + px(24.0),
            y: px(84.0) + (line_height * 2.0) + px(24.0),
        }
    }

    fn terminal_selection_range(
        &self,
        session_id: &str,
        screen: &str,
    ) -> Option<std::ops::Range<usize>> {
        if self.terminal_selection_session_id.as_deref() != Some(session_id) {
            return None;
        }
        let anchor = self.terminal_selection_anchor?;
        let focus = self.terminal_selection_focus?;
        if anchor == focus {
            return None;
        }

        let (start, end) = if (anchor.row, anchor.col) <= (focus.row, focus.col) {
            (anchor, focus)
        } else {
            (focus, anchor)
        };

        let start = terminal_text_offset_for_grid(screen, start)?;
        let end = terminal_text_offset_for_grid(screen, end)?;
        (start < end).then_some(start..end)
    }

    fn copy_terminal_selection(&self, cx: &mut Context<Self>) -> bool {
        let Some(handle) = self.active_session_handle() else {
            return false;
        };
        let snapshot = handle.snapshot();
        let screen = if snapshot.rendered_screen.trim().is_empty() {
            snapshot.raw_output
        } else {
            snapshot.rendered_screen
        };
        let Some(range) = self.terminal_selection_range(&snapshot.id, &screen) else {
            return false;
        };

        cx.write_to_clipboard(ClipboardItem::new_string(screen[range].to_string()));
        true
    }

    fn render_menu_page(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let section_title = match self.selected_menu_section {
            MenuSection::Hosts => "SSH",
            MenuSection::Identities => "Identities",
            MenuSection::PortForwarding => "Port Forwarding",
            MenuSection::Sftp => "SFTP",
        };

        let section_body = match self.selected_menu_section {
            MenuSection::Hosts => self.render_ssh_profiles_page(cx).into_any_element(),
            MenuSection::Identities => div()
                .flex()
                .flex_col()
                .gap_3()
                .child(
                    div()
                        .flex()
                        .justify_between()
                        .items_center()
                        .child(
                            div()
                                .text_3xl()
                                .font_weight(FontWeight::BOLD)
                                .child(section_title),
                        )
                        .child(
                            div()
                                .id("new-identity")
                                .px_3()
                                .py_2()
                                .rounded_md()
                                .cursor_pointer()
                                .bg(rgb(0x0f172a))
                                .hover(|this| this.bg(rgb(0x1e293b)))
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.open_identity_editor(cx);
                                }))
                                .child(div().text_sm().font_weight(FontWeight::BOLD).child("+")),
                        ),
                )
                .child(
                    div().mt_2().flex().flex_col().gap_2().children(
                        self.system_index
                            .keys
                            .iter()
                            .chain(self.app_keys.iter())
                            .map(|key| {
                                let key_id = key.id.clone();
                                div()
                                    .cursor_pointer()
                                    .hover(|this| this.bg(rgb(0x334155)))
                                    .on_mouse_down(
                                        MouseButton::Left,
                                        cx.listener(move |this, _, _, cx| {
                                            this.open_identity_public_key_preview(&key_id, cx);
                                        }),
                                    )
                                    .child(render_identity_row(key, cx))
                                    .into_any_element()
                            })
                            .collect::<Vec<_>>(),
                    ),
                )
                .when(
                    self.system_index.keys.is_empty() && self.app_keys.is_empty(),
                    |this| {
                        this.child(
                            div()
                                .mt_2()
                                .p_3()
                                .rounded_md()
                                .bg(rgb(0x0f172a))
                                .border_1()
                                .border_color(rgb(0x1e293b))
                                .text_color(rgb(0x94a3b8))
                                .child("No identities available."),
                        )
                    },
                )
                .into_any_element(),
            MenuSection::PortForwarding => {
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .justify_between()
                            .items_center()
                            .child(div().text_lg().font_weight(FontWeight::BOLD).child("Rules"))
                            .child(
                                div()
                                    .id("new-tunnel-rule")
                                    .px_3()
                                    .py_2()
                                    .rounded_md()
                                    .cursor_pointer()
                                    .bg(rgb(0x0f172a))
                                    .hover(|this| this.bg(rgb(0x1e293b)))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.create_tunnel_rule(cx);
                                    }))
                                    .child(
                                        div().text_sm().font_weight(FontWeight::BOLD).child("+"),
                                    ),
                            ),
                    )
                    .child(div().mt_2().flex().flex_col().gap_2().children(
                        self.tunnels.iter().map(|tunnel| {
                            let tunnel_id = tunnel.id.clone();
                            let profile_name = self
                                .all_profiles()
                                .into_iter()
                                .find(|profile| profile.id == tunnel.profile_id)
                                .map(|profile| profile.display_name.clone())
                                .unwrap_or_else(|| "Unknown profile".into());
                            div()
                                .id(SharedString::from(format!("tunnel-rule-{}", tunnel.id)))
                                .p_3()
                                .rounded_md()
                                .cursor_pointer()
                                .bg(rgb(0x1e293b))
                                .hover(|this| this.bg(rgb(0x334155)))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.tunnel_context_menu = None;
                                    this.open_tunnel_preview(&tunnel_id, cx);
                                }))
                                .on_mouse_down(
                                    MouseButton::Right,
                                    cx.listener({
                                        let tunnel_id = tunnel.id.clone();
                                        move |this, _, _, cx| {
                                            this.open_tunnel_context_menu(&tunnel_id, cx);
                                        }
                                    }),
                                )
                                .child(
                                    div()
                                        .flex()
                                        .justify_between()
                                        .items_center()
                                        .child(
                                            div()
                                                .text_sm()
                                                .font_weight(FontWeight::BOLD)
                                                .child(tunnel.name.clone()),
                                        )
                                        .child(
                                            div()
                                                .px_2()
                                                .py_0p5()
                                                .rounded_full()
                                                .bg(rgb(0x1d4ed8))
                                                .text_xs()
                                                .child(tunnel_mode_label(tunnel.mode)),
                                        ),
                                )
                                .child(div().mt_1().text_xs().text_color(rgb(0xcbd5e1)).child(
                                    format!(
                                            "{}:{} -> {}:{} via {}",
                                            tunnel.bind_host,
                                            tunnel.bind_port,
                                            tunnel
                                                .target_host
                                                .clone()
                                                .unwrap_or_else(|| "SOCKS".into()),
                                            tunnel
                                                .target_port
                                                .map(|port| port.to_string())
                                                .unwrap_or_else(|| "-".into()),
                                            profile_name
                                        ),
                                ))
                                .when(
                                    self.tunnel_context_menu
                                        .as_ref()
                                        .is_some_and(|menu| menu.tunnel_id == tunnel.id),
                                    |this| {
                                        this.child(
                                            div()
                                                .mt_3()
                                                .w(px(160.0))
                                                .rounded_md()
                                                .border_1()
                                                .border_color(rgb(0x334155))
                                                .bg(rgb(0x0f172a))
                                                .p_2()
                                                .child(
                                                    div()
                                                        .id(SharedString::from(format!(
                                                            "tunnel-menu-edit-{}",
                                                            tunnel.id
                                                        )))
                                                        .px_3()
                                                        .py_2()
                                                        .rounded_md()
                                                        .cursor_pointer()
                                                        .hover(|this| this.bg(rgb(0x1e293b)))
                                                        .on_click(cx.listener({
                                                            let tunnel_id = tunnel.id.clone();
                                                            move |this, _, _, cx| {
                                                                this.edit_tunnel_rule(
                                                                    &tunnel_id, cx,
                                                                );
                                                            }
                                                        }))
                                                        .child("Edit"),
                                                ),
                                        )
                                        .child(
                                            div()
                                                .id(SharedString::from(format!(
                                                    "tunnel-menu-delete-{}",
                                                    tunnel.id
                                                )))
                                                .mt_1()
                                                .px_3()
                                                .py_2()
                                                .rounded_md()
                                                .cursor_pointer()
                                                .hover(|this| this.bg(rgb(0x3f1d24)))
                                                .text_color(rgb(0xfca5a5))
                                                .on_click(cx.listener({
                                                    let tunnel_id = tunnel.id.clone();
                                                    move |this, _, _, cx| {
                                                        this.delete_tunnel_rule(&tunnel_id, cx);
                                                    }
                                                }))
                                                .child("Delete"),
                                        )
                                    },
                                )
                                .into_any_element()
                        }),
                    ))
                    .into_any_element()
            }
            MenuSection::Sftp => div()
                .flex()
                .flex_col()
                .gap_3()
                .child(div().mt_2().flex().flex_wrap().gap_2().children(
                    self.all_profiles().into_iter().map(|profile| {
                        let profile_id = profile.id.clone();
                        let active = self.active_sftp_profile_id() == Some(profile.id.as_str());
                        div()
                            .id(SharedString::from(format!("sftp-profile-{}", profile.id)))
                            .px_3()
                            .py_2()
                            .rounded_md()
                            .cursor_pointer()
                            .bg(if active { rgb(0x1d4ed8) } else { rgb(0x1e293b) })
                            .border_1()
                            .border_color(if active { rgb(0x60a5fa) } else { rgb(0x334155) })
                            .hover(|this| this.bg(rgb(0x334155)))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.open_sftp_browser(&profile_id, cx);
                            }))
                            .child(
                                div()
                                    .text_sm()
                                    .font_weight(FontWeight::BOLD)
                                    .child(profile.display_name.clone()),
                            )
                            .into_any_element()
                    }),
                ))
                .child(
                    div()
                        .mt_2()
                        .p_3()
                        .rounded_md()
                        .bg(rgb(0x0f172a))
                        .border_1()
                        .border_color(rgb(0x1e293b))
                        .text_color(rgb(0x94a3b8))
                        .child("Select an SSH profile to open it in a new SFTP tab."),
                )
                .into_any_element(),
        };

        div()
            .id("menu-pane")
            .size_full()
            .p_5()
            .overflow_scroll()
            .bg(rgb(0x020617))
            .text_color(rgb(0xe2e8f0))
            .child(section_body)
    }

    fn render_profile_details(&self, profile: Option<&HostProfile>) -> impl IntoElement {
        let Some(profile) = profile else {
            return div()
                .id("empty-profile-pane")
                .size_full()
                .p_5()
                .bg(rgb(0x020617))
                .text_color(rgb(0xe2e8f0))
                .child("No profile selected.");
        };

        div()
            .id(SharedString::from(format!("profile-pane-{}", profile.id)))
            .size_full()
            .p_5()
            .overflow_scroll()
            .bg(rgb(0x020617))
            .text_color(rgb(0xe2e8f0))
            .child(
                div()
                    .text_2xl()
                    .font_weight(FontWeight::BOLD)
                    .child(profile.display_name.clone()),
            )
            .child(
                div()
                    .mt_2()
                    .text_color(rgb(0x94a3b8))
                    .child(format!("Host: {}", profile.hostname)),
            )
            .child(div().mt_1().child(format!("Port: {}", profile.port)))
            .child(div().mt_1().child(format!(
                "User: {}",
                profile.username.clone().unwrap_or_else(|| "(default)".into())
            )))
            .child(div().mt_1().child(format!("Source: {:?}", profile.source)))
            .child(div().mt_1().child(format!(
                "Identity: {}",
                profile
                    .identity_path
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "ssh-agent / default".into())
            )))
            .child(div().mt_1().child(format!(
                "ProxyJump: {}",
                profile
                    .ssh_options
                    .proxy_jump
                    .clone()
                    .unwrap_or_else(|| "none".into())
            )))
    }

    fn render_session_tab(
        &self,
        session: Option<&TerminalSessionHandle>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        match session {
            Some(handle) => {
                let snapshot = handle.snapshot();
                let raw_screen = if snapshot.rendered_screen.trim().is_empty() {
                    snapshot.raw_output
                } else {
                    snapshot.rendered_screen
                };
                let focused = self.terminal_focus.is_focused(window);
                let selection_range = self.terminal_selection_range(&snapshot.id, &raw_screen);
                let display_screen = if selection_range.is_none()
                    && focused
                    && !snapshot.hide_cursor
                {
                    render_terminal_cursor(&raw_screen, snapshot.cursor_row, snapshot.cursor_col)
                } else {
                    raw_screen.clone()
                };
                let terminal_text = if let Some(range) = selection_range.clone() {
                    StyledText::new(display_screen.clone())
                        .with_highlights([(range, rgb(0x1d4ed8).into())])
                        .into_any_element()
                } else {
                    div().child(display_screen).into_any_element()
                };

                div()
                    .id(SharedString::from(format!("session-pane-{}", snapshot.id)))
                    .track_focus(&self.terminal_focus)
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_terminal_mouse_down))
                    .on_key_down(cx.listener(Self::on_terminal_key_down))
                    .on_scroll_wheel(cx.listener(Self::on_terminal_scroll_wheel))
                    .size_full()
                    .p_4()
                    .overflow_scroll()
                    .bg(rgb(0x020617))
                    .border_1()
                    .border_color(if focused {
                        rgb(0x38bdf8)
                    } else {
                        rgb(0x1e293b)
                    })
                    .text_color(rgb(0xe2e8f0))
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(0x94a3b8))
                            .child(snapshot.command_preview),
                    )
                    .child(
                        div()
                            .mt_2()
                            .text_xs()
                            .text_color(if focused {
                                rgb(0x38bdf8)
                            } else {
                                rgb(0x64748b)
                            })
                            .child(if focused {
                                "Terminal focused. Typing is sent to the PTY."
                            } else {
                                "Click inside the terminal to focus it."
                            }),
                    )
                    .child(
                        div()
                            .mt_4()
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(Self::on_terminal_text_mouse_down),
                            )
                            .on_mouse_move(cx.listener(Self::on_terminal_text_mouse_move))
                            .on_mouse_up(
                                MouseButton::Left,
                                cx.listener(Self::on_terminal_text_mouse_up),
                            )
                            .on_mouse_up_out(
                                MouseButton::Left,
                                cx.listener(Self::on_terminal_text_mouse_up),
                            )
                            .font_family(".SystemUIFontMonospaced")
                            .text_sm()
                            .child(terminal_text),
                    )
            }
            None => div()
                .id("missing-session-pane")
                .size_full()
                .p_4()
                .bg(rgb(0x020617))
                .text_color(rgb(0xe2e8f0))
                .child("Session handle is no longer available."),
        }
    }

    fn on_profile_editor_mouse_down(
        &mut self,
        _: &MouseDownEvent,
        window: &mut Window,
        _: &mut Context<Self>,
    ) {
        self.profile_editor_focus.focus(window);
    }

    fn on_profile_editor_key_down(
        &mut self,
        event: &KeyDownEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(tab) = self.tabs.get(self.active_tab) else {
            return;
        };
        let WorkspaceTabKind::ProfileEditor { editor_id } = &tab.kind else {
            return;
        };
        let editor_id = editor_id.clone();
        let key = event.keystroke.key.to_lowercase();

        if key == "enter"
            && (event.keystroke.modifiers.platform || event.keystroke.modifiers.control)
        {
            self.save_profile_editor(&editor_id, cx);
            cx.stop_propagation();
            return;
        }

        if self.apply_profile_editor_keystroke(&editor_id, event, cx) {
            cx.stop_propagation();
        }
    }

    fn on_identity_editor_mouse_down(
        &mut self,
        _: &MouseDownEvent,
        window: &mut Window,
        _: &mut Context<Self>,
    ) {
        self.identity_editor_focus.focus(window);
    }

    fn on_identity_editor_key_down(
        &mut self,
        event: &KeyDownEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(tab) = self.tabs.get(self.active_tab) else {
            return;
        };
        let WorkspaceTabKind::IdentityEditor { editor_id } = &tab.kind else {
            return;
        };
        let editor_id = editor_id.clone();
        let key = event.keystroke.key.to_lowercase();

        if key == "enter"
            && (event.keystroke.modifiers.platform || event.keystroke.modifiers.control)
        {
            self.save_identity_editor(&editor_id, cx);
            cx.stop_propagation();
            return;
        }

        if self.apply_identity_editor_keystroke(&editor_id, event, cx) {
            cx.stop_propagation();
        }
    }

    fn render_profile_editor(
        &self,
        editor_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let editor = self
            .profile_editors
            .get(editor_id)
            .cloned()
            .expect("profile editor must exist");
        let focused = self.profile_editor_focus.is_focused(window);
        let use_identity = editor.auth_mode == ProfileAuthMode::Identity;
        let use_password = editor.auth_mode == ProfileAuthMode::Password;
        let identity_buttons = self
            .system_index
            .keys
            .iter()
            .chain(self.app_keys.iter())
            .filter_map(|key| {
                let path = key.path.as_ref()?.display().to_string();
                let active = editor.identity_path == path;
                let editor_id = editor_id.to_string();
                let label = key.name.clone();
                Some(
                    div()
                        .id(SharedString::from(format!(
                            "profile-identity-{}-{}",
                            editor_id, key.id
                        )))
                        .px_3()
                        .py_2()
                        .rounded_md()
                        .cursor_pointer()
                        .bg(if active { rgb(0x14532d) } else { rgb(0x1e293b) })
                        .border_1()
                        .border_color(if active { rgb(0x22c55e) } else { rgb(0x334155) })
                        .hover(|this| this.bg(rgb(0x334155)))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.choose_profile_identity(&editor_id, Some(path.clone()), cx);
                        }))
                        .child(label)
                        .into_any_element(),
                )
            })
            .collect::<Vec<_>>();
        let has_identity_buttons = !identity_buttons.is_empty();

        div()
            .id(SharedString::from(format!("profile-editor-{editor_id}")))
            .track_focus(&self.profile_editor_focus)
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_profile_editor_mouse_down),
            )
            .on_key_down(cx.listener(Self::on_profile_editor_key_down))
            .size_full()
            .p_5()
            .overflow_scroll()
            .bg(rgb(0x020617))
            .text_color(rgb(0xe2e8f0))
            .child(
                div()
                    .text_3xl()
                    .font_weight(FontWeight::BOLD)
                    .child("New SSH Configuration"),
            )
            .child(
                div()
                    .mt_3()
                    .text_color(if focused {
                        rgb(0x38bdf8)
                    } else {
                        rgb(0x94a3b8)
                    })
                    .child(
                        "Click a field, type to edit, use Tab to move, and Cmd/Ctrl+Enter to save.",
                    ),
            )
            .when_some(editor.error.as_ref(), |this, error| {
                this.child(
                    div()
                        .mt_4()
                        .rounded_md()
                        .border_1()
                        .border_color(rgb(0x7f1d1d))
                        .bg(rgb(0x1f1014))
                        .p_3()
                        .text_color(rgb(0xfca5a5))
                        .child(error.clone()),
                )
            })
            .child(
                div()
                    .mt_6()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .child(render_profile_input(
                        "Name",
                        &editor.display_name,
                        editor.focused_field == ProfileFormField::DisplayName,
                        editor.select_all && editor.focused_field == ProfileFormField::DisplayName,
                        editor.cursor_offset,
                        editor_id,
                        ProfileFormField::DisplayName,
                        false,
                        None,
                        cx,
                    ))
                    .child(render_profile_input(
                        "Host",
                        &editor.hostname,
                        editor.focused_field == ProfileFormField::Hostname,
                        editor.select_all && editor.focused_field == ProfileFormField::Hostname,
                        editor.cursor_offset,
                        editor_id,
                        ProfileFormField::Hostname,
                        false,
                        None,
                        cx,
                    ))
                    .child(render_profile_input(
                        "User",
                        &editor.username,
                        editor.focused_field == ProfileFormField::Username,
                        editor.select_all && editor.focused_field == ProfileFormField::Username,
                        editor.cursor_offset,
                        editor_id,
                        ProfileFormField::Username,
                        false,
                        None,
                        cx,
                    ))
                    .child(render_profile_input(
                        "Port",
                        &editor.port,
                        editor.focused_field == ProfileFormField::Port,
                        editor.select_all && editor.focused_field == ProfileFormField::Port,
                        editor.cursor_offset,
                        editor_id,
                        ProfileFormField::Port,
                        false,
                        None,
                        cx,
                    ))
                    .child(
                        div()
                            .child(
                                div()
                                    .text_sm()
                                    .text_color(rgb(0x94a3b8))
                                    .child("Authentication"),
                            )
                            .child(
                                div()
                                    .mt_2()
                                    .flex()
                                    .gap_2()
                                    .child(
                                        div()
                                            .px_3()
                                            .py_2()
                                            .rounded_md()
                                            .cursor_pointer()
                                            .bg(if use_identity { rgb(0x1d4ed8) } else { rgb(0x1e293b) })
                                            .border_1()
                                            .border_color(if use_identity { rgb(0x60a5fa) } else { rgb(0x334155) })
                                            .hover(|this| this.bg(rgb(0x334155)))
                                            .on_mouse_down(MouseButton::Left, cx.listener({
                                                let editor_id = editor_id.to_string();
                                                move |this, _, _, cx| {
                                                    this.select_profile_auth_mode(
                                                        &editor_id,
                                                        ProfileAuthMode::Identity,
                                                        cx,
                                                    );
                                                }
                                            }))
                                            .child("Use Identity"),
                                    )
                                    .child(
                                        div()
                                            .px_3()
                                            .py_2()
                                            .rounded_md()
                                            .cursor_pointer()
                                            .bg(if use_password { rgb(0x1d4ed8) } else { rgb(0x1e293b) })
                                            .border_1()
                                            .border_color(if use_password { rgb(0x60a5fa) } else { rgb(0x334155) })
                                            .hover(|this| this.bg(rgb(0x334155)))
                                            .on_mouse_down(MouseButton::Left, cx.listener({
                                                let editor_id = editor_id.to_string();
                                                move |this, _, _, cx| {
                                                    this.select_profile_auth_mode(
                                                        &editor_id,
                                                        ProfileAuthMode::Password,
                                                        cx,
                                                    );
                                                }
                                            }))
                                            .child("Use Password"),
                                    ),
                            ),
                    )
                    .when(use_identity && has_identity_buttons, |this| {
                        this.child(
                            div()
                                .child(
                                    div()
                                        .text_sm()
                                        .text_color(rgb(0x94a3b8))
                                        .child("Choose Identity"),
                                )
                                .child(
                                    div()
                                        .mt_2()
                                        .flex()
                                        .flex_wrap()
                                        .gap_2()
                                        .children(identity_buttons),
                                )
                                .child(
                                    div().mt_2().child(
                                        div()
                                            .px_3()
                                            .py_2()
                                            .rounded_md()
                                            .cursor_pointer()
                                            .bg(rgb(0x0f172a))
                                            .border_1()
                                            .border_color(rgb(0x334155))
                                            .hover(|this| this.bg(rgb(0x1e293b)))
                                            .on_mouse_down(
                                                MouseButton::Left,
                                                cx.listener({
                                                    let editor_id = editor_id.to_string();
                                                    move |this, _, _, cx| {
                                                        this.choose_profile_identity(
                                                            &editor_id, None, cx,
                                                        );
                                                    }
                                                }),
                                            )
                                            .child("Clear Identity"),
                                    ),
                                ),
                        )
                    })
                    .when(use_identity && !has_identity_buttons, |this| {
                        this.child(
                            div()
                                .rounded_md()
                                .border_1()
                                .border_color(rgb(0x334155))
                                .bg(rgb(0x0f172a))
                                .p_3()
                                .text_color(rgb(0x94a3b8))
                                .child("No identities available. Create one in the Identities page first."),
                        )
                    })
                    .when(use_password, |this| {
                        this.child(
                            div()
                                .child(render_profile_input(
                                    "Password",
                                    &editor.password,
                                    editor.focused_field == ProfileFormField::Password,
                                    editor.select_all
                                        && editor.focused_field == ProfileFormField::Password,
                                    editor.cursor_offset,
                                    editor_id,
                                    ProfileFormField::Password,
                                    !editor.password_revealed,
                                    if editor.password_secret_id.is_some() && editor.password.is_empty()
                                    {
                                        Some("••••••••")
                                    } else {
                                        None
                                    },
                                    cx,
                                ))
                                .child(
                                    div()
                                        .mt_2()
                                        .flex()
                                        .gap_2()
                                        .child(
                                            div()
                                                .px_3()
                                                .py_2()
                                                .rounded_md()
                                                .cursor_pointer()
                                                .bg(rgb(0x0f172a))
                                                .border_1()
                                                .border_color(rgb(0x334155))
                                                .hover(|this| this.bg(rgb(0x1e293b)))
                                                .on_mouse_down(MouseButton::Left, cx.listener({
                                                    let editor_id = editor_id.to_string();
                                                    move |this, _, _, cx| {
                                                        this.toggle_profile_password_reveal(
                                                            &editor_id, cx,
                                                        );
                                                    }
                                                }))
                                                .child(if editor.password_revealed {
                                                    "Hide Password"
                                                } else if editor.password_secret_id.is_some()
                                                    && editor.password.is_empty()
                                                {
                                                    "Reveal Saved Password"
                                                } else {
                                                    "Reveal Password"
                                                }),
                                        ),
                                ),
                        )
                    })
                    .when(use_password, |this| {
                        this.child(
                            div()
                                .text_sm()
                                .text_color(rgb(0x94a3b8))
                                .child(if editor.password_secret_id.is_some() {
                                    "A saved password exists in the system keychain. Type a new one to replace it."
                                } else {
                                    "Saved in the system keychain for this profile."
                                }),
                        )
                    })
                    .child(
                        div()
                            .mt_2()
                            .flex()
                            .gap_2()
                            .child(
                                div()
                                    .id(SharedString::from(format!("profile-save-{editor_id}")))
                                    .px_4()
                                    .py_2()
                                    .rounded_md()
                                    .cursor_pointer()
                                    .bg(rgb(0x1d4ed8))
                                    .hover(|this| this.bg(rgb(0x2563eb)))
                                    .on_click(cx.listener({
                                        let editor_id = editor_id.to_string();
                                        move |this, _, _, cx| {
                                            this.save_profile_editor(&editor_id, cx);
                                        }
                                    }))
                                    .child("Save"),
                            )
                            .child(
                                div()
                                    .id(SharedString::from(format!("profile-cancel-{editor_id}")))
                                    .px_4()
                                    .py_2()
                                    .rounded_md()
                                    .cursor_pointer()
                                    .bg(rgb(0x1e293b))
                                    .hover(|this| this.bg(rgb(0x334155)))
                                    .on_click(cx.listener({
                                        let editor_id = editor_id.to_string();
                                        move |this, _, _, cx| {
                                            this.close_profile_editor_tab(&editor_id, cx);
                                        }
                                    }))
                                    .child("Cancel"),
                            ),
                    ),
            )
    }

    fn render_identity_editor(
        &self,
        editor_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let editor = self
            .identity_editors
            .get(editor_id)
            .cloned()
            .expect("identity editor must exist");
        let focused = self.identity_editor_focus.is_focused(window);
        let mode_buttons = [
            (IdentityInputMode::Existing, "Use Existing"),
            (IdentityInputMode::CreateNew, "Create New"),
        ]
        .into_iter()
        .map(|(mode, label)| {
            let active = editor.input_mode == mode;
            let editor_id = editor_id.to_string();
            div()
                .id(SharedString::from(format!(
                    "identity-mode-{}-{label}",
                    editor_id
                )))
                .px_3()
                .py_2()
                .rounded_md()
                .cursor_pointer()
                .bg(if active { rgb(0x1d4ed8) } else { rgb(0x1e293b) })
                .border_1()
                .border_color(if active { rgb(0x60a5fa) } else { rgb(0x334155) })
                .hover(|this| this.bg(rgb(0x334155)))
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.set_identity_input_mode(&editor_id, mode, cx);
                }))
                .child(label)
                .into_any_element()
        })
        .collect::<Vec<_>>();

        div()
            .id(SharedString::from(format!("identity-editor-{editor_id}")))
            .track_focus(&self.identity_editor_focus)
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_identity_editor_mouse_down),
            )
            .on_key_down(cx.listener(Self::on_identity_editor_key_down))
            .size_full()
            .p_5()
            .overflow_scroll()
            .bg(rgb(0x020617))
            .text_color(rgb(0xe2e8f0))
            .child(
                div()
                    .text_3xl()
                    .font_weight(FontWeight::BOLD)
                    .child("New Identity"),
            )
            .child(
                div()
                    .mt_3()
                    .text_color(if focused {
                        rgb(0x38bdf8)
                    } else {
                        rgb(0x94a3b8)
                    })
                    .child(
                        "Click a field, type to edit, use Tab to move, and Cmd/Ctrl+Enter to save.",
                    ),
            )
            .child(div().mt_6().flex().gap_2().children(mode_buttons))
            .when_some(editor.error.as_ref(), |this, error| {
                this.child(
                    div()
                        .mt_4()
                        .rounded_md()
                        .border_1()
                        .border_color(rgb(0x7f1d1d))
                        .bg(rgb(0x1f1014))
                        .p_3()
                        .text_color(rgb(0xfca5a5))
                        .child(error.clone()),
                )
            })
            .child(
                div()
                    .mt_6()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .child(render_identity_input(
                        "Name",
                        &editor.name,
                        editor.focused_field == IdentityFormField::Name,
                        editor.select_all && editor.focused_field == IdentityFormField::Name,
                        editor.cursor_offset,
                        editor_id,
                        IdentityFormField::Name,
                        cx,
                    ))
                    .when(editor.input_mode == IdentityInputMode::Existing, |this| {
                        this.child(render_identity_path_input(
                            "Private Key Path",
                            &editor.private_key_path,
                            editor.focused_field == IdentityFormField::PrivateKeyPath,
                            editor.select_all
                                && editor.focused_field == IdentityFormField::PrivateKeyPath,
                            editor.cursor_offset,
                            editor_id,
                            IdentityFormField::PrivateKeyPath,
                            cx,
                        ))
                        .child(render_identity_path_input(
                            "Public Key Path",
                            &editor.public_key_path,
                            editor.focused_field == IdentityFormField::PublicKeyPath,
                            editor.select_all
                                && editor.focused_field == IdentityFormField::PublicKeyPath,
                            editor.cursor_offset,
                            editor_id,
                            IdentityFormField::PublicKeyPath,
                            cx,
                        ))
                        .child(render_identity_input(
                            "Fingerprint",
                            &editor.fingerprint,
                            editor.focused_field == IdentityFormField::Fingerprint,
                            editor.select_all
                                && editor.focused_field == IdentityFormField::Fingerprint,
                            editor.cursor_offset,
                            editor_id,
                            IdentityFormField::Fingerprint,
                            cx,
                        ))
                    })
                    .when(editor.input_mode == IdentityInputMode::CreateNew, |this| {
                        this.child(
                            div()
                                .rounded_md()
                                .border_1()
                                .border_color(rgb(0x1e293b))
                                .bg(rgb(0x0f172a))
                                .p_3()
                                .text_color(rgb(0xcbd5e1))
                                .child(
                                    "Save will generate a new Ed25519 keypair in PuppyTerm storage.",
                                ),
                        )
                    })
                    .child(
                        div()
                            .mt_2()
                            .flex()
                            .gap_2()
                            .child(
                                div()
                                    .id(SharedString::from(format!("identity-save-{editor_id}")))
                                    .px_4()
                                    .py_2()
                                    .rounded_md()
                                    .cursor_pointer()
                                    .bg(rgb(0x1d4ed8))
                                    .hover(|this| this.bg(rgb(0x2563eb)))
                                    .on_click(cx.listener({
                                        let editor_id = editor_id.to_string();
                                        move |this, _, _, cx| {
                                            this.save_identity_editor(&editor_id, cx);
                                        }
                                    }))
                                    .child("Save"),
                            )
                            .child(
                                div()
                                    .id(SharedString::from(format!("identity-cancel-{editor_id}")))
                                    .px_4()
                                    .py_2()
                                    .rounded_md()
                                    .cursor_pointer()
                                    .bg(rgb(0x1e293b))
                                    .hover(|this| this.bg(rgb(0x334155)))
                                    .on_click(cx.listener({
                                        let editor_id = editor_id.to_string();
                                        move |this, _, _, cx| {
                                            this.close_identity_editor_tab(&editor_id, cx);
                                        }
                                    }))
                                    .child("Cancel"),
                            ),
                    ),
            )
    }

    fn on_tunnel_editor_mouse_down(
        &mut self,
        _: &MouseDownEvent,
        window: &mut Window,
        _: &mut Context<Self>,
    ) {
        self.tunnel_editor_focus.focus(window);
        self.tunnel_context_menu = None;
    }

    fn on_tunnel_editor_key_down(
        &mut self,
        event: &KeyDownEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(tab) = self.tabs.get(self.active_tab) else {
            return;
        };
        let WorkspaceTabKind::TunnelEditor { editor_id } = &tab.kind else {
            return;
        };
        let editor_id = editor_id.clone();
        let key = event.keystroke.key.to_lowercase();

        if key == "enter"
            && (event.keystroke.modifiers.platform || event.keystroke.modifiers.control)
        {
            self.save_tunnel_editor(&editor_id, cx);
            cx.stop_propagation();
            return;
        }

        if self.apply_tunnel_editor_keystroke(&editor_id, event, cx) {
            cx.stop_propagation();
        }
    }

    fn render_tunnel_editor(
        &self,
        editor_id: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let editor = self
            .tunnel_editors
            .get(editor_id)
            .cloned()
            .expect("tunnel editor must exist");
        let editor_focused = self.tunnel_editor_focus.is_focused(window);

        let mode_buttons = [
            TunnelMode::Local,
            TunnelMode::Remote,
            TunnelMode::DynamicSocks,
        ]
        .into_iter()
        .map(|mode| {
            let active = editor.mode == mode;
            let editor_id = editor_id.to_string();
            div()
                .id(SharedString::from(format!(
                    "tunnel-mode-{}-{}",
                    editor_id,
                    tunnel_mode_label(mode)
                )))
                .px_3()
                .py_2()
                .rounded_md()
                .cursor_pointer()
                .bg(if active { rgb(0x1d4ed8) } else { rgb(0x1e293b) })
                .border_1()
                .border_color(if active { rgb(0x60a5fa) } else { rgb(0x334155) })
                .hover(|this| this.bg(rgb(0x334155)))
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.select_tunnel_mode(&editor_id, mode, cx);
                }))
                .child(tunnel_mode_label(mode))
                .into_any_element()
        })
        .collect::<Vec<_>>();

        let profile_buttons = self
            .all_profiles()
            .into_iter()
            .map(|profile| {
                let active = editor.profile_id == profile.id;
                let profile_id = profile.id.clone();
                let editor_id = editor_id.to_string();
                div()
                    .id(SharedString::from(format!(
                        "tunnel-profile-{}-{}",
                        editor_id, profile.id
                    )))
                    .px_3()
                    .py_2()
                    .rounded_md()
                    .cursor_pointer()
                    .bg(if active { rgb(0x14532d) } else { rgb(0x1e293b) })
                    .border_1()
                    .border_color(if active { rgb(0x22c55e) } else { rgb(0x334155) })
                    .hover(|this| this.bg(rgb(0x334155)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.select_tunnel_profile(&editor_id, &profile_id, cx);
                    }))
                    .child(profile.display_name.clone())
                    .into_any_element()
            })
            .collect::<Vec<_>>();

        let selected_profile_name = self
            .all_profiles()
            .into_iter()
            .find(|profile| profile.id == editor.profile_id)
            .map(|profile| profile.display_name.clone())
            .unwrap_or_else(|| "Unknown profile".into());

        div()
            .id(SharedString::from(format!("tunnel-editor-{editor_id}")))
            .track_focus(&self.tunnel_editor_focus)
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(Self::on_tunnel_editor_mouse_down),
            )
            .on_key_down(cx.listener(Self::on_tunnel_editor_key_down))
            .size_full()
            .p_5()
            .overflow_scroll()
            .bg(rgb(0x020617))
            .text_color(rgb(0xe2e8f0))
            .child(div().text_3xl().font_weight(FontWeight::BOLD).child(
                if editor.existing_tunnel_id.is_some() {
                    "Edit Port Forward"
                } else {
                    "New Port Forward"
                },
            ))
            .child(
                div()
                    .mt_3()
                    .text_color(if editor_focused {
                        rgb(0x38bdf8)
                    } else {
                        rgb(0x94a3b8)
                    })
                    .child(
                        "Click a field, type to edit, use Tab to move, and Cmd/Ctrl+Enter to save.",
                    ),
            )
            .when_some(editor.error.as_ref(), |this, error| {
                this.child(
                    div()
                        .id(SharedString::from(format!(
                            "tunnel-delete-editor-{}",
                            editor.existing_tunnel_id.clone().unwrap_or_default()
                        )))
                        .mt_4()
                        .rounded_md()
                        .border_1()
                        .border_color(rgb(0x7f1d1d))
                        .bg(rgb(0x1f1014))
                        .p_3()
                        .text_color(rgb(0xfca5a5))
                        .child(error.clone()),
                )
            })
            .child(
                div()
                    .mt_6()
                    .flex()
                    .flex_col()
                    .gap_4()
                    .when(
                        editor.existing_tunnel_id.is_none()
                            && editor.step == TunnelEditorStep::SelectProfile,
                        |this| {
                            this.child(
                                div()
                                    .child(
                                        div()
                                            .text_sm()
                                            .text_color(rgb(0x94a3b8))
                                            .child("Step 1: Choose SSH Profile"),
                                    )
                                    .child(
                                        div()
                                            .mt_2()
                                            .flex()
                                            .flex_wrap()
                                            .gap_2()
                                            .children(profile_buttons),
                                    ),
                            )
                        },
                    )
                    .when(
                        editor.existing_tunnel_id.is_some()
                            || editor.step == TunnelEditorStep::Configure,
                        |this| {
                            this.child(
                                div()
                                    .flex()
                                    .justify_between()
                                    .items_center()
                                    .child(
                                        div()
                                            .text_sm()
                                            .text_color(rgb(0x94a3b8))
                                            .child(format!("Profile: {selected_profile_name}")),
                                    )
                                    .when(editor.existing_tunnel_id.is_none(), |this| {
                                        this.child(
                                            div()
                                                .px_3()
                                                .py_2()
                                                .rounded_md()
                                                .cursor_pointer()
                                                .bg(rgb(0x0f172a))
                                                .border_1()
                                                .border_color(rgb(0x334155))
                                                .hover(|this| this.bg(rgb(0x1e293b)))
                                                .on_mouse_down(
                                                    MouseButton::Left,
                                                    cx.listener({
                                                        let editor_id = editor_id.to_string();
                                                        move |this, _, _, cx| {
                                                            this.go_to_tunnel_profile_step(
                                                                &editor_id, cx,
                                                            );
                                                        }
                                                    }),
                                                )
                                                .child("Back"),
                                        )
                                    }),
                            )
                            .child(render_tunnel_input(
                                "Name",
                                &editor.name,
                                editor.focused_field == TunnelFormField::Name,
                                editor.select_all && editor.focused_field == TunnelFormField::Name,
                                editor.cursor_offset,
                                editor_id,
                                TunnelFormField::Name,
                                cx,
                            ))
                            .child(
                                div()
                                    .child(div().text_sm().text_color(rgb(0x94a3b8)).child("Mode"))
                                    .child(div().mt_2().flex().gap_2().children(mode_buttons)),
                            )
                            .child(render_tunnel_input(
                                "Bind Host",
                                &editor.bind_host,
                                editor.focused_field == TunnelFormField::BindHost,
                                editor.select_all
                                    && editor.focused_field == TunnelFormField::BindHost,
                                editor.cursor_offset,
                                editor_id,
                                TunnelFormField::BindHost,
                                cx,
                            ))
                            .child(render_tunnel_input(
                                "Bind Port",
                                &editor.bind_port,
                                editor.focused_field == TunnelFormField::BindPort,
                                editor.select_all
                                    && editor.focused_field == TunnelFormField::BindPort,
                                editor.cursor_offset,
                                editor_id,
                                TunnelFormField::BindPort,
                                cx,
                            ))
                            .when(
                                !matches!(editor.mode, TunnelMode::DynamicSocks),
                                |this| {
                                    this.child(render_tunnel_input(
                                        "Target Host",
                                        &editor.target_host,
                                        editor.focused_field == TunnelFormField::TargetHost,
                                        editor.select_all
                                            && editor.focused_field == TunnelFormField::TargetHost,
                                        editor.cursor_offset,
                                        editor_id,
                                        TunnelFormField::TargetHost,
                                        cx,
                                    ))
                                    .child(
                                        render_tunnel_input(
                                            "Target Port",
                                            &editor.target_port,
                                            editor.focused_field == TunnelFormField::TargetPort,
                                            editor.select_all
                                                && editor.focused_field
                                                    == TunnelFormField::TargetPort,
                                            editor.cursor_offset,
                                            editor_id,
                                            TunnelFormField::TargetPort,
                                            cx,
                                        ),
                                    )
                                },
                            )
                        },
                    )
                    .child(
                        div()
                            .mt_2()
                            .flex()
                            .gap_2()
                            .child(
                                div()
                                    .id(SharedString::from(format!("tunnel-save-{editor_id}")))
                                    .px_4()
                                    .py_2()
                                    .rounded_md()
                                    .cursor_pointer()
                                    .bg(rgb(0x1d4ed8))
                                    .hover(|this| this.bg(rgb(0x2563eb)))
                                    .when(
                                        editor.existing_tunnel_id.is_none()
                                            && editor.step == TunnelEditorStep::SelectProfile,
                                        |this| this.opacity(0.5),
                                    )
                                    .on_click(cx.listener({
                                        let editor_id = editor_id.to_string();
                                        move |this, _, _, cx| {
                                            if let Some(editor) =
                                                this.tunnel_editors.get(&editor_id)
                                            {
                                                if editor.existing_tunnel_id.is_none()
                                                    && editor.step
                                                        == TunnelEditorStep::SelectProfile
                                                {
                                                    return;
                                                }
                                            }
                                            this.save_tunnel_editor(&editor_id, cx);
                                        }
                                    }))
                                    .child("Save"),
                            )
                            .child(
                                div()
                                    .id(SharedString::from(format!("tunnel-cancel-{editor_id}")))
                                    .px_4()
                                    .py_2()
                                    .rounded_md()
                                    .cursor_pointer()
                                    .bg(rgb(0x1e293b))
                                    .hover(|this| this.bg(rgb(0x334155)))
                                    .on_click(cx.listener({
                                        let editor_id = editor_id.to_string();
                                        move |this, _, _, cx| {
                                            this.close_tunnel_editor_tab(&editor_id, cx);
                                        }
                                    }))
                                    .child("Cancel"),
                            ),
                    ),
            )
            .when(editor.existing_tunnel_id.is_some(), |this| {
                this.child(
                    div()
                        .id(SharedString::from(format!(
                            "tunnel-delete-editor-{}",
                            editor.existing_tunnel_id.clone().unwrap_or_default()
                        )))
                        .mt_4()
                        .px_4()
                        .py_2()
                        .rounded_md()
                        .cursor_pointer()
                        .bg(rgb(0x3f1d24))
                        .hover(|this| this.bg(rgb(0x7f1d1d)))
                        .text_color(rgb(0xfca5a5))
                        .on_click(cx.listener({
                            let tunnel_id = editor.existing_tunnel_id.clone().unwrap_or_default();
                            move |this, _, _, cx| {
                                this.delete_tunnel_rule(&tunnel_id, cx);
                            }
                        }))
                        .child("Delete Tunnel"),
                )
            })
    }

    fn render_text_preview(
        &self,
        title: String,
        body: String,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        div()
            .id("preview-pane")
            .size_full()
            .p_5()
            .overflow_scroll()
            .bg(rgb(0x020617))
            .text_color(rgb(0xe2e8f0))
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .child(div().text_xl().font_weight(FontWeight::BOLD).child(title))
                    .child({
                        let copy_body = body.clone();
                        div()
                            .px_3()
                            .py_2()
                            .rounded_md()
                            .cursor_pointer()
                            .bg(rgb(0x0f172a))
                            .border_1()
                            .border_color(rgb(0x334155))
                            .hover(|this| this.bg(rgb(0x1e293b)))
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(move |_, _, _, cx| {
                                    cx.write_to_clipboard(ClipboardItem::new_string(
                                        copy_body.clone(),
                                    ));
                                }),
                            )
                            .child(div().text_sm().font_weight(FontWeight::BOLD).child("Copy"))
                    }),
            )
            .child(
                div()
                    .mt_4()
                    .font_family(".SystemUIFontMonospaced")
                    .text_sm()
                    .child(body),
            )
    }

    fn render_ssh_profile_row(
        &self,
        profile: &HostProfile,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let profile_clone = profile.clone();
        let is_app_profile = profile.source == ProfileSource::AppManaged;
        let profile_id = profile.id.clone();

        div()
            .id(SharedString::from(format!("connect-profile-{}", profile.id)))
            .p_3()
            .rounded_md()
            .cursor_pointer()
            .bg(rgb(0x1e293b))
            .hover(|this| this.bg(rgb(0x334155)))
            .on_click(cx.listener(move |this, _, window, cx| {
                this.profile_context_menu = None;
                this.start_session_for_profile(profile_clone.clone(), window, cx);
            }))
            .when(is_app_profile, |this| {
                this.on_mouse_down(
                    MouseButton::Right,
                    cx.listener({
                        let profile_id = profile_id.clone();
                        move |this, _, _, cx| {
                            this.open_profile_context_menu(&profile_id, cx);
                        }
                    }),
                )
            })
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .child(
                        div()
                            .text_sm()
                            .font_weight(FontWeight::BOLD)
                            .child(profile.display_name.clone()),
                    )
                    .child(
                        div()
                            .px_2()
                            .py_0p5()
                            .rounded_full()
                            .bg(match profile.source {
                                ProfileSource::SystemDiscovered => rgb(0x14532d),
                                ProfileSource::AppManaged => rgb(0x7c2d12),
                            })
                            .text_xs()
                            .child(match profile.source {
                                ProfileSource::SystemDiscovered => "System",
                                ProfileSource::AppManaged => "App",
                            }),
                    ),
            )
            .child(
                div()
                    .mt_1()
                    .text_xs()
                    .text_color(rgb(0xcbd5e1))
                    .child(format!(
                        "{}{}",
                        profile.hostname,
                        profile
                            .username
                            .as_ref()
                            .map(|user| format!(" as {user}"))
                            .unwrap_or_default()
                    )),
            )
            .when(
                is_app_profile
                    && self
                        .profile_context_menu
                        .as_ref()
                        .is_some_and(|menu| menu.profile_id == profile.id),
                |this| {
                    this.child(
                        div()
                            .mt_3()
                            .w(px(160.0))
                            .rounded_md()
                            .border_1()
                            .border_color(rgb(0x334155))
                            .bg(rgb(0x0f172a))
                            .p_2()
                            .child(
                                div()
                                    .id(SharedString::from(format!(
                                        "profile-menu-edit-{}",
                                        profile.id
                                    )))
                                    .px_3()
                                    .py_2()
                                    .rounded_md()
                                    .cursor_pointer()
                                    .hover(|this| this.bg(rgb(0x1e293b)))
                                    .on_mouse_down(MouseButton::Left, cx.listener({
                                        let profile_id = profile.id.clone();
                                        move |this, _, _, cx| {
                                            cx.stop_propagation();
                                            this.edit_profile_config(&profile_id, cx);
                                        }
                                    }))
                                    .child("Edit"),
                            ),
                    )
                },
            )
    }

    fn render_ssh_profiles_page(&self, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .id("ssh-profiles-pane")
            .size_full()
            .p_5()
            .overflow_scroll()
            .bg(rgb(0x020617))
            .text_color(rgb(0xe2e8f0))
            .child(
                div()
                    .flex()
                    .justify_between()
                    .items_center()
                    .child(div().text_3xl().font_weight(FontWeight::BOLD).child("SSH"))
                    .child(
                        div()
                            .id("new-ssh-profile")
                            .px_3()
                            .py_2()
                            .rounded_md()
                            .cursor_pointer()
                            .bg(rgb(0x0f172a))
                            .hover(|this| this.bg(rgb(0x1e293b)))
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.open_profile_editor(cx);
                            }))
                            .child(div().text_sm().font_weight(FontWeight::BOLD).child("+")),
                    ),
            )
            .child(
                div().mt_6().flex().flex_col().gap_2().children(
                    self.system_index
                        .profiles
                        .iter()
                        .chain(self.app_profiles.iter())
                        .map(|profile| self.render_ssh_profile_row(profile, cx).into_any_element())
                        .collect::<Vec<_>>(),
                ),
            )
    }

    fn render_sftp_browser_tab(
        &self,
        profile_id: &str,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let profile = self
            .all_profiles()
            .into_iter()
            .find(|profile| profile.id == profile_id)
            .cloned();
        let browser = self.sftp_browsers.get(profile_id).cloned();

        div()
            .id(SharedString::from(format!(
                "sftp-browser-pane-{profile_id}"
            )))
            .size_full()
            .p_5()
            .overflow_scroll()
            .bg(rgb(0x020617))
            .text_color(rgb(0xe2e8f0))
            .child(
                div().text_3xl().font_weight(FontWeight::BOLD).child(
                    profile
                        .as_ref()
                        .map(|profile| format!("SFTP {}", profile.display_name))
                        .unwrap_or_else(|| "SFTP".into()),
                ),
            )
            .when_some(browser.as_ref(), |this, browser| {
                this.child(
                    div()
                        .mt_4()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(
                            div()
                                .id(SharedString::from(format!("sftp-up-{profile_id}")))
                                .px_3()
                                .py_2()
                                .rounded_md()
                                .cursor_pointer()
                                .bg(rgb(0x0f172a))
                                .border_1()
                                .border_color(rgb(0x1e293b))
                                .hover(|this| this.bg(rgb(0x1e293b)))
                                .on_click(cx.listener({
                                    let profile_id = profile_id.to_string();
                                    move |this, _, _, cx| {
                                        this.go_up_sftp_directory(&profile_id, cx);
                                    }
                                }))
                                .child(div().text_sm().font_weight(FontWeight::BOLD).child("Up")),
                        )
                        .child(
                            div()
                                .flex_1()
                                .px_3()
                                .py_2()
                                .rounded_md()
                                .bg(rgb(0x0f172a))
                                .border_1()
                                .border_color(rgb(0x1e293b))
                                .text_color(rgb(0xcbd5e1))
                                .child(format!("Path: {}", browser.path)),
                        )
                        .child(
                            div()
                                .id(SharedString::from(format!("sftp-refresh-{profile_id}")))
                                .px_3()
                                .py_2()
                                .rounded_md()
                                .cursor_pointer()
                                .bg(rgb(0x0f172a))
                                .border_1()
                                .border_color(rgb(0x1e293b))
                                .hover(|this| this.bg(rgb(0x1e293b)))
                                .on_click(cx.listener({
                                    let profile_id = profile_id.to_string();
                                    move |this, _, _, cx| {
                                        this.refresh_sftp_browser(&profile_id, cx);
                                    }
                                }))
                                .child(
                                    div()
                                        .text_sm()
                                        .font_weight(FontWeight::BOLD)
                                        .child("Refresh"),
                                ),
                        ),
                )
                .when_some(browser.error.as_ref(), |this, error| {
                    this.child(
                        div()
                            .mt_3()
                            .rounded_md()
                            .border_1()
                            .border_color(rgb(0x7f1d1d))
                            .bg(rgb(0x1f1014))
                            .p_3()
                            .text_color(rgb(0xfca5a5))
                            .child(error.clone()),
                    )
                })
                .child(div().mt_3().flex().flex_col().gap_2().children(
                    if browser.entries.is_empty() {
                        vec![
                            div()
                                .p_3()
                                .rounded_md()
                                .bg(rgb(0x0f172a))
                                .border_1()
                                .border_color(rgb(0x1e293b))
                                .text_color(rgb(0x94a3b8))
                                .child("No directory entries.")
                                .into_any_element(),
                        ]
                    } else {
                        browser
                            .entries
                            .iter()
                            .map(|entry| {
                                let entry_name = entry.name.clone();
                                let row = div()
                                    .id(SharedString::from(format!(
                                        "sftp-entry-{}-{}",
                                        profile_id, entry.name
                                    )))
                                    .p_3()
                                    .rounded_md()
                                    .bg(rgb(0x0f172a))
                                    .border_1()
                                    .border_color(rgb(0x1e293b))
                                    .child(
                                        div()
                                            .flex()
                                            .justify_between()
                                            .items_center()
                                            .child(
                                                div()
                                                    .text_sm()
                                                    .font_weight(FontWeight::BOLD)
                                                    .child(format!(
                                                        "{}{}",
                                                        if entry.is_dir { "[DIR] " } else { "" },
                                                        entry.name
                                                    )),
                                            )
                                            .child(
                                                div().text_xs().text_color(rgb(0x94a3b8)).child(
                                                    if entry.is_dir { "Directory" } else { "File" },
                                                ),
                                            ),
                                    )
                                    .child(
                                        div()
                                            .mt_1()
                                            .text_xs()
                                            .text_color(rgb(0xcbd5e1))
                                            .child(entry.detail.clone()),
                                    );

                                if entry.is_dir {
                                    row.cursor_pointer()
                                        .hover(|this| this.bg(rgb(0x1e293b)))
                                        .on_click(cx.listener({
                                            let profile_id = profile_id.to_string();
                                            move |this, _, _, cx| {
                                                this.open_sftp_entry(&profile_id, &entry_name, cx);
                                            }
                                        }))
                                        .into_any_element()
                                } else {
                                    row.into_any_element()
                                }
                            })
                            .collect::<Vec<_>>()
                    },
                ))
            })
    }

    fn render_active_tab(&self, window: &mut Window, cx: &mut Context<Self>) -> gpui::AnyElement {
        let tab = self
            .tabs
            .get(self.active_tab)
            .cloned()
            .unwrap_or(WorkspaceTab {
                id: "menu".into(),
                title: "Menu".into(),
                kind: WorkspaceTabKind::Menu,
            });

        match tab.kind {
            WorkspaceTabKind::Menu => self.render_menu_page(cx).into_any_element(),
            WorkspaceTabKind::Profile { profile_id } => self
                .render_profile_details(
                    self.all_profiles()
                        .into_iter()
                        .find(|profile| profile.id == profile_id),
                )
                .into_any_element(),
            WorkspaceTabKind::SftpBrowser { profile_id } => self
                .render_sftp_browser_tab(&profile_id, cx)
                .into_any_element(),
            WorkspaceTabKind::ProfileEditor { editor_id } => self
                .render_profile_editor(&editor_id, window, cx)
                .into_any_element(),
            WorkspaceTabKind::IdentityEditor { editor_id } => self
                .render_identity_editor(&editor_id, window, cx)
                .into_any_element(),
            WorkspaceTabKind::Session { session_id } => self
                .render_session_tab(self.live_sessions.get(&session_id), window, cx)
                .into_any_element(),
            WorkspaceTabKind::TunnelEditor { editor_id } => self
                .render_tunnel_editor(&editor_id, window, cx)
                .into_any_element(),
            WorkspaceTabKind::TextPreview { title, body } => {
                self.render_text_preview(title, body, cx).into_any_element()
            }
        }
    }
}

impl Focusable for PuppyTermView {
    fn focus_handle(&self, _: &App) -> FocusHandle {
        self.terminal_focus.clone()
    }
}

fn metric_card(title: &str, value: usize) -> impl IntoElement {
    div()
        .p_4()
        .rounded_lg()
        .bg(rgb(0x0f172a))
        .border_1()
        .border_color(rgb(0x1e293b))
        .child(div().text_color(rgb(0x94a3b8)).child(title.to_string()))
        .child(
            div()
                .mt_2()
                .text_2xl()
                .font_weight(FontWeight::BOLD)
                .child(value.to_string()),
        )
}

fn session_requests_password(output: &str) -> bool {
    output
        .lines()
        .rev()
        .take(3)
        .map(|line| line.trim().to_ascii_lowercase())
        .any(|line| {
            line.ends_with("password:")
                || line.ends_with("password: ")
                || line.contains("password for ")
        })
}

fn menu_nav_button(
    label: &str,
    active: bool,
    section: MenuSection,
    cx: &mut Context<PuppyTermView>,
) -> impl IntoElement {
    div()
        .id(SharedString::from(format!("menu-nav-{label}")))
        .px_3()
        .py_2()
        .rounded_md()
        .bg(if active { rgb(0x1d4ed8) } else { rgb(0x111827) })
        .border_1()
        .border_color(if active { rgb(0x60a5fa) } else { rgb(0x1e293b) })
        .text_color(rgb(0xf8fafc))
        .cursor_pointer()
        .hover(|this| this.bg(rgb(0x1e293b)))
        .on_click(cx.listener(move |this, _, _, cx| {
            this.open_menu(section, cx);
        }))
        .child(label.to_string())
}

fn tunnel_mode_label(mode: TunnelMode) -> &'static str {
    match mode {
        TunnelMode::Local => "Local",
        TunnelMode::Remote => "Remote",
        TunnelMode::DynamicSocks => "SOCKS",
    }
}

fn parse_sftp_entries(stdout: &str) -> Vec<SftpBrowserEntry> {
    stdout
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("sftp>") || trimmed.starts_with("total") {
                return None;
            }

            let parts = trimmed.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 9 {
                return None;
            }

            let name = parts[8..].join(" ");
            if name.is_empty() {
                return None;
            }

            Some(SftpBrowserEntry {
                name,
                is_dir: parts[0].starts_with('d'),
                detail: parts[0..8].join(" "),
            })
        })
        .collect()
}

fn join_remote_path(base: &str, name: &str) -> String {
    if base == "." || base.is_empty() {
        name.to_string()
    } else if base == "/" {
        format!("/{name}")
    } else {
        format!("{base}/{name}")
    }
}

fn parent_remote_path(path: &str) -> String {
    if path == "." || path == "/" || path.is_empty() {
        return ".".into();
    }

    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some((parent, _)) if parent.is_empty() => "/".into(),
        Some((parent, _)) => parent.into(),
        None => ".".into(),
    }
}

fn render_identity_row(key: &StoredKey, cx: &mut Context<PuppyTermView>) -> impl IntoElement {
    let source_label = match key.source {
        ProfileSource::SystemDiscovered => "System",
        ProfileSource::AppManaged => "App",
    };
    let path_label = key
        .path
        .as_ref()
        .map(|path| path.display().to_string())
        .or_else(|| {
            key.encrypted_blob_path
                .as_ref()
                .map(|path| path.display().to_string())
        })
        .unwrap_or_else(|| "No path".into());

    div()
        .id(SharedString::from(format!("identity-row-{}", key.id)))
        .p_3()
        .rounded_md()
        .bg(rgb(0x1e293b))
        .child(
            div()
                .flex()
                .justify_between()
                .items_center()
                .child(
                    div()
                        .text_sm()
                        .font_weight(FontWeight::BOLD)
                        .child(key.name.clone()),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(
                            div()
                                .px_2()
                                .py_0p5()
                                .rounded_full()
                                .bg(match key.source {
                                    ProfileSource::SystemDiscovered => rgb(0x14532d),
                                    ProfileSource::AppManaged => rgb(0x7c2d12),
                                })
                                .text_xs()
                                .child(source_label),
                        )
                        .child(
                            div()
                                .id(SharedString::from(format!("identity-copy-{}", key.id)))
                                .px_2()
                                .py_1()
                                .rounded_md()
                                .cursor_pointer()
                                .bg(rgb(0x0f172a))
                                .border_1()
                                .border_color(rgb(0x334155))
                                .hover(|this| this.bg(rgb(0x1e293b)))
                                .on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener({
                                        let key_id = key.id.clone();
                                        move |this, _, _, cx| {
                                            cx.stop_propagation();
                                            this.copy_identity_public_key(&key_id, cx);
                                        }
                                    }),
                                )
                                .child(div().text_xs().child("Copy")),
                        ),
                ),
        )
        .child(
            div()
                .mt_1()
                .text_xs()
                .text_color(rgb(0xcbd5e1))
                .child(path_label),
        )
        .when_some(key.fingerprint.as_ref(), |this, fingerprint| {
            this.child(
                div()
                    .mt_1()
                    .text_xs()
                    .text_color(rgb(0x94a3b8))
                    .child(format!("Fingerprint: {fingerprint}")),
            )
        })
}

fn identity_public_key_preview_body(key: &StoredKey) -> String {
    let public_key_path = key.public_key_path.clone().or_else(|| {
        key.path
            .as_ref()
            .map(|path| std::path::PathBuf::from(format!("{}.pub", path.display())))
    });

    match public_key_path {
        Some(path) => match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) => format!(
                "Could not read public key.\n\nPath: {}\nError: {}",
                path.display(),
                error
            ),
        },
        None => "No public key file is associated with this identity.".into(),
    }
}

fn render_tunnel_input(
    label: &str,
    value: &str,
    active: bool,
    select_all: bool,
    cursor_offset: usize,
    editor_id: &str,
    field: TunnelFormField,
    cx: &mut Context<PuppyTermView>,
) -> impl IntoElement {
    let editor_id = editor_id.to_string();
    let label = label.to_string();

    div()
        .child(div().text_sm().text_color(rgb(0x94a3b8)).child(label))
        .child(
            div()
                .id(SharedString::from(format!(
                    "tunnel-field-{}-{:?}",
                    editor_id, field
                )))
                .mt_2()
                .px_3()
                .py_2()
                .rounded_md()
                .cursor_pointer()
                .bg(rgb(0x0f172a))
                .font_family(".SystemUIFontMonospaced")
                .border_1()
                .border_color(if active { rgb(0x38bdf8) } else { rgb(0x1e293b) })
                .hover(|this| this.bg(rgb(0x111827)))
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, event: &MouseDownEvent, window, cx| {
                        this.focus_tunnel_field_at(&editor_id, field, event.position, window, cx);
                    }),
                )
                .child(if active && select_all && !value.is_empty() {
                    StyledText::new(value.to_string())
                        .with_highlights([(0..value.len(), rgb(0x1d4ed8).into())])
                        .into_any_element()
                } else if active {
                    render_inline_input_cursor(value, cursor_offset).into_any_element()
                } else {
                    div()
                        .child(if value.is_empty() {
                            "<empty>".to_string()
                        } else {
                            value.to_string()
                        })
                        .into_any_element()
                }),
        )
}

fn render_profile_input(
    label: &str,
    value: &str,
    active: bool,
    select_all: bool,
    cursor_offset: usize,
    editor_id: &str,
    field: ProfileFormField,
    masked: bool,
    placeholder: Option<&str>,
    cx: &mut Context<PuppyTermView>,
) -> impl IntoElement {
    let editor_id = editor_id.to_string();
    let label = label.to_string();
    let display_value = if masked && !value.is_empty() {
        "*".repeat(value.chars().count())
    } else {
        value.to_string()
    };
    let empty_display = placeholder.unwrap_or("<empty>").to_string();

    div()
        .child(div().text_sm().text_color(rgb(0x94a3b8)).child(label))
        .child(
            div()
                .id(SharedString::from(format!(
                    "profile-field-{}-{:?}",
                    editor_id, field
                )))
                .mt_2()
                .px_3()
                .py_2()
                .rounded_md()
                .cursor_pointer()
                .bg(rgb(0x0f172a))
                .font_family(".SystemUIFontMonospaced")
                .border_1()
                .border_color(if active { rgb(0x38bdf8) } else { rgb(0x1e293b) })
                .hover(|this| this.bg(rgb(0x111827)))
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, event: &MouseDownEvent, window, cx| {
                        this.focus_profile_field_at(&editor_id, field, event.position, window, cx);
                    }),
                )
                .child(if active && select_all && !display_value.is_empty() {
                    StyledText::new(display_value.clone())
                        .with_highlights([(0..display_value.len(), rgb(0x1d4ed8).into())])
                        .into_any_element()
                } else if active {
                    if display_value.is_empty() && !empty_display.is_empty() {
                        div()
                            .flex()
                            .items_center()
                            .child(
                                div()
                                    .text_color(rgb(0x64748b))
                                    .child(empty_display.clone()),
                            )
                            .child(div().w(px(2.0)).h(px(22.0)).bg(rgb(0xe2e8f0)))
                            .into_any_element()
                    } else {
                        render_inline_input_cursor(&display_value, cursor_offset).into_any_element()
                    }
                } else {
                    div()
                        .child(if display_value.is_empty() {
                            empty_display.clone()
                        } else {
                            display_value.clone()
                        })
                        .into_any_element()
                }),
        )
}

fn render_identity_input(
    label: &str,
    value: &str,
    active: bool,
    select_all: bool,
    cursor_offset: usize,
    editor_id: &str,
    field: IdentityFormField,
    cx: &mut Context<PuppyTermView>,
) -> impl IntoElement {
    let editor_id = editor_id.to_string();
    let label = label.to_string();

    div()
        .child(div().text_sm().text_color(rgb(0x94a3b8)).child(label))
        .child(
            div()
                .id(SharedString::from(format!(
                    "identity-field-{}-{:?}",
                    editor_id, field
                )))
                .mt_2()
                .px_3()
                .py_2()
                .rounded_md()
                .cursor_pointer()
                .bg(rgb(0x0f172a))
                .font_family(".SystemUIFontMonospaced")
                .border_1()
                .border_color(if active { rgb(0x38bdf8) } else { rgb(0x1e293b) })
                .hover(|this| this.bg(rgb(0x111827)))
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, event: &MouseDownEvent, window, cx| {
                        this.focus_identity_field_at(&editor_id, field, event.position, window, cx);
                    }),
                )
                .child(if active && select_all && !value.is_empty() {
                    StyledText::new(value.to_string())
                        .with_highlights([(0..value.len(), rgb(0x1d4ed8).into())])
                        .into_any_element()
                } else if active {
                    render_inline_input_cursor(value, cursor_offset).into_any_element()
                } else {
                    div()
                        .child(if value.is_empty() {
                            "<empty>".to_string()
                        } else {
                            value.to_string()
                        })
                        .into_any_element()
                }),
        )
}

fn render_identity_path_input(
    label: &str,
    value: &str,
    active: bool,
    select_all: bool,
    cursor_offset: usize,
    editor_id: &str,
    field: IdentityFormField,
    cx: &mut Context<PuppyTermView>,
) -> impl IntoElement {
    let editor_id_for_input = editor_id.to_string();
    let editor_id_for_button = editor_id.to_string();
    let label = label.to_string();

    div()
        .child(div().text_sm().text_color(rgb(0x94a3b8)).child(label))
        .child(
            div()
                .mt_2()
                .flex()
                .gap_2()
                .child(
                    div()
                        .id(SharedString::from(format!(
                            "identity-field-{}-{:?}",
                            editor_id_for_input, field
                        )))
                        .flex_1()
                        .px_3()
                        .py_2()
                        .rounded_md()
                        .cursor_pointer()
                        .bg(rgb(0x0f172a))
                        .font_family(".SystemUIFontMonospaced")
                        .border_1()
                        .border_color(if active { rgb(0x38bdf8) } else { rgb(0x1e293b) })
                        .hover(|this| this.bg(rgb(0x111827)))
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |this, event: &MouseDownEvent, window, cx| {
                                this.focus_identity_field_at(
                                    &editor_id_for_input,
                                    field,
                                    event.position,
                                    window,
                                    cx,
                                );
                            }),
                        )
                        .child(if active && select_all && !value.is_empty() {
                            StyledText::new(value.to_string())
                                .with_highlights([(0..value.len(), rgb(0x1d4ed8).into())])
                                .into_any_element()
                        } else if active {
                            render_inline_input_cursor(value, cursor_offset).into_any_element()
                        } else {
                            div()
                                .child(if value.is_empty() {
                                    "<empty>".to_string()
                                } else {
                                    value.to_string()
                                })
                                .into_any_element()
                        }),
                )
                .child(
                    div()
                        .id(SharedString::from(format!(
                            "identity-browse-{}-{:?}",
                            editor_id_for_button, field
                        )))
                        .px_4()
                        .py_2()
                        .rounded_md()
                        .cursor_pointer()
                        .bg(rgb(0x1e293b))
                        .border_1()
                        .border_color(rgb(0x334155))
                        .hover(|this| this.bg(rgb(0x334155)))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.pick_identity_file(&editor_id_for_button, field, cx);
                        }))
                        .child("Browse"),
                ),
        )
}

fn tunnel_field_value_mut(editor: &mut TunnelEditorState, field: TunnelFormField) -> &mut String {
    match field {
        TunnelFormField::Name => &mut editor.name,
        TunnelFormField::BindHost => &mut editor.bind_host,
        TunnelFormField::BindPort => &mut editor.bind_port,
        TunnelFormField::TargetHost => &mut editor.target_host,
        TunnelFormField::TargetPort => &mut editor.target_port,
    }
}

fn tunnel_field_value(editor: &TunnelEditorState, field: TunnelFormField) -> &str {
    match field {
        TunnelFormField::Name => &editor.name,
        TunnelFormField::BindHost => &editor.bind_host,
        TunnelFormField::BindPort => &editor.bind_port,
        TunnelFormField::TargetHost => &editor.target_host,
        TunnelFormField::TargetPort => &editor.target_port,
    }
}

fn profile_field_value_mut(
    editor: &mut ProfileEditorState,
    field: ProfileFormField,
) -> &mut String {
    match field {
        ProfileFormField::DisplayName => &mut editor.display_name,
        ProfileFormField::Hostname => &mut editor.hostname,
        ProfileFormField::Username => &mut editor.username,
        ProfileFormField::Port => &mut editor.port,
        ProfileFormField::IdentityPath => &mut editor.identity_path,
        ProfileFormField::Password => &mut editor.password,
    }
}

fn profile_field_value(editor: &ProfileEditorState, field: ProfileFormField) -> &str {
    match field {
        ProfileFormField::DisplayName => &editor.display_name,
        ProfileFormField::Hostname => &editor.hostname,
        ProfileFormField::Username => &editor.username,
        ProfileFormField::Port => &editor.port,
        ProfileFormField::IdentityPath => &editor.identity_path,
        ProfileFormField::Password => &editor.password,
    }
}

fn identity_field_value_mut(
    editor: &mut IdentityEditorState,
    field: IdentityFormField,
) -> &mut String {
    match field {
        IdentityFormField::Name => &mut editor.name,
        IdentityFormField::PrivateKeyPath => &mut editor.private_key_path,
        IdentityFormField::PublicKeyPath => &mut editor.public_key_path,
        IdentityFormField::Fingerprint => &mut editor.fingerprint,
    }
}

fn identity_field_value(editor: &IdentityEditorState, field: IdentityFormField) -> &str {
    match field {
        IdentityFormField::Name => &editor.name,
        IdentityFormField::PrivateKeyPath => &editor.private_key_path,
        IdentityFormField::PublicKeyPath => &editor.public_key_path,
        IdentityFormField::Fingerprint => &editor.fingerprint,
    }
}

fn identity_editor_fields(mode: IdentityInputMode) -> &'static [IdentityFormField] {
    match mode {
        IdentityInputMode::Existing => &[
            IdentityFormField::Name,
            IdentityFormField::PrivateKeyPath,
            IdentityFormField::PublicKeyPath,
            IdentityFormField::Fingerprint,
        ],
        IdentityInputMode::CreateNew => &[IdentityFormField::Name],
    }
}

fn sanitize_key_filename(name: &str) -> String {
    let sanitized = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    if sanitized.is_empty() {
        "identity".into()
    } else {
        sanitized
    }
}

fn generate_new_identity_key(
    key_blobs: &std::path::Path,
    key_id: &str,
    key_name: &str,
) -> anyhow::Result<StoredKey> {
    let base_name = sanitize_key_filename(key_name);
    let suffix_len = key_id.len().min(8);
    let private_key_path = key_blobs.join(format!("{}_{}", base_name, &key_id[..suffix_len]));
    let public_key_path = private_key_path.with_extension("pub");

    let output = Command::new("ssh-keygen")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-C")
        .arg(key_name)
        .arg("-f")
        .arg(&private_key_path)
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        anyhow::bail!(
            "ssh-keygen failed{}",
            if stderr.is_empty() {
                ".".to_string()
            } else {
                format!(": {stderr}")
            }
        );
    }

    let fingerprint = fingerprint_for_public_key(&public_key_path);

    Ok(StoredKey {
        id: key_id.to_string(),
        source: ProfileSource::AppManaged,
        name: key_name.to_string(),
        path: Some(private_key_path),
        public_key_path: Some(public_key_path),
        fingerprint,
        encrypted_blob_path: None,
        meta: crate::domain::RecordMeta::new(),
    })
}

fn fingerprint_for_public_key(path: &std::path::Path) -> Option<String> {
    let output = Command::new("ssh-keygen")
        .arg("-lf")
        .arg(path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    stdout.split_whitespace().nth(1).map(ToOwned::to_owned)
}

fn char_to_byte_index(value: &str, char_offset: usize) -> usize {
    value
        .char_indices()
        .nth(char_offset)
        .map(|(idx, _)| idx)
        .unwrap_or(value.len())
}

fn insert_text_at_cursor(value: &mut String, cursor_offset: &mut usize, text: &str) {
    let byte_index = char_to_byte_index(value, *cursor_offset);
    value.insert_str(byte_index, text);
    *cursor_offset += text.chars().count();
}

fn delete_char_before_cursor(value: &mut String, cursor_offset: &mut usize) {
    if *cursor_offset == 0 {
        return;
    }
    let start = char_to_byte_index(value, cursor_offset.saturating_sub(1));
    let end = char_to_byte_index(value, *cursor_offset);
    value.replace_range(start..end, "");
    *cursor_offset = cursor_offset.saturating_sub(1);
}

fn split_at_char_offset(value: &str, cursor_offset: usize) -> (String, String) {
    let cursor_offset = cursor_offset.min(value.chars().count());
    let byte_index = char_to_byte_index(value, cursor_offset);
    (
        value[..byte_index].to_string(),
        value[byte_index..].to_string(),
    )
}

fn render_inline_input_cursor(value: &str, cursor_offset: usize) -> impl IntoElement {
    let (before, after) = split_at_char_offset(value, cursor_offset);
    div()
        .flex()
        .items_center()
        .when(!before.is_empty(), |this| this.child(before))
        .child(div().w(px(2.0)).h(px(22.0)).bg(rgb(0xe2e8f0)))
        .when(!after.is_empty(), |this| this.child(after))
}

fn terminal_bytes_for_keystroke(event: &KeyDownEvent) -> Option<String> {
    let keystroke = &event.keystroke;
    let key = keystroke.key.to_lowercase();

    match key.as_str() {
        "enter" => return Some("\r".into()),
        "tab" if keystroke.modifiers.shift => return Some("\u{1b}[Z".into()),
        "tab" => return Some("\t".into()),
        "backspace" => return Some("\u{7f}".into()),
        "escape" => return Some("\u{1b}".into()),
        "up" => return Some("\u{1b}[A".into()),
        "down" => return Some("\u{1b}[B".into()),
        "right" => return Some("\u{1b}[C".into()),
        "left" => return Some("\u{1b}[D".into()),
        "home" => return Some("\u{1b}[H".into()),
        "end" => return Some("\u{1b}[F".into()),
        "delete" => return Some("\u{1b}[3~".into()),
        "pageup" => return Some("\u{1b}[5~".into()),
        "pagedown" => return Some("\u{1b}[6~".into()),
        _ => {}
    }

    if keystroke.modifiers.platform {
        return None;
    }

    if keystroke.modifiers.control && !keystroke.modifiers.alt {
        let byte = match key.as_str() {
            "space" => 0,
            "[" => 27,
            "\\" => 28,
            "]" => 29,
            "^" => 30,
            "_" => 31,
            _ => {
                let ch = keystroke.key.chars().next()?;
                if !ch.is_ascii_alphabetic() {
                    return None;
                }
                ch.to_ascii_lowercase() as u8 - b'a' + 1
            }
        };
        return Some((byte as char).to_string());
    }

    if let Some(text) = keystroke.key_char.as_ref() {
        if keystroke.modifiers.alt {
            return Some(format!("\u{1b}{text}"));
        }
        return Some(text.clone());
    }

    None
}

fn render_terminal_cursor(screen: &str, row: u16, col: u16) -> String {
    let mut lines = if screen.is_empty() {
        vec![String::new()]
    } else {
        screen.lines().map(ToOwned::to_owned).collect::<Vec<_>>()
    };

    let row = usize::from(row);
    let col = usize::from(col);

    while lines.len() <= row {
        lines.push(String::new());
    }

    let line = &mut lines[row];
    let current_len = line.chars().count();
    if current_len < col {
        line.push_str(&" ".repeat(col - current_len));
    }

    let mut chars = line.chars().collect::<Vec<_>>();
    if col < chars.len() {
        chars[col] = '█';
    } else {
        chars.push('█');
    }
    *line = chars.into_iter().collect();
    lines.join("\n")
}

fn terminal_text_offset_for_grid(screen: &str, point: TerminalGridPoint) -> Option<usize> {
    let mut offset = 0usize;
    let mut lines = screen.split('\n').peekable();

    for row in 0..=point.row {
        let line = lines.next()?;
        if row == point.row {
            let mut col_offset = 0usize;
            let mut seen = 0usize;
            for ch in line.chars() {
                if seen == point.col {
                    break;
                }
                col_offset += ch.len_utf8();
                seen += 1;
            }
            if point.col > seen {
                col_offset = line.len();
            }
            return Some(offset + col_offset);
        }

        offset += line.len();
        if lines.peek().is_some() {
            offset += 1;
        }
    }

    Some(screen.len())
}

fn clamp_pixels(value: Pixels, min: Pixels, max: Pixels) -> Pixels {
    value.max(min).min(max)
}

impl Render for PuppyTermView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let hosts_selected = self.selected_menu_section == MenuSection::Hosts;

        div()
            .size_full()
            .on_mouse_move(cx.listener(Self::on_root_mouse_move))
            .on_mouse_up(MouseButton::Left, cx.listener(Self::end_resize))
            .on_mouse_up_out(MouseButton::Left, cx.listener(Self::end_resize))
            .bg(rgb(0x030712))
            .text_color(rgb(0xe2e8f0))
            .child(
                div()
                    .h_full()
                    .flex()
                    .child(
                        div()
                            .id("sidebar-scroll")
                            .w(self.sidebar_width)
                            .h_full()
                            .p_4()
                            .overflow_scroll()
                            .bg(rgb(0x111827))
                            .child(
                                div().w_full().flex().justify_center().child(
                                    img(std::path::PathBuf::from(SIDEBAR_LOGO_PATH))
                                        .w(px(220.0))
                                        .h(px(220.0)),
                                ),
                            )
                            .child(
                                div()
                                    .mt_4()
                                    .text_sm()
                                    .text_color(rgb(0x94a3b8))
                                    .child("Menu"),
                            )
                            .child(
                                div()
                                    .mt_2()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .child(menu_nav_button(
                                        "SSH",
                                        hosts_selected,
                                        MenuSection::Hosts,
                                        cx,
                                    ))
                                    .child(menu_nav_button(
                                        "Identities",
                                        self.selected_menu_section == MenuSection::Identities,
                                        MenuSection::Identities,
                                        cx,
                                    ))
                                    .child(menu_nav_button(
                                        "Port Forwarding",
                                        self.selected_menu_section == MenuSection::PortForwarding,
                                        MenuSection::PortForwarding,
                                        cx,
                                    ))
                                    .child(menu_nav_button(
                                        "SFTP",
                                        self.selected_menu_section == MenuSection::Sftp,
                                        MenuSection::Sftp,
                                        cx,
                                    )),
                            ),
                    )
                    .child(
                        div()
                            .id("sidebar-resize-handle")
                            .w(px(8.0))
                            .h_full()
                            .cursor(CursorStyle::ResizeColumn)
                            .bg(if self.active_resize == Some(ActivePaneResize::Sidebar) {
                                rgb(0x38bdf8)
                            } else {
                                rgb(0x1f2937)
                            })
                            .hover(|this| this.bg(rgb(0x334155)))
                            .on_mouse_down(
                                MouseButton::Left,
                                cx.listener(Self::begin_sidebar_resize),
                            ),
                    )
                    .child(
                        div()
                            .flex_1()
                            .h_full()
                            .flex()
                            .flex_col()
                            .child(
                                div()
                                    .px_4()
                                    .py_3()
                                    .flex()
                                    .gap_2()
                                    .border_b_1()
                                    .border_color(rgb(0x1f2937))
                                    .children(
                                        self.tabs
                                            .iter()
                                            .enumerate()
                                            .filter(|(_, tab)| Self::tab_is_closable(tab))
                                            .map(|(index, tab)| {
                                                let active = self.active_tab == index;
                                                let tab_index = index;
                                                let close_index = index;
                                                div()
                                                    .id(SharedString::from(tab.id.clone()))
                                                    .px_3()
                                                    .py_2()
                                                    .rounded_md()
                                                    .cursor_pointer()
                                                    .bg(if active {
                                                        rgb(0x1d4ed8)
                                                    } else {
                                                        rgb(0x0f172a)
                                                    })
                                                    .hover(move |this| {
                                                        this.bg(if active {
                                                            rgb(0x2563eb)
                                                        } else {
                                                            rgb(0x1e293b)
                                                        })
                                                    })
                                                    .on_click(cx.listener(move |this, _, _, cx| {
                                                        this.active_tab = tab_index;
                                                        cx.notify();
                                                    }))
                                                    .child(
                                                        div()
                                                            .flex()
                                                            .items_center()
                                                            .gap_2()
                                                            .child(
                                                                div()
                                                                    .text_sm()
                                                                    .child(tab.title.clone()),
                                                            )
                                                            .child(
                                                                div()
                                                                    .id(SharedString::from(
                                                                        format!("{}-close", tab.id),
                                                                    ))
                                                                    .px_1()
                                                                    .rounded_sm()
                                                                    .text_color(rgb(0xe2e8f0))
                                                                    .hover(move |this| {
                                                                        this.bg(if active {
                                                                            rgb(0x1d4ed8)
                                                                        } else {
                                                                            rgb(0x334155)
                                                                        })
                                                                    })
                                                                    .on_click(cx.listener(
                                                                        move |this, _, _, cx| {
                                                                            cx.stop_propagation();
                                                                            this.close_tab(
                                                                                close_index,
                                                                                cx,
                                                                            );
                                                                        },
                                                                    ))
                                                                    .child("x"),
                                                            ),
                                                    )
                                                    .into_any_element()
                                            }),
                                    ),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .h_full()
                                    .overflow_hidden()
                                    .child(self.render_active_tab(window, cx)),
                            ),
                    ),
            )
    }
}

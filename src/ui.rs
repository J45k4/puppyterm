use std::{collections::HashMap, sync::Arc, time::Duration};

use gpui::{
    App, Context, FocusHandle, Focusable, FontWeight, KeyDownEvent, MouseButton, Render,
    SharedString, Timer, Window, div, prelude::*, px, rgb,
};
use uuid::Uuid;

use crate::{
    app::{BootState, PuppyTermServices},
    domain::{HostProfile, ProfileSource, StoredKey, SystemProfileIndex, TunnelMode, TunnelSpec},
    interop::scan_default_ssh_assets,
    ssh::{ManagedTunnel, SftpOperation},
    terminal::TerminalSessionHandle,
};

#[derive(Clone)]
enum WorkspaceTabKind {
    Overview,
    Profile { profile_id: String },
    Session { session_id: String },
    TextPreview { title: String, body: String },
}

#[derive(Clone)]
struct WorkspaceTab {
    id: String,
    title: String,
    kind: WorkspaceTabKind,
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
    terminal_focus: FocusHandle,
}

impl PuppyTermView {
    pub fn new(boot: BootState, terminal_focus: FocusHandle, cx: &mut Context<Self>) -> Self {
        let selected_profile_id = boot
            .system_index
            .profiles
            .first()
            .or_else(|| boot.app_profiles.first())
            .map(|profile| profile.id.clone());

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
                id: "overview".into(),
                title: "Overview".into(),
                kind: WorkspaceTabKind::Overview,
            }],
            active_tab: 0,
            log_lines: vec!["PuppyTerm initialized.".into()],
            live_sessions: HashMap::new(),
            live_tunnels: HashMap::new(),
            selected_profile_id,
            terminal_focus,
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

    fn add_log(&mut self, message: impl Into<String>) {
        self.log_lines.push(message.into());
        if self.log_lines.len() > 200 {
            let overflow = self.log_lines.len().saturating_sub(200);
            self.log_lines.drain(..overflow);
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

    fn select_profile(&mut self, profile_id: &str, cx: &mut Context<Self>) {
        self.selected_profile_id = Some(profile_id.to_string());
        self.open_profile_tab(profile_id, cx);
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

        match self.services.ssh_backend.open_terminal_session(&profile) {
            Ok(handle) => {
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

    fn on_terminal_mouse_down(
        &mut self,
        _: &gpui::MouseDownEvent,
        window: &mut Window,
        _: &mut Context<Self>,
    ) {
        self.terminal_focus.focus(window);
    }

    fn on_terminal_key_down(
        &mut self,
        event: &KeyDownEvent,
        _: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(payload) = terminal_bytes_for_keystroke(event) else {
            return;
        };
        let Some(handle) = self.active_session_handle() else {
            return;
        };

        match handle.send_input(&payload) {
            Ok(()) => cx.stop_propagation(),
            Err(error) => {
                self.add_log(format!("Terminal input failed: {error}"));
                cx.notify();
            }
        }
    }

    fn render_overview(&self) -> impl IntoElement {
        div()
            .id("overview-pane")
            .size_full()
            .p_5()
            .overflow_scroll()
            .bg(rgb(0x020617))
            .text_color(rgb(0xe2e8f0))
            .child(
                div()
                    .text_3xl()
                    .font_weight(FontWeight::BOLD)
                    .child("PuppyTerm"),
            )
            .child(div().mt_3().text_color(rgb(0x94a3b8)).child(
                "GPUI-based SSH workspace with native OpenSSH discovery and app-managed profiles.",
            ))
            .child(div().mt_6().grid().grid_cols(3).gap_3().children([
                metric_card("System Profiles", self.system_index.profiles.len()),
                metric_card("App Profiles", self.app_profiles.len()),
                metric_card("Known Hosts", self.system_index.known_hosts.len()),
                metric_card("Discovered Keys", self.system_index.keys.len()),
                metric_card("Saved Tunnels", self.tunnels.len()),
                metric_card("Recent Sessions", self.recent_sessions.len()),
            ]))
            .child(
                div()
                    .mt_6()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .text_lg()
                            .font_weight(FontWeight::BOLD)
                            .child("Runtime"),
                    )
                    .child(format!("ssh available: {}", self.binary_status.ssh))
                    .child(format!("sftp available: {}", self.binary_status.sftp))
                    .child(format!("scp available: {}", self.binary_status.scp))
                    .child(format!("live sessions: {}", self.live_sessions.len()))
                    .child(format!("live tunnels: {}", self.live_tunnels.len())),
            )
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
                let screen = if snapshot.rendered_screen.trim().is_empty() {
                    snapshot.raw_output
                } else {
                    snapshot.rendered_screen
                };
                let focused = self.terminal_focus.is_focused(window);
                let screen = if focused && !snapshot.hide_cursor {
                    render_terminal_cursor(&screen, snapshot.cursor_row, snapshot.cursor_col)
                } else {
                    screen
                };

                div()
                    .id(SharedString::from(format!("session-pane-{}", snapshot.id)))
                    .track_focus(&self.terminal_focus)
                    .on_mouse_down(MouseButton::Left, cx.listener(Self::on_terminal_mouse_down))
                    .on_key_down(cx.listener(Self::on_terminal_key_down))
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
                            .font_family(".SystemUIFontMonospaced")
                            .text_sm()
                            .child(screen),
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

    fn render_text_preview(&self, title: String, body: String) -> impl IntoElement {
        div()
            .id("preview-pane")
            .size_full()
            .p_5()
            .overflow_scroll()
            .bg(rgb(0x020617))
            .text_color(rgb(0xe2e8f0))
            .child(div().text_xl().font_weight(FontWeight::BOLD).child(title))
            .child(
                div()
                    .mt_4()
                    .font_family(".SystemUIFontMonospaced")
                    .text_sm()
                    .child(body),
            )
    }

    fn render_active_tab(&self, window: &mut Window, cx: &mut Context<Self>) -> gpui::AnyElement {
        let tab = self
            .tabs
            .get(self.active_tab)
            .cloned()
            .unwrap_or(WorkspaceTab {
                id: "overview".into(),
                title: "Overview".into(),
                kind: WorkspaceTabKind::Overview,
            });

        match tab.kind {
            WorkspaceTabKind::Overview => self.render_overview().into_any_element(),
            WorkspaceTabKind::Profile { profile_id } => self
                .render_profile_details(
                    self.all_profiles()
                        .into_iter()
                        .find(|profile| profile.id == profile_id),
                )
                .into_any_element(),
            WorkspaceTabKind::Session { session_id } => self
                .render_session_tab(self.live_sessions.get(&session_id), window, cx)
                .into_any_element(),
            WorkspaceTabKind::TextPreview { title, body } => {
                self.render_text_preview(title, body).into_any_element()
            }
        }
    }

    fn render_profile_row(
        &self,
        profile: &HostProfile,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let selected = self.selected_profile_id.as_deref() == Some(profile.id.as_str());
        let profile_id = profile.id.clone();
        let badge = match profile.source {
            ProfileSource::SystemDiscovered => "System",
            ProfileSource::AppManaged => "App",
        };

        div()
            .id(SharedString::from(format!("profile-{}", profile.id)))
            .p_2()
            .rounded_md()
            .cursor_pointer()
            .bg(if selected {
                rgb(0x1d4ed8)
            } else {
                rgb(0x1e293b)
            })
            .hover(|this| this.bg(rgb(0x334155)))
            .on_click(cx.listener(move |this, _, _, cx| {
                this.select_profile(&profile_id, cx);
            }))
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
                            .child(badge),
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

fn action_button(
    label: &str,
    cx: &mut Context<PuppyTermView>,
    on_click: impl Fn(&mut PuppyTermView, &mut Window, &mut Context<PuppyTermView>) + 'static,
) -> impl IntoElement {
    div()
        .id(SharedString::from(format!("button-{label}")))
        .px_3()
        .py_2()
        .rounded_md()
        .bg(rgb(0x1d4ed8))
        .text_color(rgb(0xf8fafc))
        .cursor_pointer()
        .hover(|this| this.bg(rgb(0x2563eb)))
        .on_click(cx.listener(move |this, _, window, cx| on_click(this, window, cx)))
        .child(label.to_string())
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

impl Render for PuppyTermView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let system_profiles = self.system_index.profiles.clone();
        let app_profiles = self.app_profiles.clone();
        let selected_profile = self.selected_profile().cloned();
        let logs = self.log_lines.clone();
        let startup_error = self.startup_error.clone();
        let system_profile_rows = system_profiles
            .iter()
            .map(|profile| self.render_profile_row(profile, cx).into_any_element())
            .collect::<Vec<_>>();
        let app_profile_rows = app_profiles
            .iter()
            .map(|profile| self.render_profile_row(profile, cx).into_any_element())
            .collect::<Vec<_>>();

        div()
            .size_full()
            .bg(rgb(0x030712))
            .text_color(rgb(0xe2e8f0))
            .child(
                div()
                    .h_full()
                    .flex()
                    .child(
                        div()
                            .id("sidebar-scroll")
                            .w(px(300.0))
                            .h_full()
                            .p_4()
                            .overflow_scroll()
                            .bg(rgb(0x111827))
                            .border_r_1()
                            .border_color(rgb(0x1f2937))
                            .child(
                                div()
                                    .text_2xl()
                                    .font_weight(FontWeight::BOLD)
                                    .child("Connections"),
                            )
                            .child(
                                div()
                                    .mt_3()
                                    .flex()
                                    .gap_2()
                                    .child(action_button("Refresh", cx, |this, _, cx| {
                                        this.refresh(cx)
                                    }))
                                    .child(action_button("Import", cx, |this, _, cx| {
                                        this.import_selected_profile(cx)
                                    })),
                            )
                            .child(
                                div()
                                    .mt_6()
                                    .text_sm()
                                    .text_color(rgb(0x94a3b8))
                                    .child("System Profiles"),
                            )
                            .child(
                                div()
                                    .mt_2()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .children(system_profile_rows),
                            )
                            .child(
                                div()
                                    .mt_6()
                                    .text_sm()
                                    .text_color(rgb(0x94a3b8))
                                    .child("App Profiles"),
                            )
                            .child(
                                div()
                                    .mt_2()
                                    .flex()
                                    .flex_col()
                                    .gap_2()
                                    .children(app_profile_rows),
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
                                    .p_4()
                                    .border_b_1()
                                    .border_color(rgb(0x1f2937))
                                    .bg(rgb(0x020617))
                                    .child(
                                        div()
                                            .flex()
                                            .justify_between()
                                            .items_center()
                                            .child(
                                                div()
                                                    .flex()
                                                    .gap_2()
                                                    .child(action_button(
                                                        "Open Session",
                                                        cx,
                                                        |this, window, cx| {
                                                            this.start_session(window, cx)
                                                        },
                                                    ))
                                                    .child(action_button(
                                                        "SFTP Preview",
                                                        cx,
                                                        |this, _, cx| this.preview_sftp(cx),
                                                    ))
                                                    .child(action_button(
                                                        "Tunnel Preview",
                                                        cx,
                                                        |this, _, cx| this.preview_tunnel(cx),
                                                    ))
                                                    .child(action_button(
                                                        "Refresh Output",
                                                        cx,
                                                        |this, _, cx| {
                                                            this.refresh_session_output(cx)
                                                        },
                                                    )),
                                            )
                                            .child(
                                                div().text_sm().text_color(rgb(0x94a3b8)).child(
                                                    selected_profile
                                                        .as_ref()
                                                        .map(|profile| {
                                                            format!(
                                                                "Selected: {}",
                                                                profile.display_name
                                                            )
                                                        })
                                                        .unwrap_or_else(|| {
                                                            "Select a profile".into()
                                                        }),
                                                ),
                                            ),
                                    ),
                            )
                            .child(
                                div()
                                    .px_4()
                                    .py_3()
                                    .flex()
                                    .gap_2()
                                    .border_b_1()
                                    .border_color(rgb(0x1f2937))
                                    .children(self.tabs.iter().enumerate().map(|(index, tab)| {
                                        let active = self.active_tab == index;
                                        let tab_index = index;
                                        div()
                                            .id(SharedString::from(tab.id.clone()))
                                            .px_3()
                                            .py_2()
                                            .rounded_md()
                                            .cursor_pointer()
                                            .bg(if active { rgb(0x1d4ed8) } else { rgb(0x0f172a) })
                                            .hover(|this| this.bg(rgb(0x1e293b)))
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                this.active_tab = tab_index;
                                                cx.notify();
                                            }))
                                            .child(tab.title.clone())
                                    })),
                            )
                            .child(div().flex_1().child(self.render_active_tab(window, cx))),
                    )
                    .child(
                        div()
                            .id("detail-scroll")
                            .w(px(340.0))
                            .h_full()
                            .p_4()
                            .overflow_scroll()
                            .bg(rgb(0x111827))
                            .border_l_1()
                            .border_color(rgb(0x1f2937))
                            .child(
                                div()
                                    .text_xl()
                                    .font_weight(FontWeight::BOLD)
                                    .child("Detail"),
                            )
                            .child(
                                startup_error
                                    .map(|error| {
                                        div()
                                            .mt_3()
                                            .p_3()
                                            .rounded_md()
                                            .bg(rgb(0x7f1d1d))
                                            .child(error)
                                    })
                                    .unwrap_or_else(|| div().mt_0()),
                            )
                            .child(
                                div()
                                    .mt_4()
                                    .child(self.render_profile_details(selected_profile.as_ref())),
                            )
                            .child(
                                div()
                                    .mt_6()
                                    .child(
                                        div()
                                            .text_lg()
                                            .font_weight(FontWeight::BOLD)
                                            .child("Activity"),
                                    )
                                    .child(
                                        div()
                                            .mt_2()
                                            .font_family(".SystemUIFontMonospaced")
                                            .text_xs()
                                            .text_color(rgb(0xcbd5e1))
                                            .children(
                                                logs.iter()
                                                    .rev()
                                                    .take(24)
                                                    .map(|line| div().mb_1().child(line.clone())),
                                            ),
                                    ),
                            ),
                    ),
            )
    }
}

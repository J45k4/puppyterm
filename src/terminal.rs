use std::{
    io::{Read, Write},
    path::PathBuf,
    sync::Arc,
    thread,
};

use anyhow::{Context, Result, anyhow};
use parking_lot::Mutex;
use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct TerminalCommand {
    pub title: String,
    pub program: String,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<PathBuf>,
}

impl TerminalCommand {
    pub fn preview(&self) -> String {
        let mut segments = vec![self.program.clone()];
        for arg in &self.args {
            if arg.contains(' ') {
                segments.push(format!("{arg:?}"));
            } else {
                segments.push(arg.clone());
            }
        }
        segments.join(" ")
    }
}

#[derive(Debug, Clone)]
pub struct SessionSnapshot {
    pub id: String,
    pub title: String,
    pub command_preview: String,
    pub raw_output: String,
    pub rendered_screen: String,
    pub cursor_row: u16,
    pub cursor_col: u16,
    pub hide_cursor: bool,
    pub exit_status: Option<i32>,
}

#[derive(Clone)]
pub struct TerminalSessionHandle {
    snapshot: Arc<Mutex<SessionSnapshot>>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
    child: Arc<Mutex<Box<dyn portable_pty::Child + Send + Sync>>>,
    killer: Arc<Mutex<Box<dyn ChildKiller + Send + Sync>>>,
    parser: Arc<Mutex<vt100::Parser>>,
}

impl TerminalSessionHandle {
    pub fn snapshot(&self) -> SessionSnapshot {
        self.snapshot.lock().clone()
    }

    pub fn send_input(&self, input: &str) -> Result<()> {
        self.scroll_scrollback(0);
        let mut writer = self.writer.lock();
        writer
            .write_all(input.as_bytes())
            .context("writing to PTY session")?;
        writer.flush().context("flushing PTY writer")
    }

    pub fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        self.master
            .lock()
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|error| anyhow!(error))
    }

    pub fn terminate(&self) -> Result<()> {
        self.killer
            .lock()
            .kill()
            .context("terminating PTY child process")
    }

    pub fn scroll_scrollback(&self, rows: usize) {
        let mut parser = self.parser.lock();
        parser.screen_mut().set_scrollback(rows);
        let mut snapshot = self.snapshot.lock();
        sync_snapshot_from_parser(&mut snapshot, &parser);
    }

    pub fn scroll_scrollback_by(&self, delta_rows: isize) {
        let mut parser = self.parser.lock();
        let current = parser.screen().scrollback();
        let next = if delta_rows >= 0 {
            current.saturating_add(delta_rows as usize)
        } else {
            current.saturating_sub(delta_rows.unsigned_abs())
        };
        parser.screen_mut().set_scrollback(next);
        let mut snapshot = self.snapshot.lock();
        sync_snapshot_from_parser(&mut snapshot, &parser);
    }
}

#[derive(Debug, Default)]
pub struct TerminalService;

impl TerminalService {
    pub fn spawn(&self, command: TerminalCommand) -> Result<TerminalSessionHandle> {
        let pty_system = native_pty_system();
        let pair = pty_system.openpty(PtySize {
            rows: 30,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        })?;

        let mut builder = CommandBuilder::new(&command.program);
        builder.args(&command.args);
        for (key, value) in &command.env {
            builder.env(key, value);
        }
        if let Some(cwd) = &command.cwd {
            builder.cwd(cwd);
        }

        let child = pair
            .slave
            .spawn_command(builder)
            .with_context(|| format!("spawning {}", command.preview()))?;
        let killer = child.clone_killer();
        let mut reader = pair.master.try_clone_reader()?;
        let writer = Arc::new(Mutex::new(pair.master.take_writer()?));

        let preview = command.preview();
        let snapshot = Arc::new(Mutex::new(SessionSnapshot {
            id: Uuid::new_v4().to_string(),
            title: command.title,
            command_preview: preview,
            raw_output: String::new(),
            rendered_screen: String::new(),
            cursor_row: 0,
            cursor_col: 0,
            hide_cursor: false,
            exit_status: None,
        }));
        let parser = Arc::new(Mutex::new(vt100::Parser::new(30, 120, 2_000)));

        let snapshot_for_reader = Arc::clone(&snapshot);
        let parser_for_reader = Arc::clone(&parser);
        let writer_for_reader = Arc::clone(&writer);
        thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            let mut responder = TerminalResponder::default();
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(bytes_read) => {
                        let chunk = &buffer[..bytes_read];
                        let mut parser = parser_for_reader.lock();
                        let mut snapshot = snapshot_for_reader.lock();
                        apply_terminal_bytes(&mut snapshot, &mut parser, chunk);
                        for response in responder.responses(&parser, chunk) {
                            let _ = writer_for_reader.lock().write_all(response.as_bytes());
                            let _ = writer_for_reader.lock().flush();
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let snapshot_for_waiter = Arc::clone(&snapshot);
        let child = Arc::new(Mutex::new(child));
        let child_for_waiter = Arc::clone(&child);
        thread::spawn(move || {
            let exit_code = child_for_waiter
                .lock()
                .wait()
                .ok()
                .map(|status| status.exit_code() as i32);
            snapshot_for_waiter.lock().exit_status = exit_code;
        });

        Ok(TerminalSessionHandle {
            snapshot,
            writer,
            master: Arc::new(Mutex::new(pair.master)),
            child,
            killer: Arc::new(Mutex::new(killer)),
            parser,
        })
    }
}

#[derive(Default)]
struct TerminalResponder {
    pending: Vec<u8>,
}

impl TerminalResponder {
    fn responses(&mut self, parser: &vt100::Parser, chunk: &[u8]) -> Vec<String> {
        self.pending.extend_from_slice(chunk);

        let mut responses = Vec::new();
        let mut cursor = 0;
        while cursor < self.pending.len() {
            let Some(offset) = self.pending[cursor..].iter().position(|byte| *byte == 0x1b) else {
                break;
            };
            cursor += offset;

            let Some((consumed, response)) = Self::parse_escape(parser, &self.pending[cursor..])
            else {
                break;
            };
            if let Some(response) = response {
                responses.push(response);
            }
            cursor += consumed;
        }

        if cursor > 0 {
            self.pending.drain(..cursor);
        } else if self.pending.len() > 64 {
            let split_at = self.pending.len().saturating_sub(64);
            self.pending.drain(..split_at);
        }

        responses
    }

    fn parse_escape(parser: &vt100::Parser, bytes: &[u8]) -> Option<(usize, Option<String>)> {
        if bytes.len() < 2 {
            return None;
        }
        if bytes[0] != 0x1b {
            return Some((1, None));
        }
        if bytes[1] != b'[' {
            return Some((2, None));
        }

        let mut index = 2;
        while index < bytes.len() {
            let byte = bytes[index];
            if (0x40..=0x7e).contains(&byte) {
                let params = String::from_utf8_lossy(&bytes[2..index]);
                let response = match (params.as_ref(), byte) {
                    ("6", b'n') => {
                        let (row, col) = parser.screen().cursor_position();
                        Some(format!("\u{1b}[{};{}R", row + 1, col + 1))
                    }
                    _ => None,
                };
                return Some((index + 1, response));
            }
            index += 1;
        }

        None
    }
}

fn apply_terminal_bytes(snapshot: &mut SessionSnapshot, parser: &mut vt100::Parser, chunk: &[u8]) {
    parser.process(chunk);
    snapshot
        .raw_output
        .push_str(&String::from_utf8_lossy(chunk));
    if snapshot.raw_output.len() > 24_000 {
        let split_at = snapshot.raw_output.len().saturating_sub(24_000);
        snapshot.raw_output.drain(..split_at);
    }
    sync_snapshot_from_parser(snapshot, parser);
}

fn sync_snapshot_from_parser(snapshot: &mut SessionSnapshot, parser: &vt100::Parser) {
    snapshot.rendered_screen = parser.screen().contents().to_string();
    let (row, col) = parser.screen().cursor_position();
    snapshot.cursor_row = row;
    snapshot.cursor_col = col;
    snapshot.hide_cursor = parser.screen().hide_cursor() || parser.screen().scrollback() > 0;
}

#[cfg(test)]
mod tests {
    use super::{SessionSnapshot, TerminalResponder, apply_terminal_bytes};

    #[test]
    fn terminal_parser_tracks_screen_contents() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        let mut snapshot = SessionSnapshot {
            id: "1".into(),
            title: "test".into(),
            command_preview: "echo hi".into(),
            raw_output: String::new(),
            rendered_screen: String::new(),
            cursor_row: 0,
            cursor_col: 0,
            hide_cursor: false,
            exit_status: None,
        };

        apply_terminal_bytes(&mut snapshot, &mut parser, b"hello \x1b[31mred\x1b[m");
        assert!(snapshot.raw_output.contains("hello"));
        assert!(snapshot.rendered_screen.contains("hello red"));
        assert!(!snapshot.hide_cursor);
    }

    #[test]
    fn responder_answers_cursor_position_queries() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        let mut snapshot = SessionSnapshot {
            id: "1".into(),
            title: "test".into(),
            command_preview: "echo hi".into(),
            raw_output: String::new(),
            rendered_screen: String::new(),
            cursor_row: 0,
            cursor_col: 0,
            hide_cursor: false,
            exit_status: None,
        };
        apply_terminal_bytes(&mut snapshot, &mut parser, b"hello");

        let mut responder = TerminalResponder::default();
        let responses = responder.responses(&parser, b"\x1b[6n");
        assert_eq!(responses, vec!["\x1b[1;6R".to_string()]);
    }

    #[test]
    fn responder_handles_split_cursor_position_queries() {
        let parser = vt100::Parser::new(24, 80, 0);
        let mut responder = TerminalResponder::default();

        assert!(responder.responses(&parser, b"\x1b[").is_empty());
        assert_eq!(
            responder.responses(&parser, b"6n"),
            vec!["\x1b[1;1R".to_string()]
        );
    }
}

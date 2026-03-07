use std::{
    io::{Read, Write},
    path::PathBuf,
    sync::Arc,
    thread,
};

use anyhow::{Context, Result, anyhow};
use parking_lot::Mutex;
use portable_pty::{CommandBuilder, MasterPty, PtySize, native_pty_system};
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
    pub exit_status: Option<i32>,
}

#[derive(Clone)]
pub struct TerminalSessionHandle {
    snapshot: Arc<Mutex<SessionSnapshot>>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
    child: Arc<Mutex<Box<dyn portable_pty::Child + Send + Sync>>>,
}

impl TerminalSessionHandle {
    pub fn snapshot(&self) -> SessionSnapshot {
        self.snapshot.lock().clone()
    }

    pub fn send_input(&self, input: &str) -> Result<()> {
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
        self.child
            .lock()
            .kill()
            .context("terminating PTY child process")
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
        let mut reader = pair.master.try_clone_reader()?;
        let writer = pair.master.take_writer()?;

        let preview = command.preview();
        let snapshot = Arc::new(Mutex::new(SessionSnapshot {
            id: Uuid::new_v4().to_string(),
            title: command.title,
            command_preview: preview,
            raw_output: String::new(),
            rendered_screen: String::new(),
            exit_status: None,
        }));

        let snapshot_for_reader = Arc::clone(&snapshot);
        thread::spawn(move || {
            let mut parser = vt100::Parser::new(30, 120, 2_000);
            let mut buffer = [0_u8; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(bytes_read) => {
                        let chunk = &buffer[..bytes_read];
                        let mut snapshot = snapshot_for_reader.lock();
                        apply_terminal_bytes(&mut snapshot, &mut parser, chunk);
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
            writer: Arc::new(Mutex::new(writer)),
            master: Arc::new(Mutex::new(pair.master)),
            child,
        })
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
    snapshot.rendered_screen = parser.screen().contents().to_string();
}

#[cfg(test)]
mod tests {
    use super::{SessionSnapshot, apply_terminal_bytes};

    #[test]
    fn terminal_parser_tracks_screen_contents() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        let mut snapshot = SessionSnapshot {
            id: "1".into(),
            title: "test".into(),
            command_preview: "echo hi".into(),
            raw_output: String::new(),
            rendered_screen: String::new(),
            exit_status: None,
        };

        apply_terminal_bytes(&mut snapshot, &mut parser, b"hello \x1b[31mred\x1b[m");
        assert!(snapshot.raw_output.contains("hello"));
        assert!(snapshot.rendered_screen.contains("hello red"));
    }
}

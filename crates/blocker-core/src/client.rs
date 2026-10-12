//! Thin blocking client for the daemon's Unix-socket IPC, shared by the GUI
//! and the tray. Each call opens a fresh connection, writes one request line,
//! and reads one response line.

use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use crate::ipc::{Request, Response, Status};
use crate::SOCKET_PATH;

pub fn send(req: &Request) -> Result<Status, String> {
    let mut stream = UnixStream::connect(SOCKET_PATH).map_err(|e| match e.kind() {
        // Socket exists but we may not connect: almost always a missing
        // 'blocker' group membership that is not active until re-login.
        ErrorKind::PermissionDenied => "Permission denied on the daemon's control socket.\n\
             Your user is probably not in the 'blocker' group yet — the \
             membership only takes effect after you LOG OUT and back in.\n\
             Check with:  id | grep blocker\n\
             (one-off test from a terminal:  newgrp blocker && blocker-gui)"
            .to_string(),
        // No socket / nobody listening: the daemon is not running.
        ErrorKind::NotFound | ErrorKind::ConnectionRefused => format!(
            "The blocker daemon does not seem to be running ({e}).\n\
             Start it with:  sudo systemctl start blockerd\n\
             Check it with:  systemctl status blockerd"
        ),
        _ => format!(
            "Cannot reach the blocker daemon ({e}).\n\
             Check:  systemctl status blockerd   and   id | grep blocker"
        ),
    })?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

    let mut payload = serde_json::to_string(req).map_err(|e| e.to_string())?;
    payload.push('\n');
    stream
        .write_all(payload.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;

    match serde_json::from_str::<Response>(line.trim()) {
        Ok(Response::Ok { status }) => Ok(status),
        Ok(Response::Error { message }) => Err(message),
        Err(e) => Err(format!("malformed daemon response: {e}")),
    }
}

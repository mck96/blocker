//! Thin blocking client for the daemon's Unix-socket IPC. Each call opens a
//! fresh connection, writes one request line, and reads one response line.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use blocker_core::ipc::{Request, Response, Status};
use blocker_core::SOCKET_PATH;

pub fn send(req: &Request) -> Result<Status, String> {
    let mut stream = UnixStream::connect(SOCKET_PATH).map_err(|e| {
        format!(
            "Cannot reach the blocker daemon ({e}).\n\
             Make sure it is running:  sudo systemctl start blockerd\n\
             and that your user is in the 'blocker' group."
        )
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .ok();

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

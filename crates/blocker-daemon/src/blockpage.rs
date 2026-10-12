//! Local web servers that render the motivational block page. When block-page
//! mode is on, blocked hostnames resolve to 127.0.0.1 (see `dns.rs`), so the
//! browser's request lands here. We serve HTTP on :80 and HTTPS on :443 (the
//! latter using a per-SNI certificate minted from the local CA, which the user
//! trusts). Both just answer every request with the page.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rustls::{ServerConnection, StreamOwned};

use blocker_tls::Ca;

use crate::engine::Engine;

static STARTED: AtomicBool = AtomicBool::new(false);

/// Start the block-page servers once. Idempotent: subsequent calls are no-ops.
/// Updates `engine.set_block_page_serving(..)` to reflect whether at least one
/// server is bound.
pub fn start(engine: Arc<Engine>, ca: Arc<Ca>) {
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }

    let mut any = false;

    match TcpListener::bind(("127.0.0.1", 80)) {
        Ok(listener) => {
            any = true;
            let engine = engine.clone();
            std::thread::spawn(move || http_loop(listener, engine));
            eprintln!("[blocker] block page: HTTP server on 127.0.0.1:80");
        }
        Err(e) => eprintln!("[blocker] block page: could not bind :80 ({e})"),
    }

    match TcpListener::bind(("127.0.0.1", 443)) {
        Ok(listener) => {
            any = true;
            let cfg = blocker_tls::server_config(ca);
            let engine = engine.clone();
            std::thread::spawn(move || https_loop(listener, engine, cfg));
            eprintln!("[blocker] block page: HTTPS server on 127.0.0.1:443");
        }
        Err(e) => eprintln!("[blocker] block page: could not bind :443 ({e})"),
    }

    engine.set_block_page_serving(any);
    if !any {
        // Nothing bound; make sure DNS does not point users at a dead port.
        STARTED.store(false, Ordering::SeqCst);
    }
}

fn http_loop(listener: TcpListener, engine: Arc<Engine>) {
    for stream in listener.incoming().flatten() {
        let engine = engine.clone();
        std::thread::spawn(move || {
            let _ = serve_plain(stream, &engine);
        });
    }
}

fn https_loop(listener: TcpListener, engine: Arc<Engine>, cfg: Arc<rustls::ServerConfig>) {
    for stream in listener.incoming().flatten() {
        let engine = engine.clone();
        let cfg = cfg.clone();
        std::thread::spawn(move || {
            let _ = serve_tls(stream, &engine, cfg);
        });
    }
}

fn serve_plain(mut stream: TcpStream, engine: &Engine) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let head = read_head(&mut stream)?;
    let host = host_header(&head);
    let resp =
        blocker_core::blockpage::http_response(&engine.block_title(), &engine.block_message(), &host);
    stream.write_all(&resp)?;
    stream.flush()
}

fn serve_tls(stream: TcpStream, engine: &Engine, cfg: Arc<rustls::ServerConfig>) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let conn = ServerConnection::new(cfg).map_err(std::io::Error::other)?;
    let mut tls = StreamOwned::new(conn, stream);
    let head = read_head(&mut tls)?;
    let host = host_header(&head);
    let resp =
        blocker_core::blockpage::http_response(&engine.block_title(), &engine.block_message(), &host);
    tls.write_all(&resp)?;
    tls.flush()
}

/// Read bytes up to the end of the HTTP header block (capped).
fn read_head<R: Read>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut one = [0u8; 1];
    loop {
        let n = r.read(&mut one)?;
        if n == 0 {
            break;
        }
        buf.push(one[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 16 * 1024 {
            break;
        }
    }
    Ok(buf)
}

fn host_header(head: &[u8]) -> String {
    let text = String::from_utf8_lossy(head);
    for line in text.split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                return v.trim().to_string();
            }
        }
    }
    String::new()
}

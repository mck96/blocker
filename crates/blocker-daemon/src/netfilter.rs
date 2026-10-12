//! Network-level enforcement: a transparent filter that works in every browser
//! with no per-browser setup and defeats browser "secure DNS" (DoH).
//!
//! How it works:
//! * nftables REDIRECTs locally-originated TCP to ports 80/443 to our local
//!   listener on 127.0.0.1:8081 (and [::1]:8081 for IPv6). The real destination
//!   is recovered with `SO_ORIGINAL_DST`.
//! * For port 443 we read the TLS ClientHello and extract the SNI hostname —
//!   which is visible *regardless of how DNS was resolved*, so DoH does not
//!   help the site. For port 80 we read the HTTP Host header (and path).
//! * If the hostname/URL matches the blocklist we drop the connection; otherwise
//!   we connect to the real destination and splice the bytes through untouched.
//! * Our own upstream connections carry firewall mark 1, which nftables excludes
//!   from the redirect, so there is no loop. UDP/443 (QUIC) is dropped so the
//!   browser falls back to TCP, where we can see the SNI.
//!
//! Everything fails *open*: if we cannot parse a hostname or cannot decide, the
//! connection is spliced through rather than broken.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::AsRawFd;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use socket2::{Domain, Socket, Type};

use crate::engine::Engine;

const PROXY_PORT: u16 = 8081;
const FWMARK: u32 = 1;
const SO_ORIGINAL_DST: libc::c_int = 80;

static STARTED: AtomicBool = AtomicBool::new(false);

/// Turn network-level enforcement on or off to match the config. On enable it
/// binds the listeners (once) and installs the nftables rules; on disable it
/// removes the rules (the idle listeners stay bound, harmless).
pub fn apply(engine: &Arc<Engine>, enable: bool) {
    if enable {
        ensure_listeners(engine);
        if !STARTED.load(Ordering::SeqCst) {
            eprintln!("[blocker] network filter: listener unavailable; not enabling");
            engine.set_network_filter_active(false);
            return;
        }
        match install_nft() {
            Ok(()) => {
                engine.set_network_filter_active(true);
                eprintln!("[blocker] network filter: ON (nftables redirect active)");
            }
            Err(e) => {
                engine.set_network_filter_active(false);
                eprintln!("[blocker] network filter: could not install nftables rules: {e}");
            }
        }
    } else {
        remove_nft();
        engine.set_network_filter_active(false);
    }
}

/// Remove the nftables rules (called on disable and on shutdown).
pub fn remove_nft() {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "blocker_nf"])
        .stderr(Stdio::null())
        .status();
}

fn install_nft() -> std::io::Result<()> {
    // Idempotent: drop any previous instance first.
    remove_nft();
    let script = format!(
        "table inet blocker_nf {{\n\
         \tchain out_nat {{\n\
         \t\ttype nat hook output priority -100; policy accept;\n\
         \t\tmeta mark {mark} return\n\
         \t\tip daddr 127.0.0.0/8 return\n\
         \t\tip6 daddr ::1 return\n\
         \t\tmeta l4proto tcp tcp dport {{ 80, 443 }} redirect to :{port}\n\
         \t}}\n\
         \tchain out_filter {{\n\
         \t\ttype filter hook output priority 0; policy accept;\n\
         \t\tmeta mark {mark} return\n\
         \t\tudp dport 443 drop\n\
         \t}}\n\
         }}\n",
        mark = FWMARK,
        port = PROXY_PORT,
    );
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(script.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    Ok(())
}

fn ensure_listeners(engine: &Arc<Engine>) {
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let v4 = TcpListener::bind((Ipv4Addr::LOCALHOST, PROXY_PORT));
    let v6 = TcpListener::bind((Ipv6Addr::LOCALHOST, PROXY_PORT));
    let mut any = false;
    if let Ok(l) = v4 {
        any = true;
        let engine = engine.clone();
        std::thread::spawn(move || accept_loop(l, false, engine));
    }
    if let Ok(l) = v6 {
        any = true;
        let engine = engine.clone();
        std::thread::spawn(move || accept_loop(l, true, engine));
    }
    if !any {
        STARTED.store(false, Ordering::SeqCst);
    }
}

fn accept_loop(listener: TcpListener, is_ipv6: bool, engine: Arc<Engine>) {
    for stream in listener.incoming().flatten() {
        let engine = engine.clone();
        std::thread::spawn(move || {
            let _ = handle(stream, is_ipv6, &engine);
        });
    }
}

fn handle(mut client: TcpStream, is_ipv6: bool, engine: &Engine) -> std::io::Result<()> {
    let dst = match original_dst(client.as_raw_fd(), is_ipv6) {
        Some(d) => d,
        None => return Ok(()), // cannot recover target; drop
    };
    client.set_read_timeout(Some(Duration::from_secs(10)))?;

    // Read the first chunk (ClientHello or HTTP head).
    let mut head = vec![0u8; 8192];
    let n = client.read(&mut head)?;
    if n == 0 {
        return Ok(());
    }
    head.truncate(n);

    let port = dst.port();
    let is_tls = head.first() == Some(&0x16);

    if port == 443 || is_tls {
        if let Some(host) = parse_sni(&head) {
            if engine.should_block_host_now(&host) {
                engine.log_block(&host);
                return Ok(()); // close → blocked
            }
        }
    } else {
        // Plain HTTP: we can see host AND path.
        if let Some((host, path)) = parse_http(&head) {
            if engine.should_block_url_now(&host, &path) {
                engine.log_block(&host);
                if engine.block_page_enabled() {
                    let mut w = &client;
                    let _ = w.write_all(&blocker_core::blockpage::http_response(
                        &engine.block_title(),
                        &engine.block_message(),
                        &host,
                    ));
                }
                return Ok(());
            }
        }
    }

    // Not blocked (or undecidable): splice through to the real destination.
    let upstream = match connect_marked(dst) {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    {
        let mut uw = &upstream;
        uw.write_all(&head)?;
    }
    splice(client, upstream);
    Ok(())
}

/// Recover the original destination of a redirected connection.
fn original_dst(fd: libc::c_int, is_ipv6: bool) -> Option<SocketAddr> {
    unsafe {
        if is_ipv6 {
            let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            let r = libc::getsockopt(
                fd,
                libc::SOL_IPV6,
                SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut libc::c_void,
                &mut len,
            );
            if r != 0 {
                return None;
            }
            let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
            let port = u16::from_be(addr.sin6_port);
            Some(SocketAddr::new(IpAddr::V6(ip), port))
        } else {
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let r = libc::getsockopt(
                fd,
                libc::SOL_IP,
                SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut libc::c_void,
                &mut len,
            );
            if r != 0 {
                return None;
            }
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
    }
}

/// Connect to the real destination, marking the socket so nftables does not
/// redirect our own outgoing connection (loop avoidance).
fn connect_marked(dst: SocketAddr) -> std::io::Result<TcpStream> {
    let domain = match dst {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let sock = Socket::new(domain, Type::STREAM, None)?;
    sock.set_mark(FWMARK)?;
    sock.connect_timeout(&dst.into(), Duration::from_secs(10))?;
    let stream: TcpStream = sock.into();
    stream.set_nodelay(true).ok();
    Ok(stream)
}

/// Bidirectional byte pump between the client and the upstream.
fn splice(client: TcpStream, upstream: TcpStream) {
    let (mut c_rd, mut c_wr) = (client.try_clone().ok(), client);
    let (mut u_rd, mut u_wr) = (upstream.try_clone().ok(), upstream);
    let t = std::thread::spawn(move || {
        if let Some(c) = c_rd.as_mut() {
            let _ = std::io::copy(c, &mut u_wr);
            let _ = u_wr.shutdown(std::net::Shutdown::Write);
        }
    });
    if let Some(u) = u_rd.as_mut() {
        let _ = std::io::copy(u, &mut c_wr);
        let _ = c_wr.shutdown(std::net::Shutdown::Write);
    }
    let _ = t.join();
}

/// Extract the host and path from an HTTP/1.x request head.
fn parse_http(head: &[u8]) -> Option<(String, String)> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let _method = parts.next()?;
    let target = parts.next()?;
    let path = if target.starts_with('/') {
        target.to_string()
    } else if let Some(i) = target.find("://").map(|i| i + 3).and_then(|s| target[s..].find('/').map(|j| s + j)) {
        target[i..].to_string()
    } else {
        "/".to_string()
    };
    let mut host = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                let h = v.trim();
                host = Some(h.rsplit_once(':').map(|(a, _)| a).unwrap_or(h).to_string());
                break;
            }
        }
    }
    Some((host?, path))
}

/// Parse the SNI server name from a TLS ClientHello record.
pub fn parse_sni(buf: &[u8]) -> Option<String> {
    // TLS record header: type(1)=0x16, version(2), length(2)
    if buf.len() < 43 || buf[0] != 0x16 {
        return None;
    }
    let mut p = 5usize; // start of handshake
    if buf.get(p)? != &0x01 {
        return None; // not a ClientHello
    }
    p += 4; // handshake type(1) + length(3)
    p += 2; // client version
    p += 32; // random
    // session id
    let sid_len = *buf.get(p)? as usize;
    p += 1 + sid_len;
    // cipher suites
    let cs_len = u16::from_be_bytes([*buf.get(p)?, *buf.get(p + 1)?]) as usize;
    p += 2 + cs_len;
    // compression methods
    let cm_len = *buf.get(p)? as usize;
    p += 1 + cm_len;
    // extensions
    if p + 2 > buf.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
    p += 2;
    let ext_end = (p + ext_total).min(buf.len());
    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[p], buf[p + 1]]);
        let ext_len = u16::from_be_bytes([buf[p + 2], buf[p + 3]]) as usize;
        p += 4;
        if ext_type == 0x0000 {
            // server_name extension
            // server_name_list length (2), then entries: type(1)=0 host, len(2), name
            if p + 5 > buf.len() {
                return None;
            }
            let name_type = buf[p + 2];
            if name_type != 0 {
                return None;
            }
            let name_len = u16::from_be_bytes([buf[p + 3], buf[p + 4]]) as usize;
            let start = p + 5;
            if start + name_len > buf.len() {
                return None;
            }
            let name = &buf[start..start + name_len];
            return std::str::from_utf8(name).ok().map(|s| s.to_ascii_lowercase());
        }
        p += ext_len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sni_from_clienthello() {
        // A minimal but well-formed ClientHello advertising SNI "example.com".
        let name = b"example.com";
        let mut ch = Vec::new();
        // Handshake body first (we'll prefix headers after computing lengths).
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client version TLS1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites (len 2)
        body.extend_from_slice(&[0x01, 0x00]); // compression (len 1, null)
        // extensions
        let mut exts = Vec::new();
        // SNI extension
        let mut sni = Vec::new();
        sni.extend_from_slice(&[0x00, 0x00]); // type server_name
        let server_name_list = {
            let mut l = Vec::new();
            l.push(0u8); // name type host
            l.extend_from_slice(&(name.len() as u16).to_be_bytes());
            l.extend_from_slice(name);
            l
        };
        let list_len = (server_name_list.len() as u16).to_be_bytes();
        let ext_data_len = ((server_name_list.len() + 2) as u16).to_be_bytes();
        sni.extend_from_slice(&ext_data_len);
        sni.extend_from_slice(&list_len);
        sni.extend_from_slice(&server_name_list);
        exts.extend_from_slice(&sni);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        // Handshake header: type 0x01 + 3-byte length
        let mut hs = vec![0x01];
        let blen = body.len() as u32;
        hs.extend_from_slice(&blen.to_be_bytes()[1..]); // 3 bytes
        hs.extend_from_slice(&body);

        // Record header: 0x16, version, 2-byte length
        ch.push(0x16);
        ch.extend_from_slice(&[0x03, 0x01]);
        ch.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        ch.extend_from_slice(&hs);

        assert_eq!(parse_sni(&ch).as_deref(), Some("example.com"));
    }

    #[test]
    fn http_host_and_path() {
        let req = b"GET /elonmusk/status HTTP/1.1\r\nHost: x.com\r\nAccept: */*\r\n\r\n";
        let (h, p) = parse_http(req).unwrap();
        assert_eq!(h, "x.com");
        assert_eq!(p, "/elonmusk/status");
    }

    #[test]
    fn non_tls_non_http_is_none() {
        assert!(parse_sni(b"not tls").is_none());
    }
}

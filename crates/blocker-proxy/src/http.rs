//! Tiny HTTP/1.1 helpers used by the proxy: reading request heads, pulling out
//! the bits we need, rebuilding requests in origin form, and copying bodies.

use std::io::{Read, Write};
use std::net::TcpStream;

const MAX_HEAD: usize = 64 * 1024;

/// Read bytes until the end of the header block (`\r\n\r\n`). Returns the raw
/// head bytes (including the terminator) plus any extra bytes already read that
/// belong to the body.
pub fn read_head<R: Read>(r: &mut R) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut one = [0u8; 1];
    loop {
        let n = r.read(&mut one)?;
        if n == 0 {
            break; // EOF before full head
        }
        buf.push(one[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > MAX_HEAD {
            break;
        }
    }
    Ok((buf, Vec::new()))
}

pub struct RequestLine {
    pub method: String,
    pub target: String,
    pub version: String,
}

pub fn parse_request_line(head: &[u8]) -> Option<RequestLine> {
    let end = find(head, b"\r\n").unwrap_or(head.len());
    let line = std::str::from_utf8(&head[..end]).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();
    Some(RequestLine {
        method,
        target,
        version,
    })
}

/// Case-insensitive header lookup over a raw head block.
pub fn header_value(head: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(head);
    for line in text.split("\r\n").skip(1) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

pub fn content_length(head: &[u8]) -> usize {
    header_value(head, "Content-Length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0)
}

/// Parse an absolute proxy URI like `http://host:port/path?x=1`.
pub fn parse_absolute_uri(target: &str) -> Option<(String, u16, String)> {
    let rest = target.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = split_host_port(authority, 80);
    Some((host, port, path.to_string()))
}

/// Split `host:port` (or bare `host`) into parts, applying a default port.
pub fn split_host_port(authority: &str, default: u16) -> (String, u16) {
    // Strip any userinfo.
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(stripped) = authority.strip_prefix('[') {
        // IPv6 literal [::1]:443
        if let Some(end) = stripped.find(']') {
            let host = &stripped[..end];
            let port = stripped[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default);
            return (host.to_string(), port);
        }
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            (h.to_string(), p.parse().unwrap_or(default))
        }
        _ => (authority.to_string(), default),
    }
}

/// Extract just the path portion from a request target that may be origin-form
/// (`/a/b`) or absolute-form (`http://h/a/b`).
pub fn target_path(target: &str) -> String {
    if target.starts_with('/') {
        return target.to_string();
    }
    if let Some((_, _, path)) = parse_absolute_uri(target) {
        return path;
    }
    "/".to_string()
}

/// Rebuild a request in origin form with `Connection: close`, suitable for
/// sending straight to an origin server. Preserves all headers except hop-by-
/// hop / proxy ones and any existing Connection header.
pub fn rebuild_origin_request(head: &[u8], method: &str, path: &str, version: &str) -> Vec<u8> {
    let text = String::from_utf8_lossy(head);
    let mut out = format!("{method} {path} {version}\r\n");
    for line in text.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        let name = line.split(':').next().unwrap_or("").trim();
        if name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("keep-alive")
            || name.eq_ignore_ascii_case("te")
            || name.eq_ignore_ascii_case("upgrade")
        {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    out.into_bytes()
}

/// The page shown when a request is blocked.
pub fn block_response() -> Vec<u8> {
    let body = "<!doctype html><html><head><meta charset=utf-8>\
        <title>Blocked</title></head>\
        <body style=\"font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;color:#333\">\
        <h1>\u{1f6e1}\u{fe0f} Blocked</h1>\
        <p>This page is blocked by <strong>Blocker</strong>.</p>\
        <p style=\"color:#888\">Open the Blocker app to manage your blocklist.</p>\
        </body></html>";
    format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

/// Copy everything from `src` to `dst` until EOF.
pub fn pump_to_eof<R: Read, W: Write>(src: &mut R, dst: &mut W) -> std::io::Result<()> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n])?;
    }
    dst.flush()?;
    Ok(())
}

/// Blindly relay bytes both ways between two TCP streams (used for CONNECT
/// tunnels to hosts we don't intercept).
pub fn blind_tunnel(client: TcpStream, upstream: TcpStream) {
    let (mut cr, mut cw) = (
        client.try_clone().ok(),
        client,
    );
    let (mut ur, mut uw) = (
        upstream.try_clone().ok(),
        upstream,
    );
    let t = std::thread::spawn(move || {
        if let Some(cr) = cr.as_mut() {
            let _ = std::io::copy(cr, &mut uw);
            let _ = uw.shutdown(std::net::Shutdown::Write);
        }
    });
    if let Some(ur) = ur.as_mut() {
        let _ = std::io::copy(ur, &mut cw);
        let _ = cw.shutdown(std::net::Shutdown::Write);
    }
    let _ = t.join();
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_abs() {
        let (h, p, path) = parse_absolute_uri("http://x.com/elonmusk/status").unwrap();
        assert_eq!(h, "x.com");
        assert_eq!(p, 80);
        assert_eq!(path, "/elonmusk/status");
    }

    #[test]
    fn host_port_split() {
        assert_eq!(split_host_port("x.com:443", 443), ("x.com".into(), 443));
        assert_eq!(split_host_port("x.com", 443), ("x.com".into(), 443));
        assert_eq!(split_host_port("[::1]:8443", 443), ("::1".into(), 8443));
    }

    #[test]
    fn req_line() {
        let r = parse_request_line(b"GET /a/b HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.target, "/a/b");
    }

    #[test]
    fn rebuild_drops_proxy_headers() {
        let head = b"GET http://x/a HTTP/1.1\r\nHost: x\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n";
        let out = rebuild_origin_request(head, "GET", "/a", "HTTP/1.1");
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("GET /a HTTP/1.1\r\n"));
        assert!(s.contains("Host: x\r\n"));
        assert!(s.contains("Accept: */*\r\n"));
        assert!(!s.to_lowercase().contains("proxy-connection"));
        assert!(s.contains("Connection: close\r\n"));
    }

    #[test]
    fn target_path_forms() {
        assert_eq!(target_path("/a/b"), "/a/b");
        assert_eq!(target_path("http://x.com/a/b"), "/a/b");
    }
}

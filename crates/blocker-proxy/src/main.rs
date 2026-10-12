//! blocker-proxy — optional local filtering proxy for *path-level* rules.
//!
//! Domains and subdomains are blocked by the DNS daemon and need nothing here.
//! This proxy exists only to enforce rules that include a path (e.g.
//! `x.com/elonmusk/*`), which is impossible at the DNS layer. For HTTPS hosts
//! that have path rules it terminates TLS using a locally-generated CA (which
//! the user installs into their trust store); for every other host it is a
//! transparent pass-through.
//!
//! Configure your system/browser to use this as the HTTP and HTTPS proxy
//! (default 127.0.0.1:8080). See the README.

mod filter;
mod http;

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConnection, ServerConnection, StreamOwned};
use rustls_pki_types::ServerName;

use blocker_tls::{self as tls, Ca};

use crate::filter::Filter;
use crate::http::*;

struct Ctx {
    filter: Arc<Filter>,
    server_cfg: Arc<rustls::ServerConfig>,
    client_cfg: Arc<rustls::ClientConfig>,
}

fn main() {
    let mut listen = "127.0.0.1:8080".to_string();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--listen" | "-l" => {
                if let Some(v) = args.next() {
                    listen = v;
                }
            }
            "--ca-path" => {
                println!("{}", tls::CA_CERT_PATH);
                return;
            }
            "-h" | "--help" => {
                print_help();
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_help();
                std::process::exit(2);
            }
        }
    }

    tls::install_crypto_provider();

    let ca = match Ca::load_or_create() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("[proxy] could not initialise local CA: {e}");
            std::process::exit(1);
        }
    };

    let ctx = Arc::new(Ctx {
        filter: Arc::new(Filter::new()),
        server_cfg: tls::server_config(ca.clone()),
        client_cfg: tls::client_config(),
    });

    let listener = match TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[proxy] cannot bind {listen}: {e}");
            std::process::exit(1);
        }
    };

    eprintln!("[proxy] listening on {listen}");
    eprintln!("[proxy] CA certificate: {}", tls::CA_CERT_PATH);
    eprintln!(
        "[proxy] To enable HTTPS path blocking, trust that CA and point your \
         system/browser HTTP+HTTPS proxy at {listen}."
    );

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            if let Err(e) = handle(stream, &ctx) {
                let _ = e; // best-effort; connection errors are routine
            }
        });
    }
}

fn print_help() {
    println!(
        "blocker-proxy — filtering proxy for path-level block rules\n\n\
         USAGE:\n  blocker-proxy [--listen ADDR]\n\n\
         OPTIONS:\n  -l, --listen ADDR   Address to listen on (default 127.0.0.1:8080)\n  \
             --ca-path          Print the path to the CA certificate and exit\n  \
         -h, --help          Show this help"
    );
}

/// Build the motivational block-page HTTP response using the current config.
fn block_bytes(ctx: &Ctx, host: &str) -> Vec<u8> {
    blocker_core::blockpage::http_response(
        &ctx.filter.block_title(),
        &ctx.filter.block_message(),
        host,
    )
}

fn handle(mut client: TcpStream, ctx: &Ctx) -> std::io::Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(30)))?;
    client.set_write_timeout(Some(Duration::from_secs(30)))?;

    let (head, _) = read_head(&mut client)?;
    if head.is_empty() {
        return Ok(());
    }
    let rl = match parse_request_line(&head) {
        Some(r) => r,
        None => return Ok(()),
    };

    if rl.method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(client, &rl.target, ctx)
    } else {
        handle_http(client, rl, head, ctx)
    }
}

/// Plain-HTTP proxy request (absolute-form target).
fn handle_http(mut client: TcpStream, rl: RequestLine, head: Vec<u8>, ctx: &Ctx) -> std::io::Result<()> {
    let (host, port, path) = match parse_absolute_uri(&rl.target) {
        Some(v) => v,
        None => {
            // Not something we proxy (e.g. origin-form sent directly to us).
            let _ = client.write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
            return Ok(());
        }
    };

    let active = ctx.filter.active();
    if active && ctx.filter.url_blocked(&host, &path) {
        client.write_all(&block_bytes(ctx, &host))?;
        return Ok(());
    }

    // Forward to the origin server.
    let mut upstream = TcpStream::connect((host.as_str(), port))?;
    upstream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let out = rebuild_origin_request(&head, &rl.method, &path, &rl.version);
    upstream.write_all(&out)?;
    forward_body(&mut client, &mut upstream, &head)?;
    pump_to_eof(&mut upstream, &mut client)?;
    Ok(())
}

fn handle_connect(mut client: TcpStream, target: &str, ctx: &Ctx) -> std::io::Result<()> {
    let (host, port) = split_host_port(target, 443);
    let active = ctx.filter.active();

    // Intercept if the host is fully blocked (show the page over TLS) or has a
    // path rule to evaluate. Everything else is a transparent tunnel.
    if active && (ctx.filter.host_fully_blocked(&host) || ctx.filter.host_has_path_rule(&host)) {
        return mitm_connect(client, &host, port, ctx);
    }

    // Transparent tunnel.
    let upstream = match TcpStream::connect((host.as_str(), port)) {
        Ok(s) => s,
        Err(_) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return Ok(());
        }
    };
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
    // No timeout on long-lived tunnels.
    let _ = client.set_read_timeout(None);
    let _ = upstream.set_read_timeout(None);
    blind_tunnel(client, upstream);
    Ok(())
}

/// Intercept TLS for a host that has path rules, filter the request, and
/// re-originate to the real server.
fn mitm_connect(mut client: TcpStream, host: &str, port: u16, ctx: &Ctx) -> std::io::Result<()> {
    client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;

    // Terminate TLS with the client using a minted cert for `host`.
    let server_conn = match ServerConnection::new(ctx.server_cfg.clone()) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };
    let mut client_tls = StreamOwned::new(server_conn, client);

    let (head, _) = match read_head(&mut client_tls) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    if head.is_empty() {
        return Ok(());
    }
    let rl = match parse_request_line(&head) {
        Some(r) => r,
        None => return Ok(()),
    };
    let path = target_path(&rl.target);

    if ctx.filter.host_fully_blocked(host) || ctx.filter.url_blocked(host, &path) {
        let _ = client_tls.write_all(&block_bytes(ctx, host));
        let _ = client_tls.flush();
        return Ok(());
    }

    // Allowed: open a fresh TLS connection to the real server and relay.
    let server_name = match ServerName::try_from(host.to_string()) {
        Ok(n) => n,
        Err(_) => return Ok(()),
    };
    let upstream_tcp = match TcpStream::connect((host, port)) {
        Ok(s) => s,
        Err(_) => {
            let _ = client_tls.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            return Ok(());
        }
    };
    let client_conn = match ClientConnection::new(ctx.client_cfg.clone(), server_name) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };
    let mut upstream_tls = StreamOwned::new(client_conn, upstream_tcp);

    let out = rebuild_origin_request(&head, &rl.method, &path, &rl.version);
    upstream_tls.write_all(&out)?;
    forward_body(&mut client_tls, &mut upstream_tls, &head)?;
    pump_to_eof(&mut upstream_tls, &mut client_tls)?;
    Ok(())
}

/// Forward a request body (if any) from client to upstream, based on
/// Content-Length. Chunked bodies are rare for navigations and are relayed
/// best-effort by the subsequent EOF pump on the client side being skipped.
fn forward_body<R: std::io::Read, W: Write>(
    client: &mut R,
    upstream: &mut W,
    head: &[u8],
) -> std::io::Result<()> {
    let len = content_length(head);
    if len == 0 {
        return Ok(());
    }
    let mut remaining = len;
    let mut buf = [0u8; 16 * 1024];
    while remaining > 0 {
        let want = remaining.min(buf.len());
        let n = client.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        upstream.write_all(&buf[..n])?;
        remaining -= n;
    }
    upstream.flush()?;
    Ok(())
}

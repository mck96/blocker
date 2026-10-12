//! blockerd — the privileged Blocker daemon.
//!
//! Runs as root (via systemd). It owns the local DNS sinkhole, the managed
//! /etc/hosts block, and /etc/resolv.conf, and exposes a small Unix-socket IPC
//! surface for the GUI. On shutdown it reverses every system change.

mod blockpage;
mod dns;
mod engine;
mod netfilter;
mod system;

use std::ffi::CString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use blocker_core::config::Config;
use blocker_core::ipc::{Request, Response};
use blocker_core::{CONFIG_PATH, SOCKET_PATH};

use crate::engine::Engine;

static TERMINATE: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_sig: libc::c_int) {
    // Async-signal-safe: only touch an atomic. Real cleanup happens in main.
    TERMINATE.store(true, Ordering::SeqCst);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "status") {
        return cli_status();
    }
    let verbose = args.iter().any(|a| a == "-v" || a == "--verbose");

    if unsafe { libc::geteuid() } != 0 {
        eprintln!(
            "blockerd must run as root (it manages DNS, /etc/hosts and \
             /etc/resolv.conf).\nStart it via: sudo systemctl start blockerd"
        );
        std::process::exit(1);
    }

    if let Err(e) = system::ensure_state_dir() {
        eprintln!("[blocker] cannot create state dir: {e}");
        std::process::exit(1);
    }

    let config = load_or_init_config();

    // Detect real upstreams *before* we touch resolv.conf.
    let mut upstreams = if config.upstream_dns.is_empty() {
        system::detect_upstreams()
    } else {
        config.upstream_dns.clone()
    };
    // Always keep a public resolver as a fallback so forwarding still works if
    // the detected (often LAN) resolver becomes unreachable after a network
    // change. forward() tries upstreams in order, so detected ones win.
    for fallback in ["1.1.1.1:53", "9.9.9.9:53"] {
        if !upstreams.iter().any(|u| u == fallback) {
            upstreams.push(fallback.to_string());
        }
    }
    eprintln!("[blocker] upstream resolvers: {}", upstreams.join(", "));

    let engine = Arc::new(Engine::new(config, upstreams, verbose));

    // Start the DNS sinkhole. Only take over resolv.conf if it bound cleanly,
    // otherwise we would break all name resolution on the machine.
    match dns::serve(engine.clone()) {
        Ok(()) => {
            eprintln!("[blocker] DNS sinkhole listening on 127.0.0.1:53");
            if let Err(e) = system::install_resolver() {
                eprintln!("[blocker] warning: could not update resolv.conf: {e}");
            } else {
                eprintln!("[blocker] /etc/resolv.conf now points at the sinkhole");
            }
        }
        Err(e) => {
            eprintln!(
                "[blocker] warning: could not bind 127.0.0.1:53 ({e}). \
                 Running in hosts-file-only mode; leaving resolv.conf untouched."
            );
        }
    }

    // Initialise the local CA (shared with the proxy) so the HTTPS block page
    // can present trusted certificates. Creating it is harmless even when the
    // block page is off; the user trusts it when they opt in.
    blocker_tls::install_crypto_provider();
    let ca = match blocker_tls::Ca::load_or_create() {
        Ok(c) => Some(Arc::new(c)),
        Err(e) => {
            eprintln!("[blocker] warning: could not init local CA ({e}); HTTPS block page disabled");
            None
        }
    };

    install_signal_handlers();
    // Start the block-page servers if enabled now (can also be started later
    // via SetConfig when the user turns the page on).
    if engine.block_page_enabled() {
        if let Some(ca) = &ca {
            blockpage::start(engine.clone(), ca.clone());
        }
    }
    if engine.network_filter_enabled() {
        netfilter::apply(&engine, true);
    }
    sync_side_effects(&engine);
    start_ticker(engine.clone());

    let listener = match setup_socket() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[blocker] cannot create control socket: {e}");
            cleanup(&engine);
            std::process::exit(1);
        }
    };
    eprintln!("[blocker] control socket ready at {SOCKET_PATH}");

    serve_ipc(listener, engine.clone(), ca);

    eprintln!("[blocker] shutting down, reverting system changes…");
    cleanup(&engine);
}

fn load_or_init_config() -> Config {
    match fs::read_to_string(CONFIG_PATH) {
        Ok(s) => match Config::from_json(&s) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[blocker] config parse error ({e}); using defaults");
                Config::default()
            }
        },
        Err(_) => {
            let c = Config::default();
            persist_config(&c);
            c
        }
    }
}

fn persist_config(c: &Config) {
    if let Err(e) = fs::write(CONFIG_PATH, c.to_json()) {
        eprintln!("[blocker] could not persist config: {e}");
    } else {
        let _ = fs::set_permissions(CONFIG_PATH, fs::Permissions::from_mode(0o644));
    }
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGTERM, handle_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, handle_signal as *const () as libc::sighandler_t);
    }
}

/// Make /etc/hosts reflect the current active state.
fn sync_side_effects(engine: &Engine) {
    let entries = if engine.is_active() {
        engine.hosts_entries()
    } else {
        Vec::new()
    };
    if let Err(e) = system::apply_hosts(&entries) {
        eprintln!("[blocker] warning: could not update /etc/hosts: {e}");
    }
}

fn start_ticker(engine: Arc<Engine>) {
    std::thread::spawn(move || {
        let mut last_persisted = engine.config_snapshot().to_json();
        let mut ticks: u64 = 0;
        loop {
            std::thread::sleep(Duration::from_secs(5));
            if TERMINATE.load(Ordering::SeqCst) {
                break;
            }
            if engine.refresh_active().is_some() {
                sync_side_effects(&engine);
            }
            // Persist if the config drifted (e.g. a session expired).
            let snap = engine.config_snapshot().to_json();
            if snap != last_persisted {
                persist_config(&engine.config_snapshot());
                last_persisted = snap;
            }
            // VPN / network coexistence (every ~10s).
            ticks += 1;
            if ticks.is_multiple_of(2) {
                maintain_resolver(&engine);
            }
        }
    });
}

/// Keep coexisting with VPNs / network managers:
///
/// * In auto-detect mode (`upstream_dns` empty) adopt the current real
///   resolvers — e.g. a VPN's DNS — so non-blocked queries flow through them
///   and VPN-internal names keep resolving with no DNS leak.
/// * Always re-assert our `/etc/resolv.conf` pointer if something external
///   (a VPN client, NetworkManager, resolvconf) replaced it, otherwise our
///   interception would be silently bypassed.
fn maintain_resolver(engine: &Engine) {
    // Only meddle with resolv.conf if we actually took it over (DNS bound).
    if !engine.dns_listening() {
        return;
    }
    // Detect current real resolvers FIRST (a VPN may have just written its DNS
    // into resolv.conf), then re-assert our pointer so we don't clobber it
    // before harvesting.
    if engine.config_snapshot().upstream_dns.is_empty() {
        let mut detected = system::detect_upstreams();
        for fallback in ["1.1.1.1:53", "9.9.9.9:53"] {
            if !detected.iter().any(|u| u == fallback) {
                detected.push(fallback.to_string());
            }
        }
        if engine.set_upstreams(detected.clone()) {
            eprintln!("[blocker] upstream resolvers updated: {}", detected.join(", "));
        }
    }
    if system::reassert_resolver_if_hijacked() {
        eprintln!("[blocker] resolv.conf was changed externally; re-asserted sinkhole pointer");
    }
}

fn setup_socket() -> std::io::Result<UnixListener> {
    let dir = std::path::Path::new(SOCKET_PATH).parent().unwrap();
    fs::create_dir_all(dir)?;
    let _ = fs::remove_file(SOCKET_PATH);
    let listener = UnixListener::bind(SOCKET_PATH)?;
    listener.set_nonblocking(true)?;

    // Grant access to members of the `blocker` group if it exists; otherwise
    // fall back to world-accessible (with a warning) so the GUI still works.
    match group_gid("blocker") {
        Some(gid) => {
            let c = CString::new(SOCKET_PATH).unwrap();
            unsafe {
                libc::chown(c.as_ptr(), 0, gid);
            }
            fs::set_permissions(SOCKET_PATH, fs::Permissions::from_mode(0o660))?;
        }
        None => {
            eprintln!(
                "[blocker] note: group 'blocker' not found; control socket is \
                 world-accessible. Run the installer to create the group."
            );
            fs::set_permissions(SOCKET_PATH, fs::Permissions::from_mode(0o666))?;
        }
    }
    Ok(listener)
}

fn group_gid(name: &str) -> Option<u32> {
    let cname = CString::new(name).ok()?;
    unsafe {
        let grp = libc::getgrnam(cname.as_ptr());
        if grp.is_null() {
            None
        } else {
            Some((*grp).gr_gid)
        }
    }
}

/// Accept-and-dispatch loop. Non-blocking + poll so SIGTERM is observed.
fn serve_ipc(listener: UnixListener, engine: Arc<Engine>, ca: Option<Arc<blocker_tls::Ca>>) {
    use std::os::unix::io::AsRawFd;
    let fd = listener.as_raw_fd();
    loop {
        if TERMINATE.load(Ordering::SeqCst) {
            break;
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let r = unsafe { libc::poll(&mut pfd, 1, 1000) };
        if r <= 0 {
            continue;
        }
        match listener.accept() {
            Ok((stream, _addr)) => {
                let engine = engine.clone();
                let ca = ca.clone();
                std::thread::spawn(move || handle_client(stream, engine, ca));
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(_) => continue,
        }
    }
}

fn handle_client(stream: UnixStream, engine: Arc<Engine>, ca: Option<Arc<blocker_tls::Ca>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
        return;
    }
    let req: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            write_response(stream, &Response::err(format!("bad request: {e}")));
            return;
        }
    };
    let resp = dispatch(req, &engine, &ca);
    write_response(stream, &resp);
}

fn dispatch(req: Request, engine: &Arc<Engine>, ca: &Option<Arc<blocker_tls::Ca>>) -> Response {
    match req {
        Request::Status => Response::Ok {
            status: engine.status(),
        },
        Request::SetConfig { config } => {
            engine.replace_config(config);
            persist_config(&engine.config_snapshot());
            // If the user just turned the block page on, start its servers.
            if engine.block_page_enabled() {
                if let Some(ca) = ca {
                    blockpage::start(engine.clone(), ca.clone());
                }
            }
            // Apply network-filter enable/disable to match the new config.
            netfilter::apply(engine, engine.network_filter_enabled());
            sync_side_effects(engine);
            Response::Ok {
                status: engine.status(),
            }
        }
        Request::SetEnforcement { enforcement } => {
            engine.set_enforcement(enforcement);
            persist_config(&engine.config_snapshot());
            sync_side_effects(engine);
            Response::Ok {
                status: engine.status(),
            }
        }
        Request::StartSession { minutes, lock } => {
            if minutes == 0 {
                return Response::err("session length must be at least 1 minute");
            }
            let c = engine.start_session(minutes, lock);
            persist_config(&c);
            sync_side_effects(engine);
            Response::Ok {
                status: engine.status(),
            }
        }
        Request::StopSession => match engine.stop_session() {
            Ok(c) => {
                persist_config(&c);
                sync_side_effects(engine);
                Response::Ok {
                    status: engine.status(),
                }
            }
            Err(e) => Response::err(e),
        },
        Request::TakeBreak => match engine.take_break() {
            Ok(c) => {
                persist_config(&c);
                sync_side_effects(engine);
                Response::Ok {
                    status: engine.status(),
                }
            }
            Err(e) => Response::err(e),
        },
        Request::Reload => {
            let c = load_or_init_config();
            engine.replace_config(c);
            sync_side_effects(engine);
            Response::Ok {
                status: engine.status(),
            }
        }
    }
}

fn write_response(mut stream: UnixStream, resp: &Response) {
    if let Ok(mut s) = serde_json::to_string(resp) {
        s.push('\n');
        let _ = stream.write_all(s.as_bytes());
        let _ = stream.flush();
    }
}

fn cleanup(engine: &Engine) {
    netfilter::remove_nft();
    let _ = system::apply_hosts(&[]);
    if let Err(e) = system::uninstall_resolver() {
        eprintln!("[blocker] warning: could not restore resolv.conf: {e}");
    }
    let _ = fs::remove_file(SOCKET_PATH);
    let _ = engine; // kept for symmetry / future use
}

/// `blockerd status` — a tiny client for debugging without the GUI.
fn cli_status() {
    match UnixStream::connect(SOCKET_PATH) {
        Ok(mut stream) => {
            let _ = stream.write_all(b"{\"cmd\":\"status\"}\n");
            let _ = stream.flush();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() {
                match serde_json::from_str::<Response>(line.trim()) {
                    Ok(Response::Ok { status }) => {
                        println!("blocking_active : {}", status.blocking_active);
                        println!("reason          : {}", status.reason);
                        println!("dns_listening   : {}", status.dns_listening);
                        println!("host rules      : {}", status.host_rule_count);
                        println!("path rules      : {}", status.path_rule_count);
                        println!("upstreams       : {}", status.upstreams.join(", "));
                        if let Some(rem) = status.session_remaining_secs {
                            println!("session left    : {}s", rem);
                        }
                    }
                    Ok(Response::Error { message }) => eprintln!("error: {message}"),
                    Err(e) => eprintln!("could not parse daemon response: {e}"),
                }
            }
        }
        Err(e) => {
            eprintln!("could not connect to {SOCKET_PATH}: {e}");
            eprintln!("is blockerd running? try: sudo systemctl start blockerd");
            std::process::exit(1);
        }
    }
}

//! A small authoritative-for-blocked, forwarding-for-everything-else DNS
//! server. It parses just enough of each query to extract the question name
//! and type, decides via the shared engine whether to sinkhole it, and either
//! synthesises a `0.0.0.0` / `::` answer or relays the query to an upstream
//! resolver.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use crate::engine::Engine;

const MAX_UDP: usize = 1232; // conservative EDNS-free-ish buffer; we read more.

/// Spawn the UDP and TCP listeners on 127.0.0.1:53. Returns an error if the
/// port cannot be bound (e.g. another resolver holds it).
pub fn serve(engine: Arc<Engine>) -> std::io::Result<()> {
    let udp = UdpSocket::bind(("127.0.0.1", 53))?;
    let tcp = TcpListener::bind(("127.0.0.1", 53))?;
    engine.set_dns_listening(true);

    {
        let engine = engine.clone();
        let udp = udp.try_clone()?;
        std::thread::spawn(move || udp_loop(udp, engine));
    }
    {
        let engine = engine.clone();
        std::thread::spawn(move || tcp_loop(tcp, engine));
    }
    Ok(())
}

fn udp_loop(sock: UdpSocket, engine: Arc<Engine>) {
    let mut buf = [0u8; 4096];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let query = buf[..n].to_vec();
        let engine = engine.clone();
        let sock = match sock.try_clone() {
            Ok(s) => s,
            Err(_) => continue,
        };
        std::thread::spawn(move || {
            let resp = handle_query(&query, &engine, false);
            if let Some(mut resp) = resp {
                // UDP responses that would exceed the client buffer should set
                // TC; we keep it simple and truncate rarely-large answers.
                if resp.len() > MAX_UDP + 2048 {
                    resp.truncate(MAX_UDP);
                }
                let _ = sock.send_to(&resp, peer);
            }
        });
    }
}

fn tcp_loop(listener: TcpListener, engine: Arc<Engine>) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let engine = engine.clone();
        std::thread::spawn(move || handle_tcp(stream, engine));
    }
}

fn handle_tcp(mut stream: TcpStream, engine: Arc<Engine>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut len_buf = [0u8; 2];
    if stream.read_exact(&mut len_buf).is_err() {
        return;
    }
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 65535 {
        return;
    }
    let mut msg = vec![0u8; len];
    if stream.read_exact(&mut msg).is_err() {
        return;
    }
    if let Some(resp) = handle_query(&msg, &engine, true) {
        let rlen = (resp.len() as u16).to_be_bytes();
        let _ = stream.write_all(&rlen);
        let _ = stream.write_all(&resp);
    }
}

/// Decide and build a response for a single query message. `tcp` selects the
/// transport used for forwarding upstream.
fn handle_query(query: &[u8], engine: &Engine, tcp: bool) -> Option<Vec<u8>> {
    let parsed = parse_question(query);
    match parsed {
        Some(q) => {
            if engine.should_block_host(&q.name) {
                engine.log_block(&q.name);
                Some(build_block_response(query, &q, engine.use_block_page()))
            } else {
                forward(query, engine, tcp).or_else(|| Some(build_servfail(query)))
            }
        }
        // Unparseable / multi-question: just forward it untouched.
        None => forward(query, engine, tcp).or_else(|| Some(build_servfail(query))),
    }
}

struct Question {
    name: String,
    qtype: u16,
    /// Byte length of the question section (name + qtype + qclass).
    section_len: usize,
}

/// Parse the single question from a standard query. Returns `None` if the
/// header is malformed or QDCOUNT != 1.
fn parse_question(buf: &[u8]) -> Option<Question> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount != 1 {
        return None;
    }
    let mut pos = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        // Compression pointers never appear in a question name.
        if len & 0xC0 != 0 {
            return None;
        }
        if pos + len > buf.len() {
            return None;
        }
        let label = &buf[pos..pos + len];
        pos += len;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
    }
    if pos + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 4; // qtype + qclass
    let name = labels.join(".");
    Some(Question {
        name,
        qtype,
        section_len: pos - 12,
    })
}

/// Build a response that sinkholes the query. When `to_local` is true the
/// answer points at 127.0.0.1 / ::1 (so the local block-page servers can show
/// a page); otherwise 0.0.0.0 / :: for a silent, instant failure. Non-address
/// queries get NODATA (NOERROR, no answers).
fn build_block_response(query: &[u8], q: &Question, to_local: bool) -> Vec<u8> {
    let mut resp = Vec::with_capacity(query.len() + 16);
    // Header.
    resp.extend_from_slice(&query[0..2]); // ID
    let rd = query[2] & 0x01; // recursion desired bit
    let opcode = query[2] & 0x78;
    resp.push(0x80 | opcode | rd); // QR=1, opcode, RD
    resp.push(0x80); // RA=1, RCODE=0
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    let emit_answer = q.qtype == 1 || q.qtype == 28; // A or AAAA
    let ancount: u16 = if emit_answer { 1 } else { 0 };
    resp.extend_from_slice(&ancount.to_be_bytes());
    resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    // Question (copy the original bytes verbatim).
    let qstart = 12;
    let qend = 12 + q.section_len;
    resp.extend_from_slice(&query[qstart..qend]);

    if emit_answer {
        resp.extend_from_slice(&[0xC0, 0x0C]); // name pointer -> offset 12
        resp.extend_from_slice(&q.qtype.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x01]); // class IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
        if q.qtype == 1 {
            resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH 4
            let v4 = if to_local {
                Ipv4Addr::LOCALHOST
            } else {
                Ipv4Addr::UNSPECIFIED
            };
            resp.extend_from_slice(&v4.octets());
        } else {
            resp.extend_from_slice(&[0x00, 0x10]); // RDLENGTH 16
            let mut v6 = [0u8; 16]; // ::
            if to_local {
                v6[15] = 1; // ::1
            }
            resp.extend_from_slice(&v6);
        }
    }
    resp
}

/// Minimal SERVFAIL so a client never hangs when upstream is unreachable.
fn build_servfail(query: &[u8]) -> Vec<u8> {
    let mut resp = Vec::with_capacity(12 + 8);
    if query.len() >= 2 {
        resp.extend_from_slice(&query[0..2]);
    } else {
        resp.extend_from_slice(&[0, 0]);
    }
    let rd = if query.len() > 2 { query[2] & 0x01 } else { 0 };
    resp.push(0x80 | rd);
    resp.push(0x82); // RA=1, RCODE=2 SERVFAIL
    // Echo QDCOUNT if we can, else 0.
    let qd = if query.len() >= 6 {
        u16::from_be_bytes([query[4], query[5]])
    } else {
        0
    };
    resp.extend_from_slice(&qd.to_be_bytes());
    resp.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    // Copy the question section if present and sane.
    if qd == 1 {
        if let Some(q) = parse_question(query) {
            resp.extend_from_slice(&query[12..12 + q.section_len]);
        }
    }
    resp
}

/// Relay a query to the configured upstream resolvers and return the first
/// response. Tries each upstream in order.
fn forward(query: &[u8], engine: &Engine, tcp: bool) -> Option<Vec<u8>> {
    let upstreams = engine.upstreams();
    for up in &upstreams {
        let addr = if up.contains(':') {
            up.clone()
        } else {
            format!("{up}:53")
        };
        let res = if tcp {
            forward_tcp(&addr, query)
        } else {
            forward_udp(&addr, query)
        };
        if let Some(r) = res {
            return Some(r);
        }
    }
    None
}

fn forward_udp(addr: &str, query: &[u8]) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    sock.connect(addr).ok()?;
    sock.send(query).ok()?;
    let mut buf = [0u8; 4096];
    let n = sock.recv(&mut buf).ok()?;
    Some(buf[..n].to_vec())
}

fn forward_tcp(addr: &str, query: &[u8]) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect(addr).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(4))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(4))).ok()?;
    let len = (query.len() as u16).to_be_bytes();
    stream.write_all(&len).ok()?;
    stream.write_all(query).ok()?;
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).ok()?;
    let rlen = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; rlen];
    stream.read_exact(&mut resp).ok()?;
    Some(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal A query for `name`.
    fn make_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0x00, 0x01]);
        q
    }

    #[test]
    fn parses_name() {
        let q = make_query("music.youtube.com", 1);
        let parsed = parse_question(&q).unwrap();
        assert_eq!(parsed.name, "music.youtube.com");
        assert_eq!(parsed.qtype, 1);
    }

    #[test]
    fn block_response_is_zero_ip() {
        let q = make_query("youtube.com", 1);
        let parsed = parse_question(&q).unwrap();
        let resp = build_block_response(&q, &parsed, false);
        // QR bit set.
        assert_eq!(resp[2] & 0x80, 0x80);
        // ANCOUNT == 1.
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);
        // Last 4 bytes are the A record payload 0.0.0.0.
        let n = resp.len();
        assert_eq!(&resp[n - 4..], &[0, 0, 0, 0]);
    }

    #[test]
    fn block_response_local_ip_when_page() {
        let q = make_query("youtube.com", 1);
        let parsed = parse_question(&q).unwrap();
        let resp = build_block_response(&q, &parsed, true);
        let n = resp.len();
        assert_eq!(&resp[n - 4..], &[127, 0, 0, 1]);
    }

    #[test]
    fn block_response_aaaa_nodata_for_txt() {
        let q = make_query("youtube.com", 16); // TXT
        let parsed = parse_question(&q).unwrap();
        let resp = build_block_response(&q, &parsed, false);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // NODATA
    }
}

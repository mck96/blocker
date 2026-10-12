//! Renders the motivational block page shown when a blocked site is opened.
//! Shared by the daemon (DNS block-page servers) and the proxy so the page
//! looks identical however the request was intercepted.

/// Build a complete HTTP/1.1 `200 OK` response (headers + body) carrying the
/// block page. `host` is the site the user tried to reach (may be empty).
pub fn http_response(title: &str, message: &str, host: &str) -> Vec<u8> {
    let body = html(title, message, host);
    format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

/// The standalone HTML document for the block page.
pub fn html(title: &str, message: &str, host: &str) -> String {
    let title = escape(title);
    let message = escape(message);
    let host = escape(host);
    let host_line = if host.is_empty() {
        String::new()
    } else {
        format!("<p class=\"host\">{host}</p>")
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>{title}</title><style>\
:root{{color-scheme:light dark}}\
*{{box-sizing:border-box}}\
body{{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;\
font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;\
background:linear-gradient(135deg,#0f2027,#203a43,#2c5364);color:#f4f7fa;padding:24px}}\
.card{{max-width:34rem;text-align:center;padding:8px 16px}}\
.art{{width:132px;height:132px;margin:0 auto 22px;display:block}}\
h1{{font-size:2.1rem;margin:.2em 0 .35em;letter-spacing:-.01em}}\
p{{font-size:1.12rem;line-height:1.6;color:#d6e2ea;margin:.4em 0}}\
.host{{margin-top:1.6em;font-size:.85rem;letter-spacing:.14em;text-transform:uppercase;color:#8fa6b4}}\
.tag{{margin-top:2.4em;font-size:.78rem;color:#7d93a1}}\
</style></head><body><div class=\"card\">\
<svg class=\"art\" viewBox=\"0 0 120 120\" fill=\"none\" xmlns=\"http://www.w3.org/2000/svg\">\
<circle cx=\"60\" cy=\"60\" r=\"56\" stroke=\"#5eead4\" stroke-width=\"3\" opacity=\".35\"/>\
<path d=\"M60 18l30 12v22c0 20-13 34-30 42-17-8-30-22-30-42V30l30-12z\" \
fill=\"#14323a\" stroke=\"#5eead4\" stroke-width=\"3\"/>\
<path d=\"M47 60l9 9 18-20\" stroke=\"#5eead4\" stroke-width=\"5\" stroke-linecap=\"round\" \
stroke-linejoin=\"round\"/></svg>\
<h1>{title}</h1><p>{message}</p>{host_line}\
<p class=\"tag\">Blocked by Blocker</p>\
</div></body></html>"
    )
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_and_escapes() {
        let r = http_response("Focus", "<script>", "x.com");
        let s = String::from_utf8(r).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK"));
        assert!(s.contains("Content-Length:"));
        assert!(s.contains("&lt;script&gt;"));
        assert!(s.contains("x.com"));
    }
}

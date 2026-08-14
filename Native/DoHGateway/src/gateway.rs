//! Loopback HTTP/1.1 gateway. The iOS client talks plaintext HTTP to
//! 127.0.0.1; this process opens the real outbound TLS session.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::doh::DohResolver;
use crate::http::{self, MAX_BODY_BYTES, MAX_HEADER_BYTES};
use crate::tls::GatewayTls;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const VISIBLE_SNI_TIMEOUT: Duration = Duration::from_secs(2);

const HOST_HEADER: &str = "x-dexo-gateway-host";
const PORT_HEADER: &str = "x-dexo-gateway-port";
const SCHEME_HEADER: &str = "x-dexo-gateway-scheme";
const SKIP_HEADER: &str = "x-dexo-gateway-skip";

#[derive(Clone)]
pub struct Gateway {
    resolver: DohResolver,
    tls: Arc<GatewayTls>,
}

impl Gateway {
    pub fn new(resolver: DohResolver, tls: Arc<GatewayTls>) -> Self {
        Self { resolver, tls }
    }

    pub async fn serve(self, listener: TcpListener, mut shutdown: watch::Receiver<bool>) {
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _)) => {
                            let gateway = self.clone();
                            tokio::spawn(async move {
                                if let Err(error) = gateway.handle(stream).await {
                                    eprintln!("[DoHGateway] {error}");
                                }
                            });
                        }
                        Err(error) => {
                            eprintln!("[DoHGateway] accept error: {error}");
                        }
                    }
                }
            }
        }
    }

    async fn handle(&self, mut client: TcpStream) -> Result<(), String> {
        let request = match read_http_request(&mut client).await {
            Ok(request) => request,
            Err(error) => {
                let _ = write_error(&mut client, 502, &error).await;
                return Err(error);
            }
        };
        let upstream = match upstream_target(&request) {
            Ok(upstream) => upstream,
            Err(error) => {
                write_error(&mut client, 502, &error).await?;
                return Ok(());
            }
        };
        if upstream.host.eq_ignore_ascii_case(self.resolver.host()) {
            return write_error(&mut client, 502, "refusing to proxy the DoH resolver").await;
        }

        let lookup = match self.resolver.lookup(&upstream.host).await {
            Ok(lookup) => lookup,
            Err(error) => {
                return write_error(
                    &mut client,
                    502,
                    &format!("DoH lookup {}: {error}", upstream.host),
                )
                .await;
            }
        };
        let addresses = ordered_addresses(&lookup);
        if addresses.is_empty() {
            return write_error(&mut client, 502, "DoH returned no addresses").await;
        }

        let ech_config = lookup
            .https
            .iter()
            .filter_map(|record| record.ech_config.clone())
            .next();
        let ech_present = ech_config.is_some();

        let mut last_ipv4_error = None;
        let mut last_error = "all upstream addresses failed".to_string();
        for ip in addresses {
            let addr = SocketAddr::new(ip, upstream.port);
            match self.forward(&request, &upstream, addr, ech_config.as_deref()).await {
                Ok(response) => {
                    eprintln!(
                        "[DoHGateway] {} {} -> {} ({}) ech={}",
                        request.method,
                        upstream.host,
                        addr,
                        lookup_summary(&lookup),
                        ech_present && response.1
                    );
                    client
                        .write_all(&response.0)
                        .await
                        .map_err(|error| format!("client write: {error}"))?;
                    return Ok(());
                }
                Err(error) => {
                    let formatted = format_attempt_error(addr, ech_present, &error);
                    if addr.is_ipv4() {
                        last_ipv4_error = Some(formatted.clone());
                    }
                    if addr.is_ipv4() || last_ipv4_error.is_none() {
                        last_error = formatted;
                    }
                }
            }
        }
        write_error(
            &mut client,
            502,
            last_ipv4_error.as_deref().unwrap_or(&last_error),
        )
        .await
    }

    async fn forward(
        &self,
        request: &ParsedRequest,
        upstream: &Upstream,
        addr: SocketAddr,
        ech_config: Option<&[u8]>,
    ) -> Result<(Vec<u8>, bool), String> {
        if let Some(config) = ech_config {
            let stream = connect_tcp(addr).await?;
            match tokio::time::timeout(
                CONNECT_TIMEOUT,
                self.tls.connect(&upstream.host, stream, Some(config)),
            )
            .await
            {
                Ok(Ok((tls, true))) => {
                    let bytes = proxy_http(tls, request, upstream).await?;
                    return Ok((bytes, true));
                }
                Ok(Ok((tls, false))) => {
                    let bytes = proxy_http(tls, request, upstream).await?;
                    return Ok((bytes, false));
                }
                Ok(Err(error)) => {
                    eprintln!(
                        "[DoHGateway] ECH handshake {addr} failed ({error}); visible SNI fallback ≤2s"
                    );
                }
                Err(_) => {
                    eprintln!(
                        "[DoHGateway] ECH handshake {addr} timed out; visible SNI fallback ≤2s"
                    );
                    // Keep going to the short visible-SNI retry; if that also
                    // dies, format_attempt_error reports "TLS timeout".
                }
            }
        }

        let stream = connect_tcp_within(addr, VISIBLE_SNI_TIMEOUT).await?;
        let tls = tokio::time::timeout(
            VISIBLE_SNI_TIMEOUT,
            self.tls.connect_visible_sni(&upstream.host, stream),
        )
        .await
        .map_err(|_| "TLS timeout".to_string())??;
        let bytes = proxy_http(tls, request, upstream).await?;
        Ok((bytes, false))
    }
}

async fn connect_tcp(addr: SocketAddr) -> Result<TcpStream, String> {
    connect_tcp_within(addr, CONNECT_TIMEOUT).await
}

async fn connect_tcp_within(addr: SocketAddr, limit: Duration) -> Result<TcpStream, String> {
    match tokio::time::timeout(limit, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) if is_no_route(&error) => {
            Err(format!("connect {addr}: No route to host"))
        }
        Ok(Err(error)) => Err(format!("connect {addr}: {error}")),
        Err(_) => Err(format!("connect timeout {addr}")),
    }
}

fn is_no_route(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::NetworkUnreachable
    ) || matches!(error.raw_os_error(), Some(51 | 65 | 101 | 113))
}

fn format_attempt_error(addr: SocketAddr, ech_present: bool, error: &str) -> String {
    let family = if addr.is_ipv4() { "IPv4" } else { "IPv6" };
    let ech = if ech_present { "yes" } else { "no" };
    let detail = if is_no_route_text(error) {
        "No route to host"
    } else if error.contains("connect timeout") {
        "connect timeout"
    } else if error.contains("timeout") || error.contains("timed out") {
        "TLS timeout"
    } else {
        error
    };
    format!("{family} {} ech={ech} {detail}", addr.ip())
}

fn is_no_route_text(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("no route to host")
        || lower.contains("network is unreachable")
        || lower.contains("os error 65")
        || lower.contains("os error 51")
}

async fn proxy_http<S>(
    mut tls: S,
    request: &ParsedRequest,
    upstream: &Upstream,
) -> Result<Vec<u8>, String>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let payload = encode_upstream_request(request, upstream);
    tls.write_all(&payload)
        .await
        .map_err(|error| format!("upstream write: {error}"))?;
    tls.flush()
        .await
        .map_err(|error| format!("upstream flush: {error}"))?;

    let response = tokio::time::timeout(UPSTREAM_TIMEOUT, http::read_http_response(&mut tls))
        .await
        .map_err(|_| "upstream read timeout".to_string())??;
    if response.is_empty() {
        return Err("empty upstream response".into());
    }
    http::process_upstream_response(&response)
}

#[derive(Debug)]
struct ParsedRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct Upstream {
    host: String,
    port: u16,
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|(key, value)| {
        if key.eq_ignore_ascii_case(name) {
            Some(value.as_str())
        } else {
            None
        }
    })
}

fn upstream_target(request: &ParsedRequest) -> Result<Upstream, String> {
    let host_header = header_value(&request.headers, HOST_HEADER)
        .or_else(|| header_value(&request.headers, "host"))
        .ok_or_else(|| "missing Host".to_string())?;
    let (host, header_port) = split_host_port(host_header)?;
    if is_loopback_host(&host) {
        return Err("refusing loopback upstream".into());
    }
    let scheme = header_value(&request.headers, SCHEME_HEADER).unwrap_or("https");
    if !scheme.eq_ignore_ascii_case("https") {
        return Err("only HTTPS origins are supported".into());
    }
    let port = header_value(&request.headers, PORT_HEADER)
        .and_then(|value| value.parse().ok())
        .or(header_port)
        .unwrap_or(443);
    if port == 0 {
        return Err("invalid upstream port".into());
    }
    Ok(Upstream { host, port })
}

fn split_host_port(value: &str) -> Result<(String, Option<u16>), String> {
    let value = value.trim();
    if let Some(stripped) = value.strip_prefix('[') {
        let (host, rest) = stripped
            .split_once(']')
            .ok_or_else(|| "invalid IPv6 host".to_string())?;
        let port = if let Some(port) = rest.strip_prefix(':') {
            Some(port.parse().map_err(|_| "invalid port".to_string())?)
        } else if rest.is_empty() {
            None
        } else {
            return Err("invalid IPv6 host".into());
        };
        return Ok((host.to_ascii_lowercase(), port));
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if host.contains(':') {
            return Ok((value.to_ascii_lowercase(), None));
        }
        let port: u16 = port.parse().map_err(|_| "invalid port".to_string())?;
        return Ok((host.to_ascii_lowercase(), Some(port)));
    }
    Ok((value.to_ascii_lowercase(), None))
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host == "127.0.0.1"
        || host == "::1"
        || host == "0.0.0.0"
}

fn encode_upstream_request(request: &ParsedRequest, upstream: &Upstream) -> Vec<u8> {
    let target = origin_form(&request.target);
    let mut out = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", request.method, target, host_header(upstream)).into_bytes();
    for (name, value) in &request.headers {
        if is_hop_by_hop(name)
            || name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("accept-encoding")
            || name.eq_ignore_ascii_case(SKIP_HEADER)
            || name.to_ascii_lowercase().starts_with("x-dexo-gateway-")
        {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out.extend_from_slice(&request.body);
    out
}

fn host_header(upstream: &Upstream) -> String {
    if upstream.port == 443 {
        upstream.host.clone()
    } else {
        format!("{}:{}", upstream.host, upstream.port)
    }
}

fn origin_form(target: &str) -> String {
    if let Some(rest) = target.strip_prefix("http://").or_else(|| target.strip_prefix("https://")) {
        if let Some(slash) = rest.find('/') {
            return rest[slash..].to_string();
        }
        return "/".to_string();
    }
    if target.is_empty() {
        "/".to_string()
    } else {
        target.to_string()
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-connection"
    )
}

fn ordered_addresses(lookup: &crate::dns::Lookup) -> Vec<std::net::IpAddr> {
    if !lookup.ipv4.is_empty() {
        return lookup
            .ipv4
            .iter()
            .copied()
            .map(std::net::IpAddr::V4)
            .collect();
    }
    lookup
        .ipv6
        .iter()
        .copied()
        .map(std::net::IpAddr::V6)
        .collect()
}

fn lookup_summary(lookup: &crate::dns::Lookup) -> String {
    let ech = lookup.https.iter().any(|record| record.ech_config.is_some());
    format!(
        "A={} AAAA={} HTTPS={} ech_rr={}",
        lookup.ipv4.len(),
        lookup.ipv6.len(),
        lookup.https.len(),
        ech
    )
}

fn gateway_error_response(status: u16, message: &str) -> Vec<u8> {
    let reason = if message.starts_with("DoH gateway: ") {
        message.to_string()
    } else {
        format!("DoH gateway: {message}")
    };
    let body = format!(r#"{{"errors":["{}"]}}"#, json_escape(&reason));
    let phrase = match status {
        502 => "Bad Gateway",
        400 => "Bad Request",
        _ => "Error",
    };
    let mut out = format!(
        "HTTP/1.1 {status} {phrase}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

async fn write_error(stream: &mut TcpStream, status: u16, message: &str) -> Result<(), String> {
    stream
        .write_all(&gateway_error_response(status, message))
        .await
        .map_err(|error| error.to_string())?;
    Ok(())
}

async fn read_http_request(stream: &mut TcpStream) -> Result<ParsedRequest, String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("client read: {error}"))?;
        if n == 0 {
            return Err("client closed before complete request".into());
        }
        buffer.extend_from_slice(&chunk[..n]);
        if buffer.len() > MAX_HEADER_BYTES + MAX_BODY_BYTES {
            return Err("request too large".into());
        }
        if let Some(request) = parse_http_request(&buffer)? {
            return Ok(request);
        }
        if buffer.len() > MAX_HEADER_BYTES && !buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            return Err("request headers too large".into());
        }
    }
}

fn parse_http_request(buffer: &[u8]) -> Result<Option<ParsedRequest>, String> {
    const DELIM: &[u8] = b"\r\n\r\n";
    let Some(index) = buffer.windows(DELIM.len()).position(|window| window == DELIM) else {
        return Ok(None);
    };
    if index > MAX_HEADER_BYTES {
        return Err("request headers too large".into());
    }
    let header_text = std::str::from_utf8(&buffer[..index]).map_err(|_| "request headers not utf8")?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().ok_or("missing request line")?;
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().ok_or("malformed request line")?.to_string();
    let target = parts.next().ok_or("malformed request line")?.to_string();
    let version = parts.next().ok_or("malformed request line")?;
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err("unsupported HTTP version".into());
    }
    if method.eq_ignore_ascii_case("CONNECT") {
        return Err("CONNECT is not supported".into());
    }
    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or("malformed header")?;
        let name = name.trim().to_string();
        let value = value.trim().to_string();
        if name.eq_ignore_ascii_case("transfer-encoding") && !value.eq_ignore_ascii_case("identity") {
            return Err("chunked requests are not supported".into());
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().map_err(|_| "invalid content-length".to_string())?;
        }
        headers.push((name, value));
    }
    if content_length > MAX_BODY_BYTES {
        return Err("request body too large".into());
    }
    let body_start = index + DELIM.len();
    if buffer.len() < body_start + content_length {
        return Ok(None);
    }
    Ok(Some(ParsedRequest {
        method,
        target,
        headers,
        body: buffer[body_start..body_start + content_length].to_vec(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(headers: Vec<(&str, &str)>) -> ParsedRequest {
        ParsedRequest {
            method: "GET".into(),
            target: "/latest.json".into(),
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: Vec::new(),
        }
    }

    #[test]
    fn uses_gateway_host_header_and_default_https_port() {
        let parsed = request(vec![
            ("Host", "127.0.0.1:47821"),
            (HOST_HEADER, "linux.do"),
            (PORT_HEADER, "443"),
            (SCHEME_HEADER, "https"),
        ]);
        let upstream = upstream_target(&parsed).unwrap();
        assert_eq!(upstream.host, "linux.do");
        assert_eq!(upstream.port, 443);
    }

    #[test]
    fn refuses_loopback_and_non_https() {
        assert!(upstream_target(&request(vec![(HOST_HEADER, "127.0.0.1")])).is_err());
        assert!(upstream_target(&request(vec![
            (HOST_HEADER, "linux.do"),
            (SCHEME_HEADER, "http"),
        ]))
        .is_err());
    }

    #[test]
    fn strips_gateway_headers_from_upstream_request() {
        let parsed = request(vec![
            ("Host", "127.0.0.1:1"),
            (HOST_HEADER, "idcflare.com"),
            ("Accept", "application/json"),
            (SKIP_HEADER, "1"),
        ]);
        let upstream = Upstream {
            host: "idcflare.com".into(),
            port: 443,
        };
        let encoded = String::from_utf8(encode_upstream_request(&parsed, &upstream)).unwrap();
        assert!(encoded.starts_with("GET /latest.json HTTP/1.1\r\nHost: idcflare.com\r\n"));
        assert!(encoded.contains("Accept: application/json"));
        assert!(!encoded.to_ascii_lowercase().contains(HOST_HEADER));
        assert!(encoded.contains("Connection: close"));
    }

    #[test]
    fn strips_accept_encoding_from_upstream_request() {
        let parsed = request(vec![
            ("Host", "127.0.0.1:1"),
            (HOST_HEADER, "linux.do"),
            ("Accept-Encoding", "gzip, deflate"),
            ("Accept", "application/json"),
        ]);
        let upstream = Upstream {
            host: "linux.do".into(),
            port: 443,
        };
        let encoded = String::from_utf8(encode_upstream_request(&parsed, &upstream)).unwrap();
        assert!(encoded.contains("Accept: application/json"));
        assert!(!encoded.to_ascii_lowercase().contains("accept-encoding"));
    }

    #[test]
    fn gateway_failures_are_complete_json_502() {
        let response = String::from_utf8(gateway_error_response(502, "Cloudflare HTML")).unwrap();
        assert!(response.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
        assert!(response.contains("Content-Type: application/json"));
        assert!(response.contains(r#"{"errors":["DoH gateway: Cloudflare HTML"]}"#));
        assert!(!response.contains("text/plain"));
    }

    #[test]
    fn gateway_error_json_escapes_quotes() {
        let response = String::from_utf8(gateway_error_response(502, r#"TLS handshake "linux.do""#)).unwrap();
        assert!(response.contains(r#"{"errors":["DoH gateway: TLS handshake \"linux.do\""]}"#));
    }

    #[test]
    fn ipv4_present_skips_ipv6_addresses() {
        let lookup = crate::dns::Lookup {
            ipv4: vec!["104.20.16.234".parse().unwrap(), "172.66.166.61".parse().unwrap()],
            ipv6: vec!["2606:4700:10::6814:10ea".parse().unwrap()],
            https: Vec::new(),
        };
        let addresses = ordered_addresses(&lookup);
        assert_eq!(addresses.len(), 2);
        assert!(addresses.iter().all(|ip| ip.is_ipv4()));
    }

    #[test]
    fn ipv6_used_only_without_ipv4() {
        let lookup = crate::dns::Lookup {
            ipv4: Vec::new(),
            ipv6: vec!["2606:4700:10::6814:10ea".parse().unwrap()],
            https: Vec::new(),
        };
        let addresses = ordered_addresses(&lookup);
        assert_eq!(addresses.len(), 1);
        assert!(addresses[0].is_ipv6());
    }

    #[test]
    fn attempt_error_names_family_ech_and_tls_timeout() {
        let addr: SocketAddr = "104.20.16.234:443".parse().unwrap();
        assert_eq!(
            format_attempt_error(addr, true, "TLS timeout"),
            "IPv4 104.20.16.234 ech=yes TLS timeout"
        );
        let v6: SocketAddr = "[2606:4700:10::6814:10ea]:443".parse().unwrap();
        assert_eq!(
            format_attempt_error(v6, true, "connect [2606:4700:10::6814:10ea]:443 No route to host (os error 65)"),
            "IPv6 2606:4700:10::6814:10ea ech=yes No route to host"
        );
    }
}

//! Loopback HTTP/1.1 gateway. The iOS client talks plaintext HTTP to
//! 127.0.0.1; this process opens the real outbound TLS session.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use crate::doh::DohResolver;
use crate::tls::GatewayTls;

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

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
        let request = read_http_request(&mut client).await?;
        let upstream = upstream_target(&request)?;
        if upstream.host.eq_ignore_ascii_case(self.resolver.host()) {
            return write_error(&mut client, 502, "refusing to proxy the DoH resolver").await;
        }

        let lookup = self
            .resolver
            .lookup(&upstream.host)
            .await
            .map_err(|error| format!("DoH lookup {}: {error}", upstream.host))?;
        let addresses = ordered_addresses(&lookup);
        if addresses.is_empty() {
            return write_error(&mut client, 502, "DoH returned no addresses").await;
        }

        let ech_config = lookup
            .https
            .iter()
            .filter_map(|record| record.ech_config.clone())
            .next();
        let used_ech = ech_config.is_some();

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
                        used_ech && response.1
                    );
                    client
                        .write_all(&response.0)
                        .await
                        .map_err(|error| format!("client write: {error}"))?;
                    return Ok(());
                }
                Err(error) => last_error = error,
            }
        }
        write_error(&mut client, 502, &last_error).await
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
            match self.tls.connect(&upstream.host, stream, Some(config)).await {
                Ok((tls, true)) => {
                    let bytes = proxy_http(tls, request, upstream).await?;
                    return Ok((bytes, true));
                }
                Ok((tls, false)) => {
                    let bytes = proxy_http(tls, request, upstream).await?;
                    return Ok((bytes, false));
                }
                Err(error) => {
                    eprintln!(
                        "[DoHGateway] ECH connect {addr} failed ({error}); retrying TLS 1.3 with visible SNI"
                    );
                }
            }
        }

        let stream = connect_tcp(addr).await?;
        let (tls, _) = self.tls.connect(&upstream.host, stream, None).await?;
        let bytes = proxy_http(tls, request, upstream).await?;
        Ok((bytes, false))
    }
}

async fn connect_tcp(addr: SocketAddr) -> Result<TcpStream, String> {
    tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr))
        .await
        .map_err(|_| format!("connect timeout {addr}"))?
        .map_err(|error| format!("connect {addr}: {error}"))
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

    let mut response = Vec::new();
    tokio::time::timeout(UPSTREAM_TIMEOUT, tls.read_to_end(&mut response))
        .await
        .map_err(|_| "upstream read timeout".to_string())?
        .map_err(|error| format!("upstream read: {error}"))?;
    if response.is_empty() {
        return Err("empty upstream response".into());
    }
    Ok(response)
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
    let mut addresses = Vec::new();
    addresses.extend(lookup.ipv4.iter().copied().map(std::net::IpAddr::V4));
    addresses.extend(lookup.ipv6.iter().copied().map(std::net::IpAddr::V6));
    addresses
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

async fn write_error(stream: &mut TcpStream, status: u16, message: &str) -> Result<(), String> {
    let body = message.as_bytes();
    let response = format!(
        "HTTP/1.1 {status} Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|error| error.to_string())?;
    stream.write_all(body).await.map_err(|error| error.to_string())?;
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
}

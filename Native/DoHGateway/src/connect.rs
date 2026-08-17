//! HTTP CONNECT listener for isolated WKWebView data stores.
//!
//! `challenges.cloudflare.com` / `*.hcaptcha.com` are a raw TCP tunnel after
//! DoH resolve (WebKit keeps Safari TLS). Other hosts are MITM + the existing
//! ECH rustls outbound so SNI stays hidden.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use crate::doh::DohResolver;
use crate::gateway::{self, Gateway, ParsedRequest};
use crate::mitm::MitmAuthority;
use crate::tunnel_policy;

const PREFACE_LIMIT: usize = 16 * 1024;
const TUNNEL_IDLE: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct ConnectGateway {
    resolver: DohResolver,
    http: Gateway,
    mitm: Arc<MitmAuthority>,
}

impl ConnectGateway {
    pub fn new(
        resolver: DohResolver,
        http: Gateway,
        mitm: Arc<MitmAuthority>,
    ) -> Self {
        Self {
            resolver,
            http,
            mitm,
        }
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
                                    eprintln!("[DoHGateway CONNECT] {error}");
                                }
                            });
                        }
                        Err(error) => {
                            eprintln!("[DoHGateway CONNECT] accept error: {error}");
                        }
                    }
                }
            }
        }
    }

    async fn handle(&self, mut client: TcpStream) -> Result<(), String> {
        let request = match read_connect_request(&mut client).await {
            Ok(request) => request,
            Err(error) => {
                let _ = write_connect_error(&mut client, 400, &error).await;
                return Err(error);
            }
        };
        if request.host.eq_ignore_ascii_case(self.resolver.host()) {
            write_connect_error(&mut client, 502, "refusing to proxy the DoH resolver").await?;
            return Ok(());
        }
        if tunnel_policy::should_passthrough_tls(&request.host) {
            self.raw_tunnel(client, request).await
        } else {
            self.mitm_http(client, request).await
        }
    }

    async fn raw_tunnel(&self, mut client: TcpStream, request: ConnectRequest) -> Result<(), String> {
        let lookup = self
            .resolver
            .lookup(&request.host)
            .await
            .map_err(|error| format!("DoH lookup {}: {error}", request.host))?;
        let addresses = gateway::ordered_addresses(&lookup);
        if addresses.is_empty() {
            write_connect_error(&mut client, 502, "DoH returned no addresses").await?;
            return Ok(());
        }

        let mut last_error = "DoH returned no addresses".to_string();
        let mut upstream = None;
        for ip in addresses {
            let addr = SocketAddr::new(ip, request.port);
            match gateway::connect_tcp(addr).await {
                Ok(stream) => {
                    upstream = Some(stream);
                    break;
                }
                Err(error) => last_error = error,
            }
        }
        let mut upstream = match upstream {
            Some(stream) => stream,
            None => {
                write_connect_error(&mut client, 502, &last_error).await?;
                return Ok(());
            }
        };

        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|error| format!("CONNECT 200: {error}"))?;
        eprintln!(
            "[DoHGateway CONNECT] tunnel {} {} (Safari TLS)",
            request.host, request.port
        );
        match tokio::time::timeout(TUNNEL_IDLE, tokio::io::copy_bidirectional(&mut client, &mut upstream))
            .await
        {
            Ok(Ok(_)) | Err(_) => Ok(()),
            Ok(Err(error)) => Err(format!("CONNECT tunnel {}: {error}", request.host)),
        }
    }

    async fn mitm_http(&self, mut client: TcpStream, request: ConnectRequest) -> Result<(), String> {
        let config = self.mitm.server_config(&request.host)?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .map_err(|error| format!("CONNECT 200: {error}"))?;
        let acceptor = TlsAcceptor::from(config);
        let mut tls = acceptor
            .accept(client)
            .await
            .map_err(|error| format!("MITM handshake {}: {error}", request.host))?;
        eprintln!(
            "[DoHGateway CONNECT] MITM {} {} (ECH outbound)",
            request.host, request.port
        );

        loop {
            let mut parsed = match gateway::read_http_request(&mut tls).await {
                Ok(parsed) => parsed,
                Err(error) if error.contains("client closed") => return Ok(()),
                Err(error) => {
                    let _ = write_http_error(&mut tls, 502, &error).await;
                    return Err(error);
                }
            };
            ensure_host_header(&mut parsed, &request);
            match self.http.execute_http(&parsed).await {
                Ok(bytes) => {
                    tls.write_all(&bytes)
                        .await
                        .map_err(|error| format!("MITM write: {error}"))?;
                    if connection_close(&parsed) {
                        return Ok(());
                    }
                }
                Err(error) => {
                    let _ = write_http_error(&mut tls, 502, &error).await;
                    return Err(error);
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectRequest {
    host: String,
    port: u16,
}

fn ensure_host_header(request: &mut ParsedRequest, connect: &ConnectRequest) {
    let has_host = request
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"));
    if !has_host {
        let value = if connect.port == 443 {
            connect.host.clone()
        } else {
            format!("{}:{}", connect.host, connect.port)
        };
        request.headers.push(("Host".into(), value));
    }
}

fn connection_close(request: &ParsedRequest) -> bool {
    request.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("connection") && value.to_ascii_lowercase().contains("close")
    })
}

async fn read_connect_request(stream: &mut TcpStream) -> Result<ConnectRequest, String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("CONNECT read: {error}"))?;
        if n == 0 {
            return Err("client closed before CONNECT".into());
        }
        buffer.extend_from_slice(&chunk[..n]);
        if buffer.len() > PREFACE_LIMIT {
            return Err("CONNECT preface too large".into());
        }
        if let Some(request) = parse_connect_request(&buffer)? {
            return Ok(request);
        }
    }
}

pub(crate) fn parse_connect_request(buffer: &[u8]) -> Result<Option<ConnectRequest>, String> {
    const DELIM: &[u8] = b"\r\n\r\n";
    let Some(index) = buffer.windows(DELIM.len()).position(|window| window == DELIM) else {
        return Ok(None);
    };
    let header_text =
        std::str::from_utf8(&buffer[..index]).map_err(|_| "CONNECT headers not utf8")?;
    let request_line = header_text
        .split("\r\n")
        .next()
        .ok_or("missing CONNECT request line")?;
    parse_connect_request_line(request_line).map(Some)
}

pub(crate) fn parse_connect_request_line(request_line: &str) -> Result<ConnectRequest, String> {
    let mut parts = request_line.splitn(3, ' ');
    let method = parts.next().ok_or("malformed CONNECT line")?;
    let target = parts.next().ok_or("malformed CONNECT line")?;
    let version = parts.next().ok_or("malformed CONNECT line")?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err("expected CONNECT".into());
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err("unsupported HTTP version".into());
    }
    parse_authority(target)
}

fn parse_authority(authority: &str) -> Result<ConnectRequest, String> {
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let (host, rest) = stripped
            .split_once(']')
            .ok_or_else(|| "invalid IPv6 CONNECT authority".to_string())?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| "invalid IPv6 CONNECT authority".to_string())?
            .parse()
            .map_err(|_| "invalid CONNECT port".to_string())?;
        (host.to_string(), port)
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| "CONNECT authority must be host:port".to_string())?;
        if host.contains(':') {
            return Err("invalid CONNECT authority".into());
        }
        let port = port.parse().map_err(|_| "invalid CONNECT port".to_string())?;
        (host.to_string(), port)
    };
    if host.is_empty() || port == 0 {
        return Err("invalid CONNECT authority".into());
    }
    if host.eq_ignore_ascii_case("127.0.0.1")
        || host.eq_ignore_ascii_case("localhost")
        || host == "::1"
    {
        return Err("refusing loopback CONNECT".into());
    }
    Ok(ConnectRequest {
        host: host.to_ascii_lowercase(),
        port,
    })
}

async fn write_connect_error(
    stream: &mut TcpStream,
    status: u16,
    message: &str,
) -> Result<(), String> {
    let body = format!("{status} {message}\n");
    let response = format!(
        "HTTP/1.1 {status} Error\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|error| error.to_string())
}

async fn write_http_error<S>(stream: &mut S, status: u16, message: &str) -> Result<(), String>
where
    S: AsyncWriteExt + Unpin,
{
    let body = format!(r#"{{"errors":["DoH gateway: {}"]}}"#, message.replace('"', "'"));
    let response = format!(
        "HTTP/1.1 {status} Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_connect_authority() {
        let parsed = parse_connect_request_line("CONNECT linux.do:443 HTTP/1.1").unwrap();
        assert_eq!(parsed.host, "linux.do");
        assert_eq!(parsed.port, 443);
        let parsed = parse_connect_request(
            b"CONNECT challenges.cloudflare.com:443 HTTP/1.1\r\nHost: challenges.cloudflare.com:443\r\n\r\n",
        )
        .unwrap()
        .unwrap();
        assert_eq!(parsed.host, "challenges.cloudflare.com");
    }

    #[test]
    fn rejects_non_connect_and_loopback() {
        assert!(parse_connect_request_line("GET / HTTP/1.1").is_err());
        assert!(parse_connect_request_line("CONNECT 127.0.0.1:443 HTTP/1.1").is_err());
        assert!(parse_connect_request(b"CONNECT linux.do:443 HTTP/1.1\r\n").unwrap().is_none());
    }
}

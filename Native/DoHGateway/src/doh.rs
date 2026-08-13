//! DNS-over-HTTPS client that dials bootstrap IPs so the DoH hostname is not
//! resolved through system DNS (chicken-and-egg).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::dns::{self, Lookup, TYPE_A, TYPE_AAAA, TYPE_HTTPS};
use crate::tls::GatewayTls;

const DOH_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone)]
pub struct DohResolver {
    endpoint: DohEndpoint,
    tls: Arc<GatewayTls>,
}

#[derive(Clone)]
struct DohEndpoint {
    host: String,
    port: u16,
    path: String,
    bootstrap: Vec<IpAddr>,
}

impl DohResolver {
    pub fn new(doh_url: &str, tls: Arc<GatewayTls>) -> Result<Self, &'static str> {
        Ok(Self {
            endpoint: parse_doh_url(doh_url)?,
            tls,
        })
    }

    pub fn host(&self) -> &str {
        &self.endpoint.host
    }

    pub async fn lookup(&self, name: &str) -> Result<Lookup, String> {
        let mut combined = Lookup::default();
        for record_type in [TYPE_HTTPS, TYPE_A, TYPE_AAAA] {
            match self.query(name, record_type).await {
                Ok(part) => {
                    combined.ipv4.extend(part.ipv4);
                    combined.ipv6.extend(part.ipv6);
                    combined.https.extend(part.https);
                }
                Err(error) if record_type == TYPE_HTTPS => {
                    // HTTPS/SVCB is optional; A/AAAA still let us connect-by-IP.
                    tracing_log(&format!("HTTPS RR lookup skipped: {error}"));
                }
                Err(error) => {
                    if combined.ipv4.is_empty() && combined.ipv6.is_empty() {
                        return Err(error);
                    }
                }
            }
        }
        combined.ipv4.sort();
        combined.ipv4.dedup();
        combined.ipv6.sort();
        combined.ipv6.dedup();
        if combined.ipv4.is_empty() && combined.ipv6.is_empty() {
            return Err("DoH returned no addresses".into());
        }
        Ok(combined)
    }

    async fn query(&self, name: &str, record_type: u16) -> Result<Lookup, String> {
        let id = dns_id(name, record_type);
        let wire = dns::encode_query(id, name, record_type).map_err(str::to_string)?;
        let body = self.exchange(&wire).await?;
        dns::decode_lookup(&body, id).map_err(str::to_string)
    }

    async fn exchange(&self, wire: &[u8]) -> Result<Vec<u8>, String> {
        let mut last_error = "no bootstrap addresses".to_string();
        for ip in &self.endpoint.bootstrap {
            match self.exchange_one(*ip, wire).await {
                Ok(body) => return Ok(body),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    async fn exchange_one(&self, ip: IpAddr, wire: &[u8]) -> Result<Vec<u8>, String> {
        let addr = SocketAddr::new(ip, self.endpoint.port);
        let tcp = tokio::time::timeout(DOH_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| format!("DoH connect timeout {addr}"))?
            .map_err(|error| format!("DoH connect {addr}: {error}"))?;
        let connector = TlsConnector::from(self.tls.plain_config());
        let server_name = ServerName::try_from(self.endpoint.host.clone())
            .map_err(|_| "invalid DoH hostname")?;
        let mut tls = tokio::time::timeout(DOH_TIMEOUT, connector.connect(server_name, tcp))
            .await
            .map_err(|_| "DoH TLS timeout".to_string())?
            .map_err(|error| format!("DoH TLS: {error}"))?;

        let path = if self.endpoint.path.is_empty() {
            "/dns-query".to_string()
        } else {
            self.endpoint.path.clone()
        };
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
            host = self.endpoint.host,
            len = wire.len(),
        );
        tls.write_all(request.as_bytes())
            .await
            .map_err(|error| format!("DoH write headers: {error}"))?;
        tls.write_all(wire)
            .await
            .map_err(|error| format!("DoH write body: {error}"))?;
        tls.flush().await.map_err(|error| format!("DoH flush: {error}"))?;

        let mut response = Vec::new();
        tokio::time::timeout(DOH_TIMEOUT, tls.read_to_end(&mut response))
            .await
            .map_err(|_| "DoH read timeout".to_string())?
            .map_err(|error| format!("DoH read: {error}"))?;
        split_http_body(&response)
    }
}

fn tracing_log(message: &str) {
    eprintln!("[DoHGateway] {message}");
}

fn dns_id(name: &str, record_type: u16) -> u16 {
    let mut hash: u16 = 0x9E37;
    for byte in name.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(byte as u16);
    }
    hash.wrapping_add(record_type)
}

fn parse_doh_url(input: &str) -> Result<DohEndpoint, &'static str> {
    let value = input.trim();
    if !value.to_ascii_lowercase().starts_with("https://") {
        return Err("DoH URL must be HTTPS");
    }
    let rest = &value["https://".len()..];
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/dns-query".to_string()),
    };
    let authority = authority.split_once('?').map(|(a, _)| a).unwrap_or(authority);
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => {
            let port: u16 = port.parse().map_err(|_| "invalid DoH port")?;
            (host, port)
        }
        None => (authority, 443u16),
    };
    if host.is_empty() || host.contains('@') {
        return Err("invalid DoH host");
    }
    let path = path.split('#').next().unwrap_or(&path).to_string();
    let path = if let Some((path, _)) = path.split_once('?') {
        path.to_string()
    } else {
        path
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let bootstrap = bootstrap_ips(&host);
    if bootstrap.is_empty() {
        return Err("DoH host has no bootstrap IPs");
    }
    Ok(DohEndpoint {
        host,
        port,
        path,
        bootstrap,
    })
}

/// Well-known public DoH hosts. Custom endpoints must use one of these names
/// or a literal IP so the resolver itself is not a chicken-and-egg lookup.
pub fn bootstrap_ips(host: &str) -> Vec<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![ip];
    }
    let addresses: &[&str] = match host {
        "cloudflare-dns.com" | "one.one.one.one" | "1dot1dot1dot1.cloudflare-dns.com" => {
            &["1.1.1.1", "1.0.0.1"]
        }
        "mozilla.cloudflare-dns.com" => &["1.1.1.1", "1.0.0.1"],
        "dns.google" | "dns.google.com" => &["8.8.8.8", "8.8.4.4"],
        "dns.quad9.net" | "dns9.quad9.net" => &["9.9.9.9", "149.112.112.112"],
        "dns.alidns.com" => &["223.5.5.5", "223.6.6.6"],
        "doh.pub" | "dns.pub" => &["1.12.12.12", "120.53.53.53"],
        "private.canadianshield.cira.ca" => &["149.112.121.10", "149.112.122.10"],
        "dns.nextdns.io" => &["45.90.28.0", "45.90.30.0"],
        _ => &[],
    };
    addresses.iter().filter_map(|value| value.parse().ok()).collect()
}

fn split_http_body(response: &[u8]) -> Result<Vec<u8>, String> {
    const DELIM: &[u8] = b"\r\n\r\n";
    let index = response
        .windows(DELIM.len())
        .position(|window| window == DELIM)
        .ok_or_else(|| "DoH HTTP response missing header delimiter".to_string())?;
    let header = std::str::from_utf8(&response[..index]).map_err(|_| "DoH HTTP headers not utf8")?;
    let status_line = header.lines().next().unwrap_or("");
    if !status_line.contains(" 200 ") && !status_line.ends_with(" 200") {
        return Err(format!("DoH HTTP {status_line}"));
    }
    Ok(response[index + DELIM.len()..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_cloudflare_endpoint_with_bootstrap_ips() {
        let endpoint = parse_doh_url("https://cloudflare-dns.com/dns-query").unwrap();
        assert_eq!(endpoint.host, "cloudflare-dns.com");
        assert_eq!(endpoint.port, 443);
        assert_eq!(endpoint.path, "/dns-query");
        assert!(endpoint.bootstrap.contains(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn parses_aliyun_and_rejects_unknown_hosts() {
        let endpoint = parse_doh_url("https://dns.alidns.com/dns-query").unwrap();
        assert_eq!(endpoint.bootstrap[0], IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)));
        assert!(parse_doh_url("https://unknown-doh.example/dns-query").is_err());
        assert!(parse_doh_url("http://cloudflare-dns.com/dns-query").is_err());
    }

    #[test]
    fn literal_ip_bootstrap_is_the_host() {
        let endpoint = parse_doh_url("https://1.1.1.1/dns-query").unwrap();
        assert_eq!(endpoint.bootstrap, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
    }

    #[test]
    fn splits_dns_message_body() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\r\nWIRE";
        assert_eq!(split_http_body(response).unwrap(), b"WIRE");
    }
}

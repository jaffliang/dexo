//! DNS-over-HTTPS client. Well-known hosts dial hardcoded bootstrap IPs.
//! Custom DoH hostnames are resolved once at gateway start via system DNS.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::dns::{self, Lookup, TYPE_A, TYPE_AAAA, TYPE_HTTPS};
use crate::http;
use crate::tls::GatewayTls;

const DOH_TIMEOUT: Duration = Duration::from_secs(8);
const SYSTEM_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_NAME: &str = "linux.do";

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
    pub async fn new(doh_url: &str, tls: Arc<GatewayTls>) -> Result<Self, String> {
        let mut endpoint = parse_doh_url(doh_url).map_err(str::to_string)?;
        if endpoint.bootstrap.is_empty() {
            tracing_log(&format!(
                "no hardcoded bootstrap for {}; resolving once via system DNS",
                endpoint.host
            ));
            endpoint.bootstrap = system_lookup(&endpoint.host, endpoint.port).await?;
        }
        Ok(Self { endpoint, tls })
    }

    pub fn host(&self) -> &str {
        &self.endpoint.host
    }

    pub async fn probe(&self) -> Result<(), String> {
        self.lookup(PROBE_NAME)
            .await
            .map(|_| ())
            .map_err(|error| format!("DoH probe failed: {error}"))
    }

    pub async fn lookup(&self, name: &str) -> Result<Lookup, String> {
        let mut combined = Lookup::default();

        let (https_part, a_part) = tokio::join!(self.query(name, TYPE_HTTPS), self.query(name, TYPE_A));

        match https_part {
            Ok(part) => {
                combined.https.extend(part.https);
                combined.ipv4.extend(part.ipv4);
                combined.ipv6.extend(part.ipv6);
            }
            Err(error) => tracing_log(&format!("HTTPS RR lookup skipped: {error}")),
        }

        match a_part {
            Ok(part) => {
                combined.ipv4.extend(part.ipv4);
                combined.ipv6.extend(part.ipv6);
                combined.https.extend(part.https);
            }
            Err(error) => {
                if combined.ipv4.is_empty() && combined.ipv6.is_empty() {
                    tracing_log(&format!("A lookup failed: {error}"));
                }
            }
        }

        // Jeff's Wi-Fi has no IPv6 route. When A or ipv4hint exists, never
        // query or keep AAAA — IPv6 no-route must not become the last error.
        if combined.ipv4.is_empty() {
            match self.query(name, TYPE_AAAA).await {
                Ok(part) => {
                    combined.ipv4.extend(part.ipv4);
                    combined.ipv6.extend(part.ipv6);
                }
                Err(error) => {
                    if combined.ipv4.is_empty() && combined.ipv6.is_empty() {
                        return Err(error);
                    }
                }
            }
        } else {
            combined.ipv6.clear();
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
        match self.exchange_method(ip, wire, true).await {
            Ok(body) => Ok(body),
            Err(post_error) => {
                tracing_log(&format!("DoH POST failed ({post_error}); trying RFC 8484 GET"));
                match self.exchange_method(ip, wire, false).await {
                    Ok(body) => Ok(body),
                    Err(get_error) => Err(format!("{post_error}; GET {get_error}")),
                }
            }
        }
    }

    async fn exchange_method(&self, ip: IpAddr, wire: &[u8], post: bool) -> Result<Vec<u8>, String> {
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
        let request = if post {
            format!(
                "POST {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
                host = self.endpoint.host,
                len = wire.len(),
            )
        } else {
            let dns = base64url_nopad(wire);
            let separator = if path.contains('?') { '&' } else { '?' };
            format!(
                "GET {path}{separator}dns={dns} HTTP/1.1\r\nHost: {host}\r\nAccept: application/dns-message\r\nConnection: close\r\n\r\n",
                host = self.endpoint.host,
            )
        };
        tls.write_all(request.as_bytes())
            .await
            .map_err(|error| format!("DoH write headers: {error}"))?;
        if post {
            tls.write_all(wire)
                .await
                .map_err(|error| format!("DoH write body: {error}"))?;
        }
        tls.flush().await.map_err(|error| format!("DoH flush: {error}"))?;

        let response = tokio::time::timeout(DOH_TIMEOUT, http::read_http_response(&mut tls))
            .await
            .map_err(|_| "DoH read timeout".to_string())??;
        let (status, body) = http::status_and_decoded_body(&response)?;
        if status != 200 {
            return Err(format!("DoH HTTP {status}"));
        }
        Ok(body)
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

async fn system_lookup(host: &str, port: u16) -> Result<Vec<IpAddr>, String> {
    let target = format!("{host}:{port}");
    let iter = tokio::time::timeout(SYSTEM_LOOKUP_TIMEOUT, tokio::net::lookup_host(target))
        .await
        .map_err(|_| format!("system DNS timeout for {host}"))?
        .map_err(|error| format!("system DNS lookup {host}: {error}"))?;
    let mut ips: Vec<IpAddr> = iter.map(|addr| addr.ip()).collect();
    ips.sort();
    ips.dedup();
    ips.retain(|ip| !ip.is_loopback() && !ip.is_unspecified());
    if ips.is_empty() {
        return Err(format!("system DNS returned no addresses for {host}"));
    }
    Ok(ips)
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
    Ok(DohEndpoint {
        host,
        port,
        path,
        bootstrap,
    })
}

/// Well-known public DoH hosts. Unknown hostnames keep an empty list and are
/// bootstrapped once via system DNS when the gateway starts.
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

fn base64url_nopad(input: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut index = 0;
    while index < input.len() {
        let remaining = input.len() - index;
        let b0 = input[index];
        let b1 = if remaining > 1 { input[index + 1] } else { 0 };
        let b2 = if remaining > 2 { input[index + 2] } else { 0 };
        let triple = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(TABLE[((triple >> 18) & 63) as usize] as char);
        out.push(TABLE[((triple >> 12) & 63) as usize] as char);
        if remaining > 1 {
            out.push(TABLE[((triple >> 6) & 63) as usize] as char);
        }
        if remaining > 2 {
            out.push(TABLE[(triple & 63) as usize] as char);
        }
        index += 3;
    }
    out
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
    fn parses_unknown_hosts_without_bootstrap_mapping() {
        let endpoint = parse_doh_url("https://unknown-doh.example/dns-query").unwrap();
        assert_eq!(endpoint.host, "unknown-doh.example");
        assert_eq!(endpoint.path, "/dns-query");
        assert!(endpoint.bootstrap.is_empty());
        let custom = parse_doh_url("https://jeff-dean.ddd.oaifree.com/query-dns").unwrap();
        assert_eq!(custom.host, "jeff-dean.ddd.oaifree.com");
        assert_eq!(custom.path, "/query-dns");
        assert!(custom.bootstrap.is_empty());
        assert!(parse_doh_url("http://cloudflare-dns.com/dns-query").is_err());
        let alidns = parse_doh_url("https://dns.alidns.com/dns-query").unwrap();
        assert_eq!(alidns.bootstrap[0], IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)));
    }

    #[test]
    fn literal_ip_bootstrap_is_the_host() {
        let endpoint = parse_doh_url("https://1.1.1.1/dns-query").unwrap();
        assert_eq!(endpoint.bootstrap, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
    }

    #[test]
    fn base64url_matches_rfc4648_vectors() {
        assert_eq!(base64url_nopad(b""), "");
        assert_eq!(base64url_nopad(b"f"), "Zg");
        assert_eq!(base64url_nopad(b"fo"), "Zm8");
        assert_eq!(base64url_nopad(b"foo"), "Zm9v");
    }
}

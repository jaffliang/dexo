//! Outbound TLS 1.3. When the `ech` feature is on and the origin published an
//! HTTPS/SVCB ECH config, SNI is encrypted. Otherwise the client hello uses a
//! normal (visible) server_name and still dials the DoH-resolved IP.
//!
//! Cipher suites and key-exchange groups are ordered like Chrome/Safari so
//! Cloudflare is less likely to serve a "Just a moment" HTML interstitial.
//! ALPN stays `http/1.1` only.

use std::sync::Arc;

use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::pki_types::ServerName;
use rustls::{CipherSuite, ClientConfig, NamedGroup, RootCertStore, SupportedCipherSuite};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

pub struct GatewayTls {
    plain: Arc<ClientConfig>,
}

impl GatewayTls {
    pub fn new() -> Self {
        install_provider();
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut plain = client_config(roots, None).expect("plain TLS config");
        plain.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            plain: Arc::new(plain),
        }
    }

    pub fn plain_config(&self) -> Arc<ClientConfig> {
        self.plain.clone()
    }

    /// Visible-SNI handshake on a fresh TCP stream. Uses the same Chrome-like
    /// cipher provider as ECH.
    pub async fn connect_visible_sni(
        &self,
        host: &str,
        stream: TcpStream,
    ) -> Result<TlsStream<TcpStream>, String> {
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| format!("invalid TLS hostname {host}"))?;
        let connector = TlsConnector::from(self.plain.clone());
        connector
            .connect(server_name, stream)
            .await
            .map_err(|error| format!("TLS handshake {host}: {error}"))
    }

    pub async fn connect(
        &self,
        host: &str,
        stream: TcpStream,
        ech_config: Option<&[u8]>,
    ) -> Result<(TlsStream<TcpStream>, bool), String> {
        if let Some(config_list) = ech_config {
            match ech_client_config(config_list) {
                Ok(config) => {
                    let server_name = ServerName::try_from(host.to_string())
                        .map_err(|_| format!("invalid TLS hostname {host}"))?;
                    let connector = TlsConnector::from(config);
                    match connector.connect(server_name, stream).await {
                        Ok(tls) => {
                            eprintln!("[DoHGateway] ECH handshake ok for {host}");
                            return Ok((tls, true));
                        }
                        Err(error) => {
                            // Stream is burned; the caller must open a new TCP
                            // connection and call `connect_visible_sni`.
                            eprintln!("[DoHGateway] ECH handshake failed for {host}: {error}");
                            return Err(error.to_string());
                        }
                    }
                }
                Err(error) => {
                    // Do not handshake visible SNI on this burned-or-unused
                    // stream; the caller retries with a short timeout.
                    return Err(format!("ECH config {host}: {error}"));
                }
            }
        }

        let tls = self.connect_visible_sni(host, stream).await?;
        Ok((tls, false))
    }
}

fn install_provider() {
    let _ = browser_like_provider().install_default();
}

fn client_config(
    roots: RootCertStore,
    ech_mode: Option<rustls::client::EchMode>,
) -> Result<ClientConfig, String> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(browser_like_provider()));

    #[cfg(feature = "ech")]
    if let Some(mode) = ech_mode {
        return Ok(builder
            .with_ech(mode)
            .map_err(|error| error.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth());
    }

    let _ = ech_mode;
    Ok(builder
        .with_safe_default_protocol_versions()
        .map_err(|error| error.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

#[cfg(feature = "ech")]
fn ech_client_config(config_list: &[u8]) -> Result<Arc<ClientConfig>, String> {
    use rustls::client::{EchConfig, EchMode};
    use rustls::pki_types::EchConfigListBytes;

    let ech = EchConfig::new(
        EchConfigListBytes::from(config_list.to_vec()),
        rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
    )
    .map_err(|error| error.to_string())?;
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = client_config(roots, Some(EchMode::Enable(ech)))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

#[cfg(not(feature = "ech"))]
fn ech_client_config(_config_list: &[u8]) -> Result<Arc<ClientConfig>, String> {
    Err("ECH support was not compiled".into())
}

/// rustls defaults put ChaCha ahead of AES-GCM (and aws-lc may offer ML-KEM).
/// Reorder to a Chrome/Safari-like ClientHello: AES-128-GCM, AES-256-GCM,
/// ChaCha20, then TLS 1.2 ECDHE AES-GCM / ChaCha; X25519, P-256, P-384.
fn browser_like_provider() -> CryptoProvider {
    let mut provider = stock_provider();
    provider.cipher_suites = chrome_like_cipher_suites(provider.cipher_suites);
    provider.kx_groups = chrome_like_kx_groups(provider.kx_groups);
    provider
}

fn stock_provider() -> CryptoProvider {
    #[cfg(feature = "ech")]
    {
        rustls::crypto::aws_lc_rs::default_provider()
    }
    #[cfg(not(feature = "ech"))]
    {
        rustls::crypto::ring::default_provider()
    }
}

fn chrome_like_cipher_suites(suites: Vec<SupportedCipherSuite>) -> Vec<SupportedCipherSuite> {
    let mut suites = suites;
    suites.sort_by_key(|suite| cipher_priority(suite.suite()));
    suites
}

fn cipher_priority(suite: CipherSuite) -> u32 {
    match suite {
        CipherSuite::TLS13_AES_128_GCM_SHA256 => 0,
        CipherSuite::TLS13_AES_256_GCM_SHA384 => 1,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 2,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => 10,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => 11,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 12,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => 13,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => 14,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => 15,
        _ => 100,
    }
}

fn chrome_like_kx_groups(
    groups: Vec<&'static dyn SupportedKxGroup>,
) -> Vec<&'static dyn SupportedKxGroup> {
    let preferred = [NamedGroup::X25519, NamedGroup::secp256r1, NamedGroup::secp384r1];
    let ordered: Vec<_> = preferred
        .into_iter()
        .filter_map(|want| groups.iter().copied().find(|group| group.name() == want))
        .collect();
    if ordered.is_empty() {
        groups
    } else {
        ordered
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_like_ciphers_put_aes128_gcm_first() {
        let provider = browser_like_provider();
        assert!(provider.cipher_suites.len() >= 3);
        assert_eq!(
            provider.cipher_suites[0].suite(),
            CipherSuite::TLS13_AES_128_GCM_SHA256
        );
        assert_eq!(
            provider.cipher_suites[1].suite(),
            CipherSuite::TLS13_AES_256_GCM_SHA384
        );
        assert_eq!(
            provider.cipher_suites[2].suite(),
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        );
    }

    #[test]
    fn browser_like_kx_is_x25519_then_nist() {
        let provider = browser_like_provider();
        let names: Vec<NamedGroup> = provider.kx_groups.iter().map(|group| group.name()).collect();
        assert_eq!(names.first().copied(), Some(NamedGroup::X25519));
        assert!(!names.iter().any(|name| matches!(
            name,
            NamedGroup::X25519MLKEM768 | NamedGroup::secp256r1MLKEM768 | NamedGroup::MLKEM768
        )));
    }

    #[cfg(feature = "ech")]
    #[test]
    fn linux_do_https_ech_is_usable() {
        let message = hex(
            "111181800001000100000000056c696e757802646f0000410001c00c004100010000012c0088\
             0001000001000602683302683200040008681410eaac42a63d000500470045fe0d0041b50020\
             0020121ae8bca202378d31efc2e5db4cce83f4a8ed582ec5e043b69e362c42e7ab0f00040001\
             00010012636c6f7564666c6172652d6563682e636f6d00000006002026064700001000000000\
             0000681410ea260647000010000000000000ac42a63d",
        );
        let lookup = crate::dns::decode_lookup(&message, 0x1111).unwrap();
        let ech = lookup.https[0].ech_config.as_ref().expect("ECH present");
        assert!(
            ech_client_config(ech).is_ok(),
            "rustls rejected linux.do ECH: {:?}",
            ech_client_config(ech).err()
        );
    }

    #[cfg(feature = "ech")]
    fn hex(input: &str) -> Vec<u8> {
        let compact: String = input.chars().filter(|ch| !ch.is_whitespace()).collect();
        (0..compact.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&compact[index..index + 2], 16).unwrap())
            .collect()
    }
}

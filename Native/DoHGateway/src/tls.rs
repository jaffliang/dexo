//! Outbound TLS 1.3. When the `ech` feature is on and the origin published an
//! HTTPS/SVCB ECH config, SNI is encrypted. Otherwise the client hello uses a
//! normal (visible) server_name and still dials the DoH-resolved IP.

use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
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

    pub async fn connect(
        &self,
        host: &str,
        stream: TcpStream,
        ech_config: Option<&[u8]>,
    ) -> Result<(TlsStream<TcpStream>, bool), String> {
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| format!("invalid TLS hostname {host}"))?;

        if let Some(config_list) = ech_config {
            match ech_client_config(config_list) {
                Ok(config) => {
                    let connector = TlsConnector::from(config);
                    match connector.connect(server_name.clone(), stream).await {
                        Ok(tls) => {
                            eprintln!("[DoHGateway] ECH handshake ok for {host}");
                            return Ok((tls, true));
                        }
                        Err(error) => {
                            eprintln!(
                                "[DoHGateway] ECH handshake failed for {host}, falling back to visible SNI: {error}"
                            );
                            return Err(error.to_string());
                        }
                    }
                }
                Err(error) => {
                    eprintln!("[DoHGateway] ignoring unusable ECH config for {host}: {error}");
                }
            }
        }

        let connector = TlsConnector::from(self.plain.clone());
        let tls = connector
            .connect(server_name, stream)
            .await
            .map_err(|error| format!("TLS handshake {host}: {error}"))?;
        Ok((tls, false))
    }
}

fn install_provider() {
    #[cfg(feature = "ech")]
    {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
    #[cfg(not(feature = "ech"))]
    {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

fn client_config(
    roots: RootCertStore,
    ech_mode: Option<rustls::client::EchMode>,
) -> Result<ClientConfig, String> {
    let builder = rustls::ClientConfig::builder_with_provider(active_provider().into());

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

fn active_provider() -> rustls::crypto::CryptoProvider {
    #[cfg(feature = "ech")]
    {
        rustls::crypto::aws_lc_rs::default_provider()
    }
    #[cfg(not(feature = "ech"))]
    {
        rustls::crypto::ring::default_provider()
    }
}

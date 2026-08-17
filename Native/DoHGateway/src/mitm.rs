//! Ephemeral MITM CA for the WebView CONNECT listener.
//!
//! The CA is generated at gateway start and exported to iOS so an isolated
//! `WKWebsiteDataStore` can trust leaf certificates. It is never installed
//! in the system trust store.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;

pub struct MitmAuthority {
    ca_der: Vec<u8>,
    ca_cert: Certificate,
    ca_key: KeyPair,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl MitmAuthority {
    pub fn generate() -> Result<Self, String> {
        crate::tls::install_provider();
        let ca_key = KeyPair::generate().map_err(|error| format!("MITM CA key: {error}"))?;
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "Dexo WebView DoH CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "Dexo");
        let ca_cert = params
            .self_signed(&ca_key)
            .map_err(|error| format!("MITM CA cert: {error}"))?;
        let ca_der = ca_cert.der().as_ref().to_vec();
        Ok(Self {
            ca_der,
            ca_cert,
            ca_key,
            leaves: Mutex::new(HashMap::new()),
        })
    }

    pub fn ca_der(&self) -> &[u8] {
        &self.ca_der
    }

    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, String> {
        let key = host.to_ascii_lowercase();
        if let Ok(cache) = self.leaves.lock() {
            if let Some(config) = cache.get(&key) {
                return Ok(config.clone());
            }
        }
        let config = Arc::new(self.sign_leaf(&key)?);
        if let Ok(mut cache) = self.leaves.lock() {
            cache.insert(key, config.clone());
        }
        Ok(config)
    }

    fn sign_leaf(&self, host: &str) -> Result<ServerConfig, String> {
        let dns = host
            .to_string()
            .try_into()
            .map_err(|_| format!("invalid MITM hostname {host}"))?;
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|error| format!("MITM leaf params: {error}"))?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, host);
        params.subject_alt_names = vec![SanType::DnsName(dns)];
        let leaf_key = KeyPair::generate().map_err(|error| format!("MITM leaf key: {error}"))?;
        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(|error| format!("MITM leaf cert: {error}"))?;

        let certs = vec![
            CertificateDer::from(leaf_cert.der().as_ref().to_vec()),
            CertificateDer::from(self.ca_der.clone()),
        ];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|error| format!("MITM server config: {error}"))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::MitmAuthority;

    #[test]
    fn generates_ca_and_leaf_config() {
        use std::sync::Arc;
        let authority = MitmAuthority::generate().expect("ca");
        assert!(!authority.ca_der().is_empty());
        let first = authority.server_config("linux.do").expect("leaf");
        let second = authority.server_config("linux.do").expect("cached");
        assert!(Arc::ptr_eq(&first, &second));
    }
}

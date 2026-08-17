//! Ephemeral MITM CA for the WebView CONNECT listener.
//!
//! The CA is generated at gateway start and exported to iOS so an isolated
//! `WKWebsiteDataStore` can trust leaf certificates. It is never installed
//! in the system trust store.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use time::{Duration, OffsetDateTime};

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
        params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(3650);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        params.use_authority_key_identifier_extension = true;
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
        let (leaf_der, key) = self.sign_leaf_material(host)?;
        let certs = vec![
            CertificateDer::from(leaf_der),
            CertificateDer::from(self.ca_der.clone()),
        ];
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|error| format!("MITM server config: {error}"))?;
        // WebKit MITM speaks HTTP/1.1 only. Do not advertise h2.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(config)
    }

    fn sign_leaf_material(
        &self,
        host: &str,
    ) -> Result<(Vec<u8>, PrivateKeyDer<'static>), String> {
        let dns = host
            .to_string()
            .try_into()
            .map_err(|_| format!("invalid MITM hostname {host}"))?;
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|error| format!("MITM leaf params: {error}"))?;
        params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(365);
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, host);
        params.subject_alt_names = vec![SanType::DnsName(dns)];
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let leaf_key = KeyPair::generate().map_err(|error| format!("MITM leaf key: {error}"))?;
        let leaf_cert = params
            .signed_by(&leaf_key, &self.ca_cert, &self.ca_key)
            .map_err(|error| format!("MITM leaf cert: {error}"))?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        Ok((leaf_cert.der().as_ref().to_vec(), key))
    }
}

#[cfg(test)]
mod tests {
    use super::MitmAuthority;

    /// id-kp-serverAuth
    const SERVER_AUTH_OID: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    /// id-ce-keyUsage
    const KEY_USAGE_OID: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x0f];
    /// id-ce-basicConstraints
    const BASIC_CONSTRAINTS_OID: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x13];
    /// id-ce-subjectAltName
    const SAN_OID: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];

    fn contains_oid(der: &[u8], oid: &[u8]) -> bool {
        der.windows(oid.len()).any(|window| window == oid)
    }

    #[test]
    fn generates_ca_and_leaf_config() {
        use std::sync::Arc;
        let authority = MitmAuthority::generate().expect("ca");
        assert!(!authority.ca_der().is_empty());
        assert!(contains_oid(authority.ca_der(), BASIC_CONSTRAINTS_OID));
        assert!(contains_oid(authority.ca_der(), KEY_USAGE_OID));
        let first = authority.server_config("linux.do").expect("leaf");
        let second = authority.server_config("linux.do").expect("cached");
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.alpn_protocols, [b"http/1.1".to_vec()]);
        assert!(!first.alpn_protocols.iter().any(|proto| proto == b"h2"));
    }

    #[test]
    fn leaf_has_server_auth_eku_and_san() {
        let authority = MitmAuthority::generate().expect("ca");
        let (leaf, _) = authority.sign_leaf_material("cdk.linux.do").expect("leaf");
        assert!(contains_oid(&leaf, SERVER_AUTH_OID), "leaf missing serverAuth EKU");
        assert!(contains_oid(&leaf, SAN_OID), "leaf missing SAN");
        assert!(
            leaf.windows(b"cdk.linux.do".len())
                .any(|window| window == b"cdk.linux.do"),
            "leaf SAN/CN missing host"
        );
    }
}

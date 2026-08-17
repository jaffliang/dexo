//! Ephemeral MITM CA for the WebView CONNECT listener.
//!
//! The CA is generated at gateway start and exported to iOS so an isolated
//! `WKWebsiteDataStore` can trust leaf certificates. It is never installed
//! in the system trust store.
//!
//! Field layout matches `WebViewProxyX509Builder` (the iOS 17 Swift CA):
//! CA has keyCertSign+cRLSign; leaf has SAN + EKU serverAuth + a short life.
//! `CertificateParams::default()` is illegal on iOS 13+ (not_before 1975,
//! not_after 4096, empty KU/EKU) and can make the Network process hard-fail
//! with -1200 *before* `didReceive` runs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use time::{Duration, OffsetDateTime};

/// Mirror the Swift leaf: `now - 1 day` … `now + 7 days` (must stay ≤ 825).
const LEAF_NOT_AFTER_DAYS: i64 = 7;
/// Mirror the Swift CA: about 20 years.
const CA_NOT_AFTER_DAYS: i64 = 20 * 365;

pub struct MitmAuthority {
    ca_der: Vec<u8>,
    ca_cert: Certificate,
    ca_key: KeyPair,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

fn apply_ios_validity(params: &mut CertificateParams, not_after_days: i64) {
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(not_after_days);
}

impl MitmAuthority {
    pub fn generate() -> Result<Self, String> {
        crate::tls::install_provider();
        let ca_key = KeyPair::generate().map_err(|error| format!("MITM CA key: {error}"))?;
        let mut params = CertificateParams::default();
        apply_ios_validity(&mut params, CA_NOT_AFTER_DAYS);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        // Swift CA KU bits are keyCertSign+cRLSign only (0x06). Do not add
        // DigitalSignature — that is a leaf usage.
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.extended_key_usages.clear();
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
        apply_ios_validity(&mut params, LEAF_NOT_AFTER_DAYS);
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
    use time::OffsetDateTime;

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
        assert!(contains_oid(&leaf, KEY_USAGE_OID), "leaf missing keyUsage");
        assert!(
            leaf.windows(b"cdk.linux.do".len())
                .any(|window| window == b"cdk.linux.do"),
            "leaf SAN/CN missing host"
        );
    }

    #[test]
    fn ca_and_leaf_reject_rcgen_default_validity() {
        let authority = MitmAuthority::generate().expect("ca");
        let (leaf, _) = authority.sign_leaf_material("linux.do").expect("leaf");
        assert_no_rcgen_default_dates(authority.ca_der());
        assert_no_rcgen_default_dates(&leaf);
        assert!(
            !contains_oid(authority.ca_der(), SERVER_AUTH_OID),
            "CA must not carry serverAuth EKU"
        );
        let leaf_span = validity_span_days(&leaf);
        assert!(
            leaf_span > 0.0 && leaf_span <= 825.0,
            "leaf life {leaf_span}d must be ≤ 825 days"
        );
        assert!(
            (7.0..9.0).contains(&leaf_span),
            "leaf life {leaf_span}d should be ~8 days (now-1d … now+7d)"
        );
    }

    /// rcgen Default writes not_before=1975-01-01 and not_after=4096-01-01.
    /// Those years encode as UTCTime `750101000000Z` / GeneralizedTime
    /// `19750101000000Z` and `40960101000000Z`.
    fn assert_no_rcgen_default_dates(der: &[u8]) {
        for needle in [
            b"750101000000Z" as &[u8],
            b"19750101000000Z",
            b"40960101000000Z",
        ] {
            assert!(
                !der.windows(needle.len()).any(|window| window == needle),
                "DER still contains rcgen Default date {}",
                String::from_utf8_lossy(needle)
            );
        }
    }

    fn validity_span_days(der: &[u8]) -> f64 {
        let times = asn1_times(der);
        assert!(
            times.len() >= 2,
            "expected not_before/not_after, found {times:?}"
        );
        let start = parse_asn1_time(&times[0]);
        let end = parse_asn1_time(&times[1]);
        (end - start).as_seconds_f64() / 86_400.0
    }

    fn asn1_times(der: &[u8]) -> Vec<String> {
        let mut times = Vec::new();
        let mut index = 0;
        while index + 2 < der.len() {
            let tag = der[index];
            if tag != 0x17 && tag != 0x18 {
                index += 1;
                continue;
            }
            let length = der[index + 1] as usize;
            let start = index + 2;
            let end = start + length;
            if length < 0x80 && end <= der.len() {
                if let Ok(text) = std::str::from_utf8(&der[start..end]) {
                    if text.ends_with('Z') && text.bytes().take(text.len() - 1).all(|b| b.is_ascii_digit())
                    {
                        times.push(text.to_string());
                        index = end;
                        continue;
                    }
                }
            }
            index += 1;
        }
        times
    }

    fn parse_asn1_time(value: &str) -> OffsetDateTime {
        let (year, rest) = if value.len() == 13 {
            let yy: i32 = value[..2].parse().expect("utc year");
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &value[2..])
        } else if value.len() == 15 {
            (value[..4].parse().expect("gen year"), &value[4..])
        } else {
            panic!("unsupported ASN.1 time {value}");
        };
        let month: u8 = rest[..2].parse().expect("month");
        let day: u8 = rest[2..4].parse().expect("day");
        let hour: u8 = rest[4..6].parse().expect("hour");
        let minute: u8 = rest[6..8].parse().expect("minute");
        let second: u8 = rest[8..10].parse().expect("second");
        time::Date::from_calendar_date(year, time::Month::try_from(month).expect("month"), day)
            .expect("date")
            .with_hms(hour, minute, second)
            .expect("time")
            .assume_utc()
    }
}

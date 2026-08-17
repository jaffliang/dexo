//! Host split for the WebView CONNECT listener.
//!
//! Turnstile / hCaptcha must see real Safari TLS (JA3). MITM with rustls
//! on `challenges.cloudflare.com` makes the checkbox never appear.
//! Forum hosts (linux.do, idcflare, cdk.linux.do, …) are MITM'd so the
//! outbound hop can use ECH and hide SNI.

pub fn should_passthrough_tls(host: &str) -> bool {
    let host = host.trim().trim_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    host == "challenges.cloudflare.com"
        || host.ends_with(".challenges.cloudflare.com")
        || host == "hcaptcha.com"
        || host.ends_with(".hcaptcha.com")
}

#[cfg(test)]
mod tests {
    use super::should_passthrough_tls;

    #[test]
    fn turnstile_and_hcaptcha_are_passthrough() {
        assert!(should_passthrough_tls("challenges.cloudflare.com"));
        assert!(should_passthrough_tls("CHALLENGES.CLOUDFLARE.COM"));
        assert!(should_passthrough_tls("api.hcaptcha.com"));
        assert!(should_passthrough_tls("hcaptcha.com"));
        assert!(should_passthrough_tls("newassets.hcaptcha.com"));
    }

    #[test]
    fn forum_and_unrelated_hosts_are_mitm() {
        assert!(!should_passthrough_tls("linux.do"));
        assert!(!should_passthrough_tls("cdk.linux.do"));
        assert!(!should_passthrough_tls("idcflare.com"));
        assert!(!should_passthrough_tls("cloudflare.com"));
        assert!(!should_passthrough_tls("cloudflare-dns.com"));
        assert!(!should_passthrough_tls(""));
    }
}

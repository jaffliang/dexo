# DoH loopback gateway (Rust)

App-local loopback gateway used by Dexo on iOS 15+. Two listeners:

- **HTTP reverse-proxy** — URLSession / Alamofire / SDWebImage. Unchanged.
- **CONNECT** — isolated WKWebView stores only (challenge, in-app browser,
  password-login). Never attached to `WKWebsiteDataStore.default()` or the
  shared cookie jar.

## What it does

1. Binds two `127.0.0.1` ports (ephemeral by default).
2. HTTP listener: reads plaintext HTTP/1.1 from the app (`X-Dexo-Gateway-Host`
   etc.). CONNECT on this port is still rejected.
3. Resolves the origin over DNS-over-HTTPS. Known DoH hosts dial a hardcoded
   **bootstrap IP**. Custom DoH hostnames are resolved **once at start** via
   system DNS (getaddrinfo), then all forum lookups go over DoH.
4. Opens outbound TLS 1.3 to that IP:
   - **ECH** when the origin’s HTTPS/SVCB record includes an `ech` config and
     this crate is built with `--features ech` (default).
   - Otherwise **visible SNI** + connect-by-IP.
5. CONNECT listener, per `Host`:
   - `challenges.cloudflare.com` / `*.hcaptcha.com`: DoH-resolve, then a raw
     byte tunnel so WebKit does end-to-end Safari TLS (Turnstile).
   - Other WebView hosts: local MITM + the same ECH rustls outbound (hide SNI).
     The ephemeral MITM CA is exported to iOS and is not installed in the
     system trust store.

The HTTP reverse-proxy path has no MITM. One TLS hop, from this process to
the origin.

## Rebuild

Requires Rust 1.85+, cmake, libclang (Xcode or Homebrew `llvm`), and Xcode.
`aws-lc-rs` is built with the `bindgen` feature so `aarch64-apple-ios`
bindings can be generated. The script **fails** if ECH does not compile.

```bash
# From the repository root, on a Mac with Xcode:
./scripts/build-doh-gateway.sh
```

CI runs the same script before `xcodebuild`. Outputs:

- `dist/iphoneos/libdexo_doh_gateway.a`
- `dist/iphonesimulator/libdexo_doh_gateway.a` (when the simulator SDK exists)

## Tests

```bash
cd Native/DoHGateway
cargo test
```

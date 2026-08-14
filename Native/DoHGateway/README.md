# DoH loopback gateway (Rust)

App-local HTTP listener used by Dexo on iOS 15+ for URLSession / Alamofire
forum API traffic. WKWebView is not attached to this proxy.

## What it does

1. Binds `127.0.0.1` (ephemeral port by default).
2. Reads plaintext HTTP/1.1 from the app (`X-Dexo-Gateway-Host` etc.).
3. Resolves the origin over DNS-over-HTTPS. Known DoH hosts dial a hardcoded
   **bootstrap IP**. Custom DoH hostnames are resolved **once at start** via
   system DNS (getaddrinfo), then all forum lookups go over DoH.
4. Opens outbound TLS 1.3 to that IP:
   - **ECH** when the origin’s HTTPS/SVCB record includes an `ech` config and
     this crate is built with `--features ech` (default).
   - Otherwise **visible SNI** + connect-by-IP.

There is no MITM CA on this path. One TLS hop, from this process to the origin.

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

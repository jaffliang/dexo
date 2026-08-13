#!/usr/bin/env bash
# Cross-compiles libdexo_doh_gateway.a for iOS device (and simulator when the
# SDK is present). Used by GitHub Actions before xcodebuild so the Tuist app
# can link the static library without a developer Mac.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRATE="$ROOT/Native/DoHGateway"
DIST="$CRATE/dist"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Skipping iOS DoH gateway static library (not macOS)."
  exit 0
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "error: cargo is required to build Native/DoHGateway" >&2
  echo "Install Rust from https://rustup.rs and re-run $0" >&2
  exit 1
fi

if ! command -v xcrun >/dev/null 2>&1; then
  echo "error: xcrun/Xcode is required to build the iOS static library" >&2
  exit 1
fi

if ! command -v cmake >/dev/null 2>&1; then
  echo "warning: cmake not on PATH; aws-lc-rs (ECH) may fail to compile" >&2
fi

export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.0}"

cd "$CRATE"
rustup show >/dev/null
rustup target add aarch64-apple-ios
if xcrun --sdk iphonesimulator --show-sdk-path >/dev/null 2>&1; then
  rustup target add aarch64-apple-ios-sim || true
fi

copy_lib() {
  local triple="$1"
  local dest="$2"
  mkdir -p "$dest"
  cp "$CRATE/target/${triple}/release/libdexo_doh_gateway.a" "$dest/libdexo_doh_gateway.a"
}

build_target() {
  local triple="$1"
  local dest="$2"
  echo "Building dexo_doh_gateway for ${triple} with ECH"
  if cargo build --release --target "$triple" --features ech; then
    copy_lib "$triple" "$dest"
    return 0
  fi
  echo "warning: ECH (aws-lc-rs) build failed for ${triple}; retrying without ECH" >&2
  cargo build --release --target "$triple" --no-default-features
  copy_lib "$triple" "$dest"
}

build_target aarch64-apple-ios "$DIST/iphoneos"

if xcrun --sdk iphonesimulator --show-sdk-path >/dev/null 2>&1; then
  build_target aarch64-apple-ios-sim "$DIST/iphonesimulator" || {
    echo "warning: simulator library was not built" >&2
  }
fi

echo "DoH gateway libraries:"
ls -l "$DIST"/iphoneos/libdexo_doh_gateway.a
ls -l "$DIST"/iphonesimulator/libdexo_doh_gateway.a 2>/dev/null || true

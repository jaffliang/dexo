#!/usr/bin/env bash
# Cross-compiles libdexo_doh_gateway.a for iOS device (and simulator when the
# SDK is present). ECH (aws-lc-rs) is required: this script must not fall
# back to ring / visible-SNI-only.
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
  if command -v brew >/dev/null 2>&1; then
    echo "Installing cmake (required for aws-lc-rs ECH)"
    brew install cmake
  fi
fi
if ! command -v cmake >/dev/null 2>&1; then
  echo "error: cmake is required to compile aws-lc-rs ECH for iOS" >&2
  exit 1
fi

export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.0}"

ensure_libclang() {
  if [[ -n "${LIBCLANG_PATH:-}" && -e "${LIBCLANG_PATH}/libclang.dylib" ]]; then
    return 0
  fi
  local xcode_lib
  xcode_lib="$(xcode-select -p)/Toolchains/XcodeDefault.xctoolchain/usr/lib"
  if [[ -e "${xcode_lib}/libclang.dylib" ]]; then
    export LIBCLANG_PATH="$xcode_lib"
    echo "Using Xcode libclang at ${LIBCLANG_PATH}"
    return 0
  fi
  if command -v brew >/dev/null 2>&1; then
    if [[ ! -e "$(brew --prefix llvm 2>/dev/null)/lib/libclang.dylib" ]]; then
      echo "Installing Homebrew llvm (libclang for aws-lc-sys bindgen)"
      brew install llvm
    fi
    export LIBCLANG_PATH="$(brew --prefix llvm)/lib"
    export PATH="$(brew --prefix llvm)/bin:${PATH}"
    echo "Using Homebrew libclang at ${LIBCLANG_PATH}"
  fi
  if [[ ! -e "${LIBCLANG_PATH:-}/libclang.dylib" ]]; then
    echo "error: libclang not found; aws-lc-sys bindgen cannot generate aarch64-apple-ios bindings" >&2
    exit 1
  fi
}

prepare_ios_ech_env() {
  local triple="$1"
  local sdk
  local clang_target
  local min_flag
  case "$triple" in
    aarch64-apple-ios)
      sdk="$(xcrun --sdk iphoneos --show-sdk-path)"
      clang_target="arm64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET}"
      min_flag="-miphoneos-version-min=${IPHONEOS_DEPLOYMENT_TARGET}"
      ;;
    aarch64-apple-ios-sim)
      sdk="$(xcrun --sdk iphonesimulator --show-sdk-path)"
      clang_target="arm64-apple-ios${IPHONEOS_DEPLOYMENT_TARGET}-simulator"
      min_flag="-mios-simulator-version-min=${IPHONEOS_DEPLOYMENT_TARGET}"
      ;;
    *)
      echo "error: unsupported triple ${triple}" >&2
      exit 1
      ;;
  esac
  if [[ -z "$sdk" || ! -d "$sdk" ]]; then
    echo "error: missing iOS SDK for ${triple}" >&2
    exit 1
  fi

  local env_suffix
  env_suffix="$(printf '%s' "$triple" | tr '-' '_')"
  local clang_args="--target=${clang_target} -isysroot ${sdk} ${min_flag}"
  export "BINDGEN_EXTRA_CLANG_ARGS_${env_suffix}=${clang_args}"
  export BINDGEN_EXTRA_CLANG_ARGS="${clang_args}"
  export CMAKE_OSX_SYSROOT="$sdk"
  export SDKROOT="$sdk"
  echo "bindgen ${env_suffix}: ${clang_args}"
}

ensure_libclang

cd "$CRATE"
rustup show >/dev/null
rustup target add aarch64-apple-ios
if xcrun --sdk iphonesimulator --show-sdk-path >/dev/null 2>&1; then
  rustup target add aarch64-apple-ios-sim
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
  prepare_ios_ech_env "$triple"
  echo "Building dexo_doh_gateway for ${triple} with ECH (required)"
  cargo build --release --target "$triple" --features ech
  copy_lib "$triple" "$dest"
}

build_target aarch64-apple-ios "$DIST/iphoneos"

if xcrun --sdk iphonesimulator --show-sdk-path >/dev/null 2>&1; then
  build_target aarch64-apple-ios-sim "$DIST/iphonesimulator"
fi

echo "DoH gateway libraries:"
ls -l "$DIST"/iphoneos/libdexo_doh_gateway.a
ls -l "$DIST"/iphonesimulator/libdexo_doh_gateway.a 2>/dev/null || true

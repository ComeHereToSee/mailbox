#!/usr/bin/env bash
# Builds libmailcore.a for the macOS app (universal arm64 + x86_64 by default).
#   ARCHS="arm64" scripts/build-core-macos.sh   # faster local build for Apple silicon only
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARCHS="${ARCHS:-arm64 x86_64}"
PROFILE="${PROFILE:-release}"
export MACOSX_DEPLOYMENT_TARGET=14.0

cd "$ROOT/core"
libs=()
for arch in $ARCHS; do
  case "$arch" in
    arm64) target=aarch64-apple-darwin ;;
    x86_64) target=x86_64-apple-darwin ;;
    *) echo "unknown arch $arch" >&2; exit 1 ;;
  esac
  rustup target add "$target" >/dev/null 2>&1 || true
  cargo build --profile "$PROFILE" -p mailcore-ffi --target "$target"
  libs+=("target/$target/$PROFILE/libmailcore.a")
done
mkdir -p "$ROOT/macos/Vendor"
lipo -create "${libs[@]}" -output "$ROOT/macos/Vendor/libmailcore.a"
lipo -info "$ROOT/macos/Vendor/libmailcore.a"

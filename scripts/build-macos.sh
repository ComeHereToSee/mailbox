#!/usr/bin/env bash
# Builds Mailbox.app (ad-hoc signed) and dist/Mailbox.dmg.
# Requirements: Xcode 16+, Rust (rustup), XcodeGen (brew install xcodegen).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="${CONFIG:-Release}"

"$ROOT/scripts/build-core-macos.sh"

cd "$ROOT/macos"
xcodegen generate --quiet
DERIVED="$ROOT/macos/build/DerivedData"
xcodebuild -project Mailbox.xcodeproj -scheme Mailbox -configuration "$CONFIG" \
  -derivedDataPath "$DERIVED" \
  CODE_SIGN_IDENTITY="-" CODE_SIGN_STYLE=Manual DEVELOPMENT_TEAM="" \
  ONLY_ACTIVE_ARCH=NO \
  build | tee "$ROOT/macos/build/xcodebuild.log" | grep -E "error:|warning: .*deprecated|\*\* BUILD" || true
test "${PIPESTATUS[0]}" -eq 0

APP="$DERIVED/Build/Products/$CONFIG/Mailbox.app"
test -d "$APP/Contents/Library/LoginItems/MailboxHelper.app"
codesign --verify --deep --strict "$APP" && echo "signature ok"

mkdir -p "$ROOT/dist"
STAGE="$(mktemp -d)"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
rm -f "$ROOT/dist/Mailbox.dmg"
hdiutil create -volname "Mailbox" -srcfolder "$STAGE" -ov -format UDZO "$ROOT/dist/Mailbox.dmg" >/dev/null
rm -rf "$STAGE"
du -h "$ROOT/dist/Mailbox.dmg"
echo "Built $APP"

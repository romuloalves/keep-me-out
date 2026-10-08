#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1090
  source "$HOME/.cargo/env"
fi

cargo build --release
swift build -c release

BIN_DIR="$(swift build -c release --show-bin-path)"
APP="dist/Keep Me Out.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "target/release/keep-me-out" "$APP/Contents/MacOS/keep-me-out"
cp "$BIN_DIR/KeepMeOut" "$APP/Contents/MacOS/Keep Me Out"
cp Info.plist "$APP/Contents/Info.plist"
chmod +x "$APP/Contents/MacOS/keep-me-out" "$APP/Contents/MacOS/Keep Me Out"
codesign --force --sign - "$APP/Contents/MacOS/keep-me-out"
codesign --force --sign - "$APP/Contents/MacOS/Keep Me Out"
codesign --force --sign - "$APP"
echo "Built $APP"

#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP_NAME="PuppyTerm"
APP_DIR="$ROOT_DIR/build/macos/${APP_NAME}.app"
CONTENTS_DIR="$APP_DIR/Contents"
MACOS_DIR="$CONTENTS_DIR/MacOS"
RESOURCES_DIR="$CONTENTS_DIR/Resources"
BIN_PATH="$ROOT_DIR/target/debug/puppyterm"

cd "$ROOT_DIR"

cargo build --offline

rm -rf "$APP_DIR"
mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"

cp "$BIN_PATH" "$MACOS_DIR/$APP_NAME"
cp "$ROOT_DIR/assets/puppyterm.png" "$RESOURCES_DIR/puppyterm.png"

cat > "$CONTENTS_DIR/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>PuppyTerm</string>
  <key>CFBundleDisplayName</key>
  <string>PuppyTerm</string>
  <key>CFBundleExecutable</key>
  <string>PuppyTerm</string>
  <key>CFBundleIdentifier</key>
  <string>com.puppyterm.app</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>CFBundleShortVersionString</key>
  <string>0.1.0</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST

echo "Built $APP_DIR"
echo "Launch with: open \"$APP_DIR\""

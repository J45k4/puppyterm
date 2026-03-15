#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:?target triple required}"
OUT_DIR="${2:-$ROOT_DIR/dist}"
VERSION="${VERSION:-$(sed -n 's/^version = \"\\(.*\\)\"/\\1/p' "$ROOT_DIR/Cargo.toml" | head -n 1)}"

mkdir -p "$OUT_DIR"
cd "$ROOT_DIR"

cargo build --release --target "$TARGET"

case "$TARGET" in
  aarch64-apple-darwin)
    ASSET_NAME="PuppyTerm-macos-aarch64.zip"
    BIN_PATH="$ROOT_DIR/target/$TARGET/release/puppyterm"
    STAGE_DIR="$ROOT_DIR/target/$TARGET/package"
    APP_DIR="$STAGE_DIR/PuppyTerm.app"
    CONTENTS_DIR="$APP_DIR/Contents"
    MACOS_DIR="$CONTENTS_DIR/MacOS"
    RESOURCES_DIR="$CONTENTS_DIR/Resources"
    rm -rf "$STAGE_DIR"
    mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"
    cp "$BIN_PATH" "$MACOS_DIR/PuppyTerm"
    cp "$ROOT_DIR/assets/puppyterm.png" "$RESOURCES_DIR/puppyterm.png"
    /bin/cat > "$CONTENTS_DIR/Info.plist" <<PLIST
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
  <string>$VERSION</string>
  <key>CFBundleShortVersionString</key>
  <string>$VERSION</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST
    rm -f "$OUT_DIR/$ASSET_NAME"
    ditto -c -k --keepParent "$APP_DIR" "$OUT_DIR/$ASSET_NAME"
    ;;
  x86_64-apple-darwin)
    ASSET_NAME="PuppyTerm-macos-x86_64.zip"
    BIN_PATH="$ROOT_DIR/target/$TARGET/release/puppyterm"
    STAGE_DIR="$ROOT_DIR/target/$TARGET/package"
    APP_DIR="$STAGE_DIR/PuppyTerm.app"
    CONTENTS_DIR="$APP_DIR/Contents"
    MACOS_DIR="$CONTENTS_DIR/MacOS"
    RESOURCES_DIR="$CONTENTS_DIR/Resources"
    rm -rf "$STAGE_DIR"
    mkdir -p "$MACOS_DIR" "$RESOURCES_DIR"
    cp "$BIN_PATH" "$MACOS_DIR/PuppyTerm"
    cp "$ROOT_DIR/assets/puppyterm.png" "$RESOURCES_DIR/puppyterm.png"
    /bin/cat > "$CONTENTS_DIR/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0.dtd">
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
  <string>$VERSION</string>
  <key>CFBundleShortVersionString</key>
  <string>$VERSION</string>
  <key>NSHighResolutionCapable</key>
  <true/>
</dict>
</plist>
PLIST
    rm -f "$OUT_DIR/$ASSET_NAME"
    ditto -c -k --keepParent "$APP_DIR" "$OUT_DIR/$ASSET_NAME"
    ;;
  x86_64-unknown-linux-gnu)
    ASSET_NAME="PuppyTerm-linux-x86_64.zip"
    BIN_PATH="$ROOT_DIR/target/$TARGET/release/puppyterm"
    STAGE_DIR="$ROOT_DIR/target/$TARGET/package"
    APP_ROOT="$STAGE_DIR/PuppyTerm"
    rm -rf "$STAGE_DIR"
    mkdir -p "$APP_ROOT/assets"
    cp "$BIN_PATH" "$APP_ROOT/PuppyTerm"
    cp "$ROOT_DIR/assets/puppyterm.png" "$APP_ROOT/assets/puppyterm.png"
    rm -f "$OUT_DIR/$ASSET_NAME"
    python3 -m zipfile -c "$OUT_DIR/$ASSET_NAME" "$APP_ROOT"
    ;;
  *)
    echo "Unsupported target: $TARGET" >&2
    exit 1
    ;;
esac

echo "$OUT_DIR/$ASSET_NAME"

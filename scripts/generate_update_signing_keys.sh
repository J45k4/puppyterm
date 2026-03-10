#!/bin/zsh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PUBLIC_KEY_PATH="$ROOT_DIR/update_signature_public_key.txt"
PRIVATE_KEY_PATH="$ROOT_DIR/update_signature_private_key.txt"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to generate the update signing key." >&2
  exit 1
fi

PRIVATE_KEY_B64="$(openssl rand -base64 32 | tr -d '\n')"
PUBLIC_KEY_B64="$(
  cd "$ROOT_DIR"
  cargo run --quiet --bin derive_update_public_key -- "$PRIVATE_KEY_B64"
)"

printf '%s\n' "$PUBLIC_KEY_B64" > "$PUBLIC_KEY_PATH"
printf '%s\n' "$PRIVATE_KEY_B64" > "$PRIVATE_KEY_PATH"

cat <<EOF
# Wrote the private signing key to:
# $PRIVATE_KEY_PATH
#
# Wrote the matching public key to:
# $PUBLIC_KEY_PATH
#
# Store this as the GitHub Actions secret:
UPDATE_SIGNING_KEY=$PRIVATE_KEY_B64
EOF

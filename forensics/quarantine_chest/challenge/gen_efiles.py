#!/usr/bin/env python3
# Generate the 7 encrypted E:\ files (the ransomware's output). One (recovery_codes.txt)
# carries the flag. Crypto = the sample's profile: AES-128-CBC, PKCS7, zero IV,
# key = CryptDeriveKey(MD5("")) = MD5(""). FLAG overridable via env.
import hashlib, os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

FLAG = os.environ.get("FLAG", "H7CTF{750b6f18160c332f9f2b}")
KEY = hashlib.md5(b"").digest()
IV = b"\x00" * 16


def enc(pt):
    return AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(pt, 16))


FILES = {
    "Q3_financials.xlsx": b"PK\x03\x04...spreadsheet: revenue 4.1M, treasury reconciliation notes...\n",
    "board_minutes.docx": b"PK\x03\x04...minutes: acquisition of Meridian discussed under NDA...\n",
    "id_scan_cfo.png": b"\x89PNG\r\n\x1a\n...scanned identity document, CFO...\n",
    "wallet.dat": b"\x01\x00...bitcoin core wallet, keypool...\n",
    "master_password.kdbx": b"\x03\xd9\xa2\x9ag\xfbK\xb5...keepass db...\n",
    "recovery_codes.txt": ("2FA recovery codes\n" +
                           "\n".join(f"{i:05d}-{i*7%100000:05d}" for i in range(8)) +
                           f"\nvault-recovery: {FLAG}\n").encode(),
    "server_key.pem": b"-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----\n",
}

if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    out = os.path.join(here, "E_encrypted")
    os.makedirs(out, exist_ok=True)
    for name, data in FILES.items():
        open(os.path.join(out, name + ".enc"), "wb").write(enc(data))
    print("wrote", len(FILES), "encrypted files; flag in recovery_codes.txt.enc")

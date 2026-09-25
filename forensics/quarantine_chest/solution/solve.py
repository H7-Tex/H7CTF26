#!/usr/bin/env python3
# Reference solution for the quarantine chain (3 stages).
#   1. Avast chest: recover the 16 KB XOR key from aswntsqlite.dll (find it via the SQLite-
#      magic XOR of the encrypted vault.db header), XOR-decrypt vault.db, carve the quarantined
#      sample stream (ProtonVPN_x64final.exe) via the vault/crossRef/stream JOIN.
#   2. RE the carved PE: its CryptoAPI calls (CryptCreateHash CALG_MD5 over ""; CryptDeriveKey
#      CALG_AES_128; CBC + zero IV) reveal the profile: AES-128-CBC, PKCS7, zero IV,
#      key = CryptDeriveKey(MD5("")) = MD5("") (keylen==hashlen).
#   3. Decrypt the 7 encrypted E:\ files with that profile; the flag is in recovery_codes.txt.
import os, sys, glob, sqlite3, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ROOT = sys.argv[1] if len(sys.argv) > 1 else "../challenge/chest_root"
E_ENC = sys.argv[2] if len(sys.argv) > 2 else "../challenge/E_encrypted"
MAGIC = b"SQLite format 3\x00"


def stage1_carve_sample(root):
    dll = open(glob.glob(f"{root}/**/aswntsqlite.dll", recursive=True)[0], "rb").read()
    enc = open(glob.glob(f"{root}/**/vault.db", recursive=True)[0], "rb").read()
    prefix = bytes(enc[i] ^ MAGIC[i] for i in range(16))     # key prefix from the header
    off = dll.find(prefix)
    key = dll[off:off + 16384]                               # lift the full 16 KB key
    clear = bytes(enc[i] ^ key[i % 16384] for i in range(len(enc)))
    tmp = "/tmp/_vault.db"
    open(tmp, "wb").write(clear)
    db = sqlite3.connect(tmp)
    row = db.execute("SELECT data FROM vault INNER JOIN crossRef ON id=crossRef.vaultid "
                     "INNER JOIN stream ON crossRef.streamId=stream.streamId "
                     "WHERE filename LIKE '%ProtonVPN%'").fetchone()
    return row[0]


def stage3_decrypt(e_enc):
    key = hashlib.md5(b"").digest()          # from RE'ing the sample (CryptDeriveKey(MD5("")))
    iv = b"\x00" * 16
    for path in sorted(glob.glob(f"{e_enc}/*.enc")):
        pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(open(path, "rb").read()), 16)
        if b"H7CTF{" in pt:
            import re
            return re.search(rb"H7CTF\{[^}]+\}", pt).group(0).decode(), os.path.basename(path)
    return None, None


def main():
    sample = stage1_carve_sample(ROOT)
    assert sample[:2] == b"MZ", "carved sample is not a PE"
    print(f"[1] carved quarantined sample: {len(sample)} bytes, PE ok")
    print("[2] RE profile: AES-128-CBC / PKCS7 / zero IV / key = MD5(\"\")")
    flag, where = stage3_decrypt(E_ENC)
    print(f"[3] recovered 7 files; flag in {where}")
    print("FLAG:", flag)


if __name__ == "__main__":
    main()

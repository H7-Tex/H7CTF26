import sys, os
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "challenge"))
from aes_sbox import SBOX, HW


def cpa_key(traces, pts):
    sb = np.frombuffer(SBOX, dtype=np.uint8)
    tc = traces - traces.mean(0)
    tvar = np.einsum("ij,ij->j", tc, tc)
    key = bytearray(16)
    for i in range(16):
        best_k, best_c = 0, -1.0
        col = pts[:, i]
        for k in range(256):
            pred = HW[sb[col ^ k]]
            pred = pred - pred.mean()
            denom = np.sqrt((pred @ pred) * tvar) + 1e-12
            c = np.abs((pred @ tc) / denom).max()
            if c > best_c:
                best_c, best_k = c, k
        key[i] = best_k
    return bytes(key)


def solve(d):
    traces = np.load(os.path.join(d, "traces.npy")).astype(np.float64)
    pts = np.load(os.path.join(d, "plaintexts.npy")).astype(np.uint8)
    ct = open(os.path.join(d, "secret.enc"), "rb").read()
    key = cpa_key(traces, pts)
    try:
        flag = unpad(AES.new(key, AES.MODE_ECB).decrypt(ct), 16).decode(errors="replace")
    except Exception:
        return None, key
    return flag, key


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    flag, key = solve(d)
    print(f"[solve] key = {key.hex()}")
    print(f"[solve] FLAG = {flag}" if flag else "[solve] key recovered but decrypt failed")


if __name__ == "__main__":
    main()

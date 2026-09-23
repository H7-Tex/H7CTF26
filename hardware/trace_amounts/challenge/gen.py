import os, sys, secrets
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from aes_sbox import SBOX, HW

N = 500
T = 700
LEAK = 0.7
NOISE = 1.0


def make_challenge(flag, seed=None):
    rng = np.random.default_rng(seed)
    key = rng.integers(0, 256, 16, dtype=np.uint8)
    pts = rng.integers(0, 256, (N, 16), dtype=np.uint8)
    traces = rng.standard_normal((N, T)) * NOISE
    # a little correlated background activity for realism
    traces += 0.3 * np.sin(np.linspace(0, 12 * np.pi, T))[None, :]
    sb = np.frombuffer(SBOX, dtype=np.uint8)
    for i in range(16):
        t_i = 30 + i * 40
        inter = sb[pts[:, i] ^ key[i]]
        traces[:, t_i] += HW[inter] * LEAK
    ct = AES.new(bytes(key), AES.MODE_ECB).encrypt(pad(flag.encode(), 16))
    return traces.astype(np.float32), pts, bytes(key), ct


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(outdir, exist_ok=True)
    flag = os.environ.get("FLAG", "H7CTF{trace_amounts_test}")
    traces, pts, key, ct = make_challenge(flag)
    np.save(os.path.join(outdir, "traces.npy"), traces)
    np.save(os.path.join(outdir, "plaintexts.npy"), pts)
    with open(os.path.join(outdir, "secret.enc"), "wb") as f:
        f.write(ct)
    print(f"[gen] wrote traces.npy ({traces.shape}), plaintexts.npy, secret.enc")


if __name__ == "__main__":
    main()

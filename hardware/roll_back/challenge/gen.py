import os, sys, hashlib
import numpy as np
from proto import FS, N_PRESSES, make_device, pack, press_counter

TB = 1000
F_OFF = 50_000
SNR_DB = 20.0
SYNC_HIGH = 300
SYNC_GAP = 3100
HIGH1 = 600
HIGH0 = 300
IDLE = 4000


def bit_env(b):
    hi = HIGH1 if b else HIGH0
    return [1.0] * hi + [0.0] * (TB - hi)


def frame_env(code48):
    env = []
    for i in range(47, -1, -1):
        env += bit_env((code48 >> i) & 1)
    env += [1.0] * SYNC_HIGH + [0.0] * SYNC_GAP
    return env


def make_capture(flag_or_seed, seed=None):
    if seed is None:
        seed = int.from_bytes(hashlib.sha256(str(flag_or_seed).encode()).digest()[:4], "big") % (2 ** 31)
    dev = make_device(seed)
    rng = np.random.default_rng(seed)
    env = [0.0] * IDLE
    for n in range(N_PRESSES):
        env += frame_env(pack(dev["serial"], press_counter(dev, n), dev["button"]))
    env += [0.0] * IDLE
    env = np.array(env)
    t = np.arange(len(env)) / FS
    x = env * np.exp(1j * 2 * np.pi * F_OFF * t)
    n_p = 1.0 / (10 ** (SNR_DB / 10))
    noise = np.sqrt(n_p / 2) * (rng.standard_normal(len(x)) + 1j * rng.standard_normal(len(x)))
    return (x + noise).astype(np.complex64), dev


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(outdir, exist_ok=True)
    x, dev = make_capture(os.environ.get("FLAG", "H7CTF{roll_back_test}"))
    x.tofile(os.path.join(outdir, "capture.cf32"))
    print(f"[gen] wrote capture.cf32 ({N_PRESSES} presses, fs={FS}); device={dev}")


if __name__ == "__main__":
    main()

import os, sys, secrets
import numpy as np

FS = 1_000_000
SPS = 100
F_OFF = 60_000
F_DEV = 25_000
PREAMBLE = b"\xAA" * 6
SYNC = 0x2DD4
SNR_DB = 19.0
IDLE = 2500


def crc16_ccitt(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


def bits_of(data):
    out = []
    for b in data:
        for i in range(7, -1, -1):
            out.append((b >> i) & 1)
    return out


def frame(flag):
    body = bytes([len(flag)]) + flag
    crc = crc16_ccitt(body)
    payload = body + bytes([crc >> 8, crc & 0xFF])
    bits = bits_of(PREAMBLE) + [(SYNC >> i) & 1 for i in range(15, -1, -1)] + bits_of(payload)
    return bits


def fsk(bits, rng):
    phase = 0.0
    out = []
    for b in bits:
        f = F_OFF + (F_DEV if b else -F_DEV)
        step = 2 * np.pi * f / FS
        for _ in range(SPS):
            phase += step
            out.append(np.exp(1j * phase))
    return np.array(out, dtype=np.complex128)


def make_capture(flag_str, seed=None):
    rng = np.random.default_rng(seed)
    flag = flag_str.encode()
    burst = fsk(frame(flag), rng)
    lead = np.zeros(IDLE + rng.integers(0, 800), dtype=np.complex128)
    tail = np.zeros(IDLE + rng.integers(0, 800), dtype=np.complex128)
    x = np.concatenate([lead, burst, tail])
    sig_p = np.mean(np.abs(burst) ** 2)
    n_p = sig_p / (10 ** (SNR_DB / 10))
    noise = np.sqrt(n_p / 2) * (rng.standard_normal(len(x)) + 1j * rng.standard_normal(len(x)))
    return (x + noise).astype(np.complex64)


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(outdir, exist_ok=True)
    flag = os.environ.get("FLAG", "H7CTF{signal_unknown_test}")
    make_capture(flag).tofile(os.path.join(outdir, "capture.cf32"))
    print(f"[gen] wrote capture.cf32 (fs={FS} complex64 interleaved)")


if __name__ == "__main__":
    main()

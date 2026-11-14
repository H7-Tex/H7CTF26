import os, sys, wave
import numpy as np

FS = 48000
BAUD = 300
MARK = 1200
SPACE = 2200
SPB = FS // BAUD


def afsk_encode(data):
    bits = [1] * 48
    for b in data:
        bits.append(0)
        bits += [(b >> i) & 1 for i in range(8)]
        bits.append(1)
    bits += [1] * 24
    ph = 0.0
    out = []
    for bit in bits:
        f = MARK if bit else SPACE
        for _ in range(SPB):
            ph += 2 * np.pi * f / FS
            out.append(np.sin(ph))
    return np.array(out)


def ambience(n, rng):
    white = rng.standard_normal(n)
    b = np.zeros(n)
    a = 0.0
    for i in range(n):
        a = 0.98 * a + 0.02 * white[i]
        b[i] = a
    b /= (np.max(np.abs(b)) + 1e-9)
    hum = 0.03 * np.sin(2 * np.pi * 50 * np.arange(n) / FS)
    return 0.06 * b + hum


def make_audio(flag, seed=None):
    rng = np.random.default_rng(seed)
    burst = afsk_encode(flag.encode()) * 0.5
    pad = int(2.0 * FS)
    total = pad + len(burst) + pad
    room = ambience(total, rng)
    sig = room.copy()
    sig[pad:pad + len(burst)] += burst
    return np.clip(sig, -1, 1)


def write_wav(path, sig):
    w = wave.open(path, "w")
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(FS)
    w.writeframes((sig * 32767).astype("<i2").tobytes())
    w.close()


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(outdir, exist_ok=True)
    flag = os.environ.get("FLAG", "H7CTF{mic_drop_test}")
    write_wav(os.path.join(outdir, "boardroom.wav"), make_audio(flag))
    print("[gen] wrote boardroom.wav")


if __name__ == "__main__":
    main()

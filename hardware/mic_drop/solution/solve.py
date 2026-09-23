import sys, os, subprocess, io, wave
import numpy as np

FS = 48000
BAUD = 300
MARK = 1200
SPACE = 2200
SPB = FS // BAUD


def goertzel(x, f):
    k = 2 * np.cos(2 * np.pi * f / FS)
    s1 = s2 = 0.0
    for v in x:
        s0 = v + k * s1 - s2
        s2 = s1
        s1 = s0
    return s1 * s1 + s2 * s2 - k * s1 * s2


def afsk_decode(x):
    env = np.abs(x)
    if env.max() < 1e-6:
        return b""
    on = np.where(env > 0.15 * env.max())[0]
    x = x[on[0]:on[-1] + 1]
    nbits = len(x) // SPB
    bits = [1 if goertzel(x[i * SPB:(i + 1) * SPB], MARK) > goertzel(x[i * SPB:(i + 1) * SPB], SPACE) else 0
            for i in range(nbits)]
    out = bytearray()
    j = 0
    while j < len(bits) and bits[j] == 1:
        j += 1
    while j + 10 <= len(bits):
        if bits[j] != 0:
            j += 1
            continue
        byte = 0
        for k in range(8):
            byte |= bits[j + 1 + k] << k
        if bits[j + 9] != 1:
            j += 1
            continue
        out.append(byte)
        j += 10
    return bytes(out)


def load_audio(src, seconds=14):
    if src.startswith("http") or src.endswith((".m3u8", ".ts", ".m4a", ".aac", ".mp4")):
        raw = subprocess.run(
            ["ffmpeg", "-y", "-i", src, "-t", str(seconds), "-ar", str(FS), "-ac", "1", "-f", "wav", "pipe:1"],
            capture_output=True).stdout
        w = wave.open(io.BytesIO(raw))
    else:
        w = wave.open(src)
    n = w.getnframes()
    return np.frombuffer(w.readframes(n), dtype="<i2").astype(float) / 32767


def solve(src):
    sig = load_audio(src)
    payload = afsk_decode(sig)
    i = payload.find(b"H7CTF{")
    if i < 0:
        return None
    j = payload.find(b"}", i)
    return payload[i:j + 1].decode(errors="replace") if j > 0 else None


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "boardroom.wav"
    if os.path.isdir(src):
        src = os.path.join(src, "boardroom.wav")
    flag = solve(src)
    print(f"[solve] FLAG = {flag}" if flag else "[solve] no flag recovered")


if __name__ == "__main__":
    main()

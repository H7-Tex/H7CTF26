import sys, os
import numpy as np

FS = 1_000_000


def crc16_ccitt(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


def smooth(a, w):
    return np.convolve(a, np.ones(w) / w, mode="same")


def bits_to_bytes(bits):
    return bytes(int("".join(str(x) for x in bits[i:i + 8]), 2) for i in range(0, len(bits) - 7, 8))


def solve(path):
    x = np.fromfile(path, dtype=np.complex64)

    sm = smooth(np.abs(x), 64)
    on = np.where(sm > 0.5 * sm.max())[0]
    seg = x[on[0]:on[-1]]

    inst = smooth(np.angle(seg[1:] * np.conj(seg[:-1])) * FS / (2 * np.pi), 15)
    mid = (np.percentile(inst, 10) + np.percentile(inst, 90)) / 2
    bit = (inst > mid).astype(int)

    tr = np.where(np.diff(bit) != 0)[0]
    runs = np.diff(tr).astype(float)
    runs = runs[runs > 0]
    sps0 = np.median(np.sort(runs)[:max(3, len(runs) // 4)])
    k = np.round(runs / sps0)
    m = k >= 1
    sps = runs[m].sum() / k[m].sum()

    sync = "".join(str((0x2DD4 >> i) & 1) for i in range(15, -1, -1))
    nsyms = int(len(bit) / sps)
    for phase in range(int(round(sps))):
        c = (phase + sps * (0.5 + np.arange(nsyms))).round().astype(int)
        c = c[c < len(bit)]
        s = "".join(map(str, bit[c]))
        pos = s.find(sync)
        if pos < 0:
            continue
        after = [int(ch) for ch in s[pos + 16:]]
        if len(after) < 24:
            continue
        n = int("".join(map(str, after[:8])), 2)
        need = 8 + n * 8 + 16
        if len(after) < need:
            continue
        body = bits_to_bytes(after[:8 + n * 8])
        crc = bits_to_bytes(after[8 + n * 8:need])
        if crc16_ccitt(body) == (crc[0] << 8 | crc[1]):
            return body[1:1 + n].decode(errors="replace")
    return None


def main():
    p = sys.argv[1] if len(sys.argv) > 1 else "."
    if os.path.isdir(p):
        p = os.path.join(p, "capture.cf32")
    flag = solve(p)
    print(f"[solve] FLAG = {flag}" if flag else "[solve] no flag recovered")


if __name__ == "__main__":
    main()

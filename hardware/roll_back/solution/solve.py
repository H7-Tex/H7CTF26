import sys, os, json, urllib.request
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "challenge"))
from proto import unpack, pack, FS


def smooth(a, w):
    return np.convolve(a, np.ones(w) / w, mode="same")


def runs_of(mask):
    idx = np.where(np.diff(mask.astype(int)) != 0)[0] + 1
    bounds = np.concatenate([[0], idx, [len(mask)]])
    return [(mask[bounds[i]], bounds[i + 1] - bounds[i]) for i in range(len(bounds) - 1)]


def demod(path):
    x = np.fromfile(path, dtype=np.complex64)
    env = smooth(np.abs(x), 50)
    on = env > 0.5 * env.max()
    rl = runs_of(on)

    frames = []
    cur = []
    for level, width in rl:
        if not level and width > 1500:
            if cur:
                frames.append(cur)
                cur = []
            continue
        if level:
            cur.append(width)
    if cur:
        frames.append(cur)

    codes = []
    for f in frames:
        if len(f) < 48:
            continue
        bits = [1 if w > 450 else 0 for w in f[:48]]
        code = 0
        for b in bits:
            code = (code << 1) | b
        s, c, btn, ok = unpack(code)
        if ok:
            codes.append((s, c, btn))
    return codes


def predict(codes):
    serial = codes[0][0]
    button = codes[0][2]
    counters = [c for _, c, _ in codes]
    diffs = [b - a for a, b in zip(counters, counters[1:]) if b > a]
    step = int(round(np.median(diffs))) if diffs else 1
    nxt = counters[-1] + step
    return pack(serial, nxt, button), serial, nxt, button


def main():
    p = sys.argv[1] if len(sys.argv) > 1 else "."
    base_url = sys.argv[2] if len(sys.argv) > 2 else None
    if os.path.isdir(p):
        p = os.path.join(p, "capture.cf32")
    codes = demod(p)
    print(f"[solve] recovered {len(codes)} frames: " +
          ", ".join(f"c={c}" for _, c, _ in codes))
    code48, serial, nxt, button = predict(codes)
    print(f"[solve] serial={serial:06x} button={button} predicted next counter={nxt} code={code48:012x}")
    if base_url:
        req = urllib.request.Request(base_url.rstrip("/") + "/unlock",
                                     data=json.dumps({"code": f"{code48:012x}"}).encode(),
                                     headers={"Content-Type": "application/json"})
        print("[solve] /unlock ->", urllib.request.urlopen(req).read().decode())


if __name__ == "__main__":
    main()

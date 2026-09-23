import sys, os, re

RESP = 0x7E8
LINE = re.compile(r"\(([\d.]+)\)\s+(\S+)\s+([0-9A-Fa-f]+)#([0-9A-Fa-f]*)")


def parse(path):
    frames = []
    for ln in open(path):
        m = LINE.match(ln.strip())
        if m:
            frames.append((float(m.group(1)), int(m.group(3), 16), bytes.fromhex(m.group(4))))
    return frames


def reassemble_isotp(frames, cid):
    seq = [d for _, i, d in frames if i == cid]
    ff_idx = next((k for k, d in enumerate(seq) if d and (d[0] & 0xF0) == 0x10), None)
    if ff_idx is None:
        return None
    ff = seq[ff_idx]
    total = ((ff[0] & 0x0F) << 8) | ff[1]
    data = bytearray(ff[2:8])
    k = ff_idx + 1
    while len(data) < total and k < len(seq):
        d = seq[k]
        if d and (d[0] & 0xF0) == 0x20:
            data += d[1:8]
        k += 1
    return bytes(data[:total])


def solve(path):
    frames = parse(path)
    payload = reassemble_isotp(frames, RESP)
    if not payload or payload[0] != 0x62:
        return None
    return payload[3:].decode(errors="replace")


def main():
    p = sys.argv[1] if len(sys.argv) > 1 else "."
    if os.path.isdir(p):
        p = os.path.join(p, "capture.log")
    flag = solve(p)
    print(f"[solve] FLAG = {flag}" if flag else "[solve] no flag recovered")


if __name__ == "__main__":
    main()

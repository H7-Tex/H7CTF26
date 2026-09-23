import os, sys, random

IFACE = "can0"
REQ = 0x7E0
RESP = 0x7E8
SECRET_DID = 0xF1A0
NOISE_IDS = [0x0C9, 0x1A0, 0x244, 0x3B0, 0x158, 0x1F1, 0x2C0, 0x316]


def isotp_encode(payload):
    n = len(payload)
    if n <= 7:
        return [bytes([n]) + payload + b"\x00" * (7 - n)]
    frames = [bytes([0x10 | (n >> 8), n & 0xFF]) + payload[:6]]
    rest = payload[6:]
    seq = 1
    while rest:
        chunk = rest[:7]
        rest = rest[7:]
        frames.append(bytes([0x20 | (seq & 0x0F)]) + chunk + b"\x00" * (7 - len(chunk)))
        seq += 1
    return frames


def line(ts, cid, data):
    return f"({ts:.6f}) {IFACE} {cid:03X}#{data.hex().upper()}"


def noise(ts, rng):
    cid = rng.choice(NOISE_IDS)
    return line(ts, cid, rng.randbytes(rng.choice([2, 4, 8])))


def make_capture(flag, seed=None):
    rng = random.Random(seed)
    t = 1_700_000_000.0 + rng.random()
    out = []

    def emit_noise(k):
        nonlocal t
        for _ in range(k):
            t += rng.uniform(0.002, 0.02)
            out.append(noise(t, rng))

    def diag(cid, data):
        nonlocal t
        t += rng.uniform(0.004, 0.03)
        out.append(line(t, cid, data + b"\x00" * (8 - len(data))))

    emit_noise(rng.randint(40, 70))
    seed_bytes = rng.randbytes(4)
    key_bytes = bytes((b ^ 0x5A) for b in seed_bytes)
    diag(REQ, bytes([0x02, 0x10, 0x03]))                       # extended session
    diag(RESP, bytes([0x06, 0x50, 0x03, 0x00, 0x32, 0x01, 0xF4]))
    emit_noise(rng.randint(6, 14))
    diag(REQ, bytes([0x02, 0x27, 0x01]))                        # request seed
    diag(RESP, bytes([0x06, 0x67, 0x01]) + seed_bytes)
    emit_noise(rng.randint(4, 10))
    diag(REQ, bytes([0x06, 0x27, 0x02]) + key_bytes)            # send key
    diag(RESP, bytes([0x02, 0x67, 0x02]))                       # unlocked
    emit_noise(rng.randint(4, 10))
    diag(REQ, bytes([0x03, 0x22, SECRET_DID >> 8, SECRET_DID & 0xFF]))  # ReadDataByIdentifier
    resp_payload = bytes([0x62, SECRET_DID >> 8, SECRET_DID & 0xFF]) + flag.encode()
    frames = isotp_encode(resp_payload)
    diag(RESP, frames[0])                                       # first frame
    diag(REQ, bytes([0x30, 0x00, 0x00]))                        # flow control (CTS)
    for f in frames[1:]:
        nonlocal_noise = rng.random() < 0.5
        if nonlocal_noise:
            emit_noise(1)
        diag(RESP, f)                                           # consecutive frames
    emit_noise(rng.randint(30, 60))
    return "\n".join(out) + "\n"


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(outdir, exist_ok=True)
    flag = os.environ.get("FLAG", "H7CTF{zero_day_highway_test}")
    with open(os.path.join(outdir, "capture.log"), "w") as f:
        f.write(make_capture(flag))
    print("[gen] wrote capture.log")


if __name__ == "__main__":
    main()

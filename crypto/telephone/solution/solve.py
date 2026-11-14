import os
import sys
import json
import struct
import socket
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "handout"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "challenge"))
import murmur_crypto as c

GW_STATIC_PUB = bytes.fromhex("15e8896ef9b0d92253ba8e4f8b96d8600648a4b4f2f299ae1a4ece8c6db71b16")

P = (1 << 130) - 5
CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
MASK128 = (1 << 128) - 1


def poly_blocks(message):
    return [int.from_bytes(message[i:i + 16] + b"\x01", "little") for i in range(0, len(message), 16)]


def poly_value(r, message):
    acc = 0
    for b in poly_blocks(message):
        acc = ((acc + b) * r) % P
    return acc


def poly_coeffs(message):
    blocks = poly_blocks(message)
    coeffs = [0] * (len(blocks) + 1)
    for j, b in enumerate(blocks):
        coeffs[len(blocks) - j] = b % P
    return coeffs


def pnorm(a):
    while len(a) > 1 and a[-1] % P == 0:
        a.pop()
    return [x % P for x in a]


def psub(a, b):
    n = max(len(a), len(b))
    r = [0] * n
    for i in range(len(a)):
        r[i] = (r[i] + a[i]) % P
    for i in range(len(b)):
        r[i] = (r[i] - b[i]) % P
    return pnorm(r)


def pmul(a, b):
    r = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                r[i + j] = (r[i + j] + x * y) % P
    return pnorm(r)


def pdivmod(a, b):
    a = pnorm(a[:])
    b = pnorm(b[:])
    inv = pow(b[-1], P - 2, P)
    quot = [0] * max(1, len(a) - len(b) + 1)
    while len(a) >= len(b) and not (len(a) == 1 and a[0] == 0):
        d = len(a) - len(b)
        coef = (a[-1] * inv) % P
        quot[d] = coef
        for i in range(len(b)):
            a[d + i] = (a[d + i] - coef * b[i]) % P
        a = pnorm(a)
        if len(a) == 1 and a[0] == 0:
            break
    return pnorm(quot), pnorm(a)


def pmod(a, b):
    return pdivmod(a, b)[1]


def pgcd(a, b):
    a = pnorm(a[:])
    b = pnorm(b[:])
    while not (len(b) == 1 and b[0] == 0):
        a, b = b, pmod(a, b)
    inv = pow(a[-1], P - 2, P)
    return pnorm([(x * inv) % P for x in a])


def ppowmod(base, exp, mod):
    result = [1]
    base = pmod(base, mod)
    while exp > 0:
        if exp & 1:
            result = pmod(pmul(result, base), mod)
        base = pmod(pmul(base, base), mod)
        exp >>= 1
    return result


def roots_gf(f):
    f = pnorm(f[:])
    if len(f) <= 1:
        return []
    g = pgcd(f, psub(ppowmod([0, 1], P, f), [0, 1]))
    if len(g) <= 1:
        return []
    found = []

    def split(h):
        h = pnorm(h[:])
        if len(h) == 1:
            return
        if len(h) == 2:
            found.append(((-h[0]) * pow(h[1], P - 2, P)) % P)
            return
        while True:
            t = psub(ppowmod([random.randrange(P), 1], (P - 1) // 2, h), [1])
            d = pgcd(h, t)
            if 1 < len(d) < len(h):
                split(d)
                split(pdivmod(h, d)[0])
                return

    split(g)
    return found


def recover_rs(collisions):
    seen = set()
    uniq = []
    for msg, tag in collisions:
        key = (bytes(msg), bytes(tag))
        if key not in seen:
            seen.add(key)
            uniq.append((msg, tag))
    coeffs = [poly_coeffs(msg) for msg, tag in uniq]
    tags = [int.from_bytes(tag, "little") for msg, tag in uniq]
    candidates = set()
    for j in range(1, len(uniq)):
        diff = psub(coeffs[0], coeffs[j])
        const = (tags[0] - tags[j]) % P
        for delta in range(-4, 5):
            poly = psub(diff, [(const + delta * (1 << 128)) % P])
            if len(poly) <= 1:
                continue
            for root in roots_gf(poly):
                if root == (root & CLAMP):
                    candidates.add(root)
    for r in candidates:
        base = poly_value(r, uniq[0][0])
        for carry in range(5):
            s = (tags[0] + carry * (1 << 128) - base) % P
            if s >> 128:
                continue
            if all(((poly_value(r, msg) + s) & MASK128) == int.from_bytes(tag, "little")
                   for msg, tag in uniq):
                return r, s
    raise RuntimeError("mac key recovery failed")


def poly_tag(r, s, message):
    return ((poly_value(r, message) + s) & MASK128).to_bytes(16, "little")


def segment(binding, blob, start_index, start_nonce):
    frames = []
    offset = 0
    index = start_index
    nonce = start_nonce
    while offset < len(blob):
        masked = struct.unpack("<H", blob[offset:offset + 2])[0]
        length = masked ^ c.length_mask(binding, index)
        body = blob[offset + 2:offset + 2 + length]
        ftype = body[0]
        sealed = body[1:]
        frames.append({"index": index, "nonce": nonce, "type": ftype,
                       "ct": sealed[:-16], "tag": sealed[-16:]})
        offset += 2 + length
        if ftype == c.TYPE_DATA:
            nonce += 1
        index += 1
    return frames


def recv_events(reader, until):
    events = []
    for line in reader:
        line = line.strip()
        if not line:
            continue
        ev = json.loads(line)
        events.append(ev)
        if ev.get("event") == until:
            break
    return events


def solve(host, port):
    sock = socket.create_connection((host, port))
    reader = sock.makefile("r")
    events = recv_events(reader, "ready")

    wires = [e for e in events if e.get("event") == "wire"]
    m1 = bytes.fromhex(wires[0]["data"])
    m2 = bytes.fromhex(wires[1]["data"])
    n2g_blob = bytes.fromhex(wires[3]["data"])
    g2n_blob = bytes.fromhex(wires[4]["data"])

    binding = recompute_binding(m1, m2)

    n2g = segment(binding, n2g_blob, 0, 0)
    g2n = segment(binding, g2n_blob, 0, 0)

    node_zero = [f for f in n2g if f["nonce"] == 0]
    collisions = [(c.aead_mac_data(bytes([f["type"]]), f["ct"]), f["tag"]) for f in node_zero]
    r, s = recover_rs(collisions)

    keystream_n2g0 = max((f["ct"] for f in node_zero if f["type"] == c.TYPE_CONTROL), key=len)

    payload = bytes([0x01, 0x01]) + struct.pack("<H", 11) + b"READ_SECRET"
    ct = bytes(a ^ b for a, b in zip(payload, keystream_n2g0))
    tag = poly_tag(r, s, c.aead_mac_data(bytes([c.TYPE_CONTROL]), ct))
    body = bytes([c.TYPE_CONTROL]) + ct + tag
    masked = len(body) ^ c.length_mask(binding, 0)
    frame = struct.pack("<H", masked) + body

    sock.sendall((json.dumps({"cmd": "inject", "data": frame.hex()}) + "\n").encode())
    events = recv_events(reader, "wire")
    resp = bytes.fromhex([e for e in events if e.get("event") == "wire"][0]["data"])

    resp_index = len([f for f in g2n])
    resp_nonce = g2n[-1]["nonce"] + (1 if g2n[-1]["type"] == c.TYPE_DATA else 0)
    parsed = segment(binding, resp, resp_index, resp_nonce)[0]

    gw_ks = None
    for f in g2n:
        if f["type"] == c.TYPE_CONTROL and f["nonce"] == parsed["nonce"]:
            if gw_ks is None or len(f["ct"]) > len(gw_ks):
                gw_ks = f["ct"]
    plaintext = bytes(a ^ b for a, b in zip(parsed["ct"], gw_ks))
    length = struct.unpack("<H", plaintext[1:3])[0]
    flag = plaintext[3:3 + length]
    sock.close()
    return flag.decode()


def recompute_binding(m1, m2):
    ss = c.SymmetricState()
    ss.mix_hash(b"")
    ss.mix_hash(GW_STATIC_PUB)
    ss.mix_hash(m1[:32])
    ss.mix_hash(m1[32:])
    ss.mix_hash(m2[:32])
    ss.mix_hash(m2[32:])
    return ss.h


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
    print(solve(host, port))

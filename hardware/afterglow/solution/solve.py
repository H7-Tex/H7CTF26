import struct
import subprocess
import sys
import tempfile

import numpy as np
from PIL import Image

W = 256
FH = 32
NSUB = 8
PLANE_SIZE = W * FH // 8


def u32(x):
    return x & 0xFFFFFFFF


def derive(seed):
    x = u32(seed)
    x = u32(x ^ 0x5BD1E995)
    x = u32(x * 0x9E3779B1)
    x = u32(x ^ (x >> 15))
    x = u32(x * 0x85EBCA77)
    x = u32(x ^ (x >> 13))
    return x


def lfsr_next(s):
    bit = ((s >> 15) ^ (s >> 13) ^ (s >> 12) ^ (s >> 10)) & 1
    return ((s << 1) | bit) & 0xFFFF


def schedule(rkey):
    state = ((rkey ^ (rkey >> 16)) & 0xFFFF) or 0xBEEF

    def byte():
        nonlocal state
        state = lfsr_next(state)
        return state & 0xFF

    perm = list(range(NSUB))
    for i in range(NSUB - 1, 0, -1):
        j = byte() % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    inv = [byte() & 1 for _ in range(NSUB)]
    off = [((byte() % 5) - 2, (byte() % 5) - 2) for _ in range(NSUB)]
    return perm, inv, off


def keystream(rkey, s, n):
    st = u32(rkey ^ u32(0x01000193 * (s + 1)))
    out = bytearray(n)
    for i in range(n):
        st = u32(st * 1664525 + 1013904223)
        out[i] = (st >> 24) & 0xFF
    return bytes(out)


def reconstruct(rom):
    off_hdr = rom.find(b"PDPX")
    if off_hdr < 0:
        raise SystemExit("no panel header found")
    magic, width, fh, gh, nsub, seed, plane_size = struct.unpack_from("<4sHHHHIH", rom, off_hdr)
    rkey = derive(seed)
    perm, inv, off = schedule(rkey)
    base = off_hdr + struct.calcsize("<4sHHHHIH")
    intensity = np.zeros((fh, width), dtype=np.uint8)
    for s in range(nsub):
        enc = rom[base + s * plane_size: base + (s + 1) * plane_size]
        ks = keystream(rkey, s, plane_size)
        dec = bytes((enc[i] ^ ks[i]) & 0xFF for i in range(plane_size))
        stored = np.unpackbits(np.frombuffer(dec, dtype=np.uint8)).reshape(fh, width)
        dx, dy = off[s]
        raw = np.roll(np.roll(stored, -dy, axis=0), -dx, axis=1)
        if inv[s]:
            raw = raw ^ 1
        intensity |= (raw.astype(np.uint8) << perm[s])
    return intensity, seed, rkey, perm, inv, off


def ocr(intensity):
    img = (intensity > 110).astype(np.uint8) * 255
    big = Image.fromarray(img, "L").resize((W * 5, FH * 5), Image.LANCZOS)
    canvas = Image.new("L", (big.width + 40, big.height + 40), 255)
    canvas.paste(Image.eval(big, lambda p: 255 - p), (20, 20))
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
        canvas.save(tf.name)
        try:
            out = subprocess.run(
                ["tesseract", tf.name, "-", "--psm", "7", "-c",
                 "tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789{}_"],
                capture_output=True, text=True)
            return out.stdout.strip()
        except FileNotFoundError:
            return ""


def main():
    rom = open(sys.argv[1] if len(sys.argv) > 1 else "panel.rom", "rb").read()
    intensity, seed, rkey, perm, inv, off = reconstruct(rom)
    Image.fromarray(intensity, "L").resize((W * 4, FH * 4), Image.NEAREST).save("recovered.png")
    print("seed=%08x rkey=%08x service_code=%08X" % (seed, rkey, rkey))
    print("perm=%s inv=%s off=%s" % (perm, inv, off))
    text = ocr(intensity)
    print("recovered_flag=%s" % text)


if __name__ == "__main__":
    main()

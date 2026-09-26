import hashlib
import hmac
import os
import subprocess
import sys

import numpy as np
from PIL import Image, ImageDraw, ImageFont

import sched

HERE = os.path.dirname(os.path.abspath(__file__))
FONT_CANDIDATES = [
    "/usr/share/fonts/liberation/LiberationMono-Bold.ttf",
    "/usr/share/fonts/TTF/LiberationMono-Bold.ttf",
    "/usr/share/fonts/noto/NotoSansMono-Bold.ttf",
    "/usr/share/fonts/dejavu/DejaVuSansMono-Bold.ttf",
]
DECOY = b"H7CTF{ph0sph0r_burn_in_1985}"
SPLASH = b"PLASMASOFT PANEL BIOS v2.1 -- matrix ok -- no service tag in rom, keep looking"


def pick_font(size):
    for path in FONT_CANDIDATES:
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def fit_font(text, max_w, max_h):
    size = max_h
    while size > 6:
        font = pick_font(size)
        box = font.getbbox(text)
        if (box[2] - box[0]) <= max_w and (box[3] - box[1]) <= max_h:
            return font
        size -= 1
    return pick_font(6)


def render_intensity(text):
    img = Image.new("L", (sched.W, sched.FH), 0)
    draw = ImageDraw.Draw(img)
    font = fit_font(text, sched.W - 8, sched.FH - 4)
    box = font.getbbox(text)
    tw = box[2] - box[0]
    th = box[3] - box[1]
    x = (sched.W - tw) // 2 - box[0]
    y = (sched.FH - th) // 2 - box[1]
    draw.text((x, y), text, fill=255, font=font)
    arr = np.asarray(img, dtype=np.uint8).copy()
    ramp = np.linspace(0.78, 1.0, sched.FH, dtype=np.float32)[:, None]
    arr = np.clip(arr.astype(np.float32) * ramp, 0, 255).astype(np.uint8)
    return arr


def render_guard(text):
    img = Image.new("L", (sched.W, sched.GH), 0)
    draw = ImageDraw.Draw(img)
    font = fit_font(text.decode(), sched.W - 4, sched.GH)
    box = font.getbbox(text.decode())
    tw = box[2] - box[0]
    x = (sched.W - tw) // 2 - box[0]
    draw.text((x, -box[1]), text.decode(), fill=255, font=font)
    arr = (np.asarray(img, dtype=np.uint8) > 96).astype(np.uint8)
    return np.packbits(arr, axis=1).tobytes()


def build_planes(intensity, sc):
    blob = bytearray()
    for s in range(sched.NSUB):
        b = sc.perm[s]
        raw = (intensity >> b) & 1
        if sc.inv[s]:
            raw = raw ^ 1
        dx, dy = sc.off[s]
        shifted = np.roll(np.roll(raw, dy, axis=0), dx, axis=1)
        packed = np.packbits(shifted.astype(np.uint8), axis=1).reshape(-1)
        ks = sched.keystream(sc.rkey, s, sched.PLANE_SIZE)
        enc = bytes((int(packed[i]) ^ ks[i]) & 0xFF for i in range(sched.PLANE_SIZE))
        blob += enc
    return bytes(blob)


def main():
    flag = os.environ.get("FLAG", "H7CTF{afterglow_local_test_0000}")
    secret = os.environ.get("SERVER_SECRET", "afterglow-dev-secret").encode()
    seed = int.from_bytes(hmac.new(secret, flag.encode(), hashlib.sha256).digest()[:4], "little")
    seed = sched.u32(seed) or 0x1234ABCD
    rkey = sched.derive(seed)
    sc = sched.Schedule(rkey)

    intensity = render_intensity(flag)
    header = sched.build_header(seed)
    planes = build_planes(intensity, sc)
    guard = render_guard(DECOY)
    splash = SPLASH + b"\x00"

    build = os.environ.get("BUILD_DIR", HERE)
    os.makedirs(build, exist_ok=True)
    data = header + planes + guard + splash
    with open(os.path.join(build, "paneldata.bin"), "wb") as f:
        f.write(data)

    if "--intensity-out" in sys.argv:
        out = sys.argv[sys.argv.index("--intensity-out") + 1]
        Image.fromarray(intensity, "L").resize((sched.W * 3, sched.FH * 3), Image.NEAREST).save(out)

    nasm = os.environ.get("NASM", "nasm")
    subprocess.run([nasm, "-f", "bin", os.path.join(HERE, "boot.asm"), "-o",
                    os.path.join(build, "boot.bin")], check=True)
    subprocess.run([nasm, "-f", "bin", os.path.join(HERE, "panel.asm"), "-o",
                    os.path.join(build, "panel.bin"), "-I", build + "/"], check=True)

    boot = open(os.path.join(build, "boot.bin"), "rb").read()
    payload = open(os.path.join(build, "panel.bin"), "rb").read()
    payload_sectors = 63
    if len(payload) > payload_sectors * 512:
        raise SystemExit("payload too large: %d bytes" % len(payload))
    payload = payload + b"\x00" * (payload_sectors * 512 - len(payload))

    rom = boot + payload
    out_rom = os.environ.get("OUT_ROM", os.path.join(build, "panel.rom"))
    with open(out_rom, "wb") as f:
        f.write(rom)
    print("panel.rom %d bytes, payload %d bytes used, seed %08x" %
          (len(rom), len(open(os.path.join(build, "panel.bin"), "rb").read()), seed))


if __name__ == "__main__":
    main()

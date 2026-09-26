import functools
import math
import string
import struct
import sys

import numpy as np
from PIL import Image, ImageDraw, ImageFont

W = 256
FH = 32
NSUB = 8
PLANE_SIZE = W * FH // 8

FONT_CANDIDATES = [
    "/usr/share/fonts/liberation/LiberationMono-Bold.ttf",
    "/usr/share/fonts/TTF/LiberationMono-Bold.ttf",
    "/usr/share/fonts/noto/NotoSansMono-Bold.ttf",
    "/usr/share/fonts/dejavu/DejaVuSansMono-Bold.ttf",
]
CHARSET = string.ascii_letters + string.digits + "{}_"
THRESHOLD = 96
RAMP = np.linspace(0.78, 1.0, FH, dtype=np.float32)[:, None]


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


@functools.lru_cache(maxsize=64)
def pick_font(size):
    for path in FONT_CANDIDATES:
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
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
    img = Image.new("L", (W, FH), 0)
    draw = ImageDraw.Draw(img)
    font = fit_font(text, W - 8, FH - 4)
    box = font.getbbox(text)
    tw = box[2] - box[0]
    th = box[3] - box[1]
    x = (W - tw) // 2 - box[0]
    y = (FH - th) // 2 - box[1]
    draw.text((x, y), text, fill=255, font=font)
    arr = np.asarray(img, dtype=np.uint8).copy()
    arr = np.clip(arr.astype(np.float32) * RAMP, 0, 255).astype(np.uint8)
    return arr


def render_with(text, font):
    img = Image.new("L", (W, FH), 0)
    draw = ImageDraw.Draw(img)
    box = font.getbbox(text)
    tw = box[2] - box[0]
    th = box[3] - box[1]
    x = (W - tw) // 2 - box[0]
    y = (FH - th) // 2 - box[1]
    draw.text((x, y), text, fill=255, font=font)
    arr = np.asarray(img, dtype=np.uint8).astype(np.float32) * RAMP
    return np.clip(arr, 0, 255).astype(np.uint8)


@functools.lru_cache(maxsize=64)
def size_span(size):
    font = pick_font(size)
    low = font.getbbox("H7CTF")
    high = font.getbbox("Hg{_}")
    return low[3] - low[1], high[3] - high[1]


def in_band(size, obs_height):
    lo, hi = size_span(size)
    return lo - 1 <= obs_height <= hi + 1


def size_order(obs_height):
    sizes = list(range(7, FH - 3))

    def center(s):
        lo, hi = size_span(s)
        return (lo + hi) / 2.0

    band = sorted([s for s in sizes if in_band(s, obs_height)], key=lambda s: abs(center(s) - obs_height))
    rest = [s for s in sorted(sizes, key=lambda s: abs(center(s) - obs_height)) if s not in band]
    return band, rest


def build_atlas(size, cap_top):
    font = pick_font(size)
    advance = font.getlength("0")
    baseline = cap_top - font.getbbox("0")[1]
    cell = int(math.ceil(advance)) + 14
    margin = 7
    atlas = {}
    for ch in CHARSET:
        box = font.getbbox(ch)
        img = Image.new("L", (cell, FH), 0)
        ImageDraw.Draw(img).text((margin - box[0], baseline), ch, fill=255, font=font)
        gray = np.asarray(img, dtype=np.float32) * RAMP
        ink = gray > THRESHOLD
        ys = np.where(ink.any(axis=1))[0]
        xs = np.where(ink.any(axis=0))[0]
        if len(ys) == 0:
            atlas[ch] = None
            continue
        r0, r1 = int(ys.min()), int(ys.max()) + 1
        c0, c1 = int(xs.min()), int(xs.max()) + 1
        crop = gray[r0:r1, c0:c1]
        atlas[ch] = (crop, r0, c0 - margin, float((crop * crop).sum()))
    return advance, atlas


def rank_cell(gray, atlas, left):
    ranked = []
    for ch, entry in atlas.items():
        if entry is None:
            continue
        crop, roff, coff, norm = entry
        h, w = crop.shape
        best = -1.0
        for dy in range(-1, 2):
            r0 = roff + dy
            if r0 < 0 or r0 + h > FH:
                continue
            for dx in range(-2, 3):
                x0 = left + coff + dx
                if x0 < 0 or x0 + w > W:
                    continue
                region = gray[r0:r0 + h, x0:x0 + w]
                dot = float((region * crop).sum())
                energy = float((region * region).sum())
                if energy <= 0 or norm <= 0:
                    continue
                score = dot / math.sqrt(energy * norm)
                if score > best:
                    best = score
        ranked.append((best, ch))
    ranked.sort(reverse=True)
    return [ch for _, ch in ranked]


def decode_row(gray, atlas, ink_left, advance, count):
    chars = []
    choices = []
    for i in range(count):
        ranked = rank_cell(gray, atlas, int(round(ink_left + i * advance)))
        chars.append(ranked[0] if ranked else "?")
        choices.append(ranked[:12])
    return "".join(chars), choices


def refine(text, target, size, choices=None, max_passes=8):
    font = pick_font(size)
    advance = font.getlength("0")
    cur = list(text)
    n = len(cur)
    prev = None
    for _ in range(max_passes):
        current = render_with("".join(cur), font)
        diff = current != target
        total = int(diff.sum())
        if total == 0:
            break
        if prev is not None and total >= prev:
            break
        prev = total
        origin = font.getbbox("".join(cur))
        base_x = (W - (origin[2] - origin[0])) // 2 - origin[0]
        diff_cols = np.where(diff.any(axis=0))[0]
        todo = [i for i in range(n)
                if ((diff_cols >= int(round(base_x + i * advance)) - 6)
                    & (diff_cols <= int(round(base_x + (i + 1) * advance)) + 6)).any()]
        if not todo:
            todo = list(range(n))
        changed = False
        for i in todo:
            options = choices[i] if (choices is not None and i < len(choices)) else CHARSET
            original = cur[i]
            best_char = original
            best_diff = int((render_with("".join(cur), font) != target).sum())
            for ch in options:
                if ch == cur[i]:
                    continue
                cur[i] = ch
                d = int((render_with("".join(cur), font) != target).sum())
                if d < best_diff:
                    best_diff, best_char = d, ch
            cur[i] = best_char
            if best_char != original:
                changed = True
        if not changed:
            break
    return "".join(cur)


def read_flag(intensity):
    target = intensity
    gray = intensity.astype(np.float32)
    mask = intensity > THRESHOLD
    if not mask.any():
        return ""
    cols = np.where(mask.any(axis=0))[0]
    rows = np.where(mask.any(axis=1))[0]
    ink_left = int(cols.min())
    span = int(cols.max() - cols.min() + 1)
    cap_top = int(rows.min())
    obs_height = int(rows.max() - rows.min() + 1)
    want = target.tobytes()
    atlases = {}

    def atlas_for(size):
        if size not in atlases:
            atlases[size] = build_atlas(size, cap_top)
        return atlases[size]

    scored = []

    def scan(sizes, counts):
        for size in sizes:
            advance, atlas = atlas_for(size)
            if advance <= 0:
                continue
            base = int(round(span / advance))
            for count in counts(base):
                if count < 1 or count > 64:
                    continue
                cand, choices = decode_row(gray, atlas, ink_left, advance, count)
                result = render_intensity(cand)
                if result.tobytes() == want:
                    return cand
                scored.append((int((result != target).sum()), cand, size, choices))
        return None

    def try_refine(limit):
        scored.sort(key=lambda s: s[0])
        if not scored:
            return None
        cutoff = scored[0][0] * 1.4 + 24
        seen = set()
        done = 0
        for diff, cand, size, choices in scored:
            if diff > cutoff:
                break
            if cand in seen:
                continue
            seen.add(cand)
            fixed = refine(cand, target, size, choices)
            if render_intensity(fixed).tobytes() == want:
                return fixed
            fixed = refine(fixed, target, size)
            if render_intensity(fixed).tobytes() == want:
                return fixed
            done += 1
            if done >= limit:
                break
        return None

    band, rest = size_order(obs_height)
    ordered = band + rest
    primary = ordered[:5]
    secondary = ordered[5:]
    hit = scan(primary, lambda b: (b,))
    if hit is not None:
        return hit
    hit = try_refine(3)
    if hit is not None:
        return hit
    hit = scan(primary, lambda b: (b - 1, b + 1))
    if hit is not None:
        return hit
    hit = scan(secondary, lambda b: (b, b - 1, b + 1))
    if hit is not None:
        return hit
    hit = try_refine(10)
    if hit is not None:
        return hit
    scored.sort(key=lambda s: s[0])
    return scored[0][1] if scored else ""


def main():
    rom = open(sys.argv[1] if len(sys.argv) > 1 else "panel.rom", "rb").read()
    intensity, seed, rkey, perm, inv, off = reconstruct(rom)
    Image.fromarray(intensity, "L").resize((W * 4, FH * 4), Image.NEAREST).save("recovered.png")
    print("seed=%08x rkey=%08x service_code=%08X" % (seed, rkey, rkey))
    print("perm=%s inv=%s off=%s" % (perm, inv, off))
    text = read_flag(intensity)
    print("recovered_flag=%s" % text)


if __name__ == "__main__":
    main()

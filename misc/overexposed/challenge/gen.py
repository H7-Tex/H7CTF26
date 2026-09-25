import io
import struct
import zlib

from PIL import Image, ImageDraw
from PIL.PngImagePlugin import PngInfo

FRAG1 = "p0lyg10t_"
FRAG2 = "th3_1nd3x_l13s_"
FRAG3 = "r34d_th3_r4w_byt3s"
FLAG = "H7CTF{" + FRAG1 + FRAG2 + FRAG3 + "}"

README = (
    b"This archive's directory lists one file. The directory is not the archive.\n"
    b"Members can exist without the index admitting them -- read the raw local headers.\n"
    b"And remember what you are looking at: a picture carries more than its pixels.\n"
)


def make_png():
    img = Image.new("RGB", (520, 220), (16, 16, 20))
    d = ImageDraw.Draw(img)
    d.rectangle([30, 60, 490, 150], fill=(30, 30, 38))
    d.text((48, 96), "OVEREXPOSED", fill=(210, 70, 70))
    d.text((48, 120), "nothing to see in the pixels", fill=(120, 120, 130))
    meta = PngInfo()
    meta.add_text("part1", FRAG1, zip=True)  # zTXt: compressed, not visible to `strings`
    buf = io.BytesIO()
    img.save(buf, "PNG", pnginfo=meta)
    return buf.getvalue()


def deflate(data):
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def local_header(name, data):
    nb = name.encode()
    cdata = deflate(data)
    crc = zlib.crc32(data) & 0xFFFFFFFF
    hdr = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0, 8, 0, 0, crc,
                      len(cdata), len(data), len(nb), 0) + nb
    return hdr + cdata, crc, len(cdata), len(data)


def central_header(name, crc, csize, usize, local_off):
    nb = name.encode()
    return struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 8, 0, 0,
                       crc, csize, usize, len(nb), 0, 0, 0, 0, 0, local_off) + nb


def eocd(n, cd_size, cd_off):
    return struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, n, n, cd_size, cd_off, 0)


def build():
    png = make_png()
    P = len(png)

    # every member gets a real local file header; only readme is listed in the directory.
    members = [("readme.txt", README), ("part2.txt", FRAG2.encode()),
               ("part3.txt", FRAG3.encode())]
    blob = b""
    meta = {}
    for name, data in members:
        off = P + len(blob)
        chunk, crc, csize, usize = local_header(name, data)
        meta[name] = (off, crc, csize, usize)
        blob += chunk

    cd_off = P + len(blob)
    off, crc, csize, usize = meta["readme.txt"]
    cd = central_header("readme.txt", crc, csize, usize, off)
    blob += cd + eocd(1, len(cd), cd_off)
    return png + blob


if __name__ == "__main__":
    data = build()
    with open("overexposed.png", "wb") as f:
        f.write(data)
    print("wrote overexposed.png", len(data), "bytes")
    print("flag:", FLAG)

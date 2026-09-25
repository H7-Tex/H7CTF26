import io
import struct
import sys
import zlib

from PIL import Image

path = sys.argv[1] if len(sys.argv) > 1 else "overexposed.png"
blob = open(path, "rb").read()

# read 1 -- as an image: the zTXt chunk `part1`
part1 = Image.open(io.BytesIO(blob)).text["part1"]

# read 2 -- as an archive, against the grain: `unzip` follows the central directory, which
# only admits readme.txt. the real members exist as raw local file headers. walk PK\x03\x04.
members = {}
i = 0
sig = b"PK\x03\x04"
while True:
    i = blob.find(sig, i)
    if i < 0:
        break
    method = struct.unpack_from("<H", blob, i + 8)[0]
    csize = struct.unpack_from("<I", blob, i + 18)[0]
    fnlen = struct.unpack_from("<H", blob, i + 26)[0]
    extralen = struct.unpack_from("<H", blob, i + 28)[0]
    name = blob[i + 30:i + 30 + fnlen].decode(errors="replace")
    data_off = i + 30 + fnlen + extralen
    cdata = blob[data_off:data_off + csize]
    raw = zlib.decompress(cdata, -15) if method == 8 else cdata
    members[name] = raw
    i = data_off + csize

part2 = members["part2.txt"].decode()
part3 = members["part3.txt"].decode()

print("part1 (PNG zTXt):", part1)
print("part2 (unlisted local header):", part2)
print("part3 (unlisted local header):", part3)
print("FLAG:", "H7CTF{" + part1 + part2 + part3 + "}")

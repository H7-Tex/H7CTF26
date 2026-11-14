import base64
import hashlib

import mmh3
from PIL import Image, ImageDraw

# a distinctive custom favicon shared verbatim by both fronts (clearpane + halcyon) and the CDN
# host -> identical Shodan-style favicon hash across otherwise-unrelated sites = the fingerprint.
SIZE = 32
img = Image.new("RGBA", (SIZE, SIZE), (13, 17, 23, 255))
d = ImageDraw.Draw(img)
d.rectangle([4, 4, 27, 27], outline=(88, 166, 255, 255), width=2)
d.line([4, 15, 27, 15], fill=(88, 166, 255, 255), width=1)
d.line([15, 4, 15, 27], fill=(88, 166, 255, 255), width=1)
d.ellipse([12, 12, 19, 19], fill=(240, 246, 252, 255))

img.save("favicon.ico", sizes=[(32, 32)])

data = open("favicon.ico", "rb").read()
# Shodan's favicon hash: mmh3.hash over base64.encodebytes(raw bytes) (note the trailing newlines).
shodan_hash = mmh3.hash(base64.encodebytes(data))
print("favicon.ico bytes:", len(data))
print("sha256:", hashlib.sha256(data).hexdigest()[:16])
print("shodan mmh3 hash:", shodan_hash)
open("favicon_hash.txt", "w").write(str(shodan_hash) + "\n")

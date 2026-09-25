#!/usr/bin/env python3
# Build the Paper Trail OSINT bundle: a deterministic golden thread through file metadata.
#   statement.pdf  --(PDF Author + Keywords handle)-->  exports/<handle>.json
#   <handle>.json  --(pinned post references a photo)-->  gallery/final_print.jpg
#   final_print.jpg --(EXIF ImageDescription)--> the flag
# Decoys at every step (other exports, other photos with FAKE flags in EXIF) so a naive
# `exiftool gallery/* | grep H7CTF` returns several candidates - you must follow the thread.
import os, json, io
from PIL import Image, ImageDraw
import piexif
from pypdf import PdfReader, PdfWriter

FLAG = os.environ.get("FLAG", "H7CTF{m3t4d4t4_g0ld3n_thr34d_0s1nt}")
HERE = os.path.dirname(__file__)
OUT = os.path.join(HERE, "leak_bundle")
for sub in ("", "exports", "gallery"):
    os.makedirs(os.path.join(OUT, sub), exist_ok=True)

# ---------- a photo with EXIF (GPS + description/comment) ----------
def dms(deg):
    d = int(abs(deg)); m = int((abs(deg) - d) * 60); s = round(((abs(deg) - d) * 60 - m) * 60 * 100)
    return ((d, 1), (m, 1), (s, 100))

def make_photo(path, color, label, gps=None, description="", comment="", artist=""):
    im = Image.new("RGB", (640, 400), color)
    d = ImageDraw.Draw(im)
    d.text((20, 20), label, fill=(255, 255, 255))
    zeroth = {piexif.ImageIFD.Make: b"Fujifilm", piexif.ImageIFD.Model: b"X100V",
              piexif.ImageIFD.Software: b"Lightroom 13.2"}
    if description:
        zeroth[piexif.ImageIFD.ImageDescription] = description.encode()
    if artist:
        zeroth[piexif.ImageIFD.Artist] = artist.encode()
    exif = {"0th": zeroth, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None}
    if comment:
        exif["Exif"][piexif.ExifIFD.UserComment] = b"ASCII\x00\x00\x00" + comment.encode()
    if gps:
        lat, lon = gps
        exif["GPS"] = {
            piexif.GPSIFD.GPSLatitudeRef: b"N" if lat >= 0 else b"S",
            piexif.GPSIFD.GPSLatitude: dms(lat),
            piexif.GPSIFD.GPSLongitudeRef: b"E" if lon >= 0 else b"W",
            piexif.GPSIFD.GPSLongitude: dms(lon),
        }
    im.save(path, exif=piexif.dump(exif), quality=85)

# real photo: flag in ImageDescription; GPS points at a real spot (confirming clue)
make_photo(os.path.join(OUT, "gallery", "final_print.jpg"), (40, 60, 90),
           "final print - limited run",
           gps=(19.0330, 72.8256),                      # Mahalaxmi, Mumbai
           description=FLAG,
           artist="Mara Chen",
           comment="proof copy 1/1 - backup code lives in this file")
# decoys: fake flags in EXIF so grep is not enough
make_photo(os.path.join(OUT, "gallery", "sunset.jpg"), (150, 90, 40), "sunset over the bay",
           gps=(18.9220, 72.8347), description="H7CTF{n0t_th3_r34l_0n3_keep_l00k1ng}",
           artist="Mara Chen")
make_photo(os.path.join(OUT, "gallery", "studio.jpg"), (60, 60, 60), "studio setup",
           comment="H7CTF{d3c0y_fr0m_th3_stud10}", artist="Mara Chen")
make_photo(os.path.join(OUT, "gallery", "streetart.jpg"), (30, 110, 70), "street art, lower parel",
           gps=(18.9960, 72.8300), artist="Mara Chen")

# ---------- the social exports (json archives) ----------
def write_json(name, obj):
    with open(os.path.join(OUT, "exports", name), "w") as f:
        json.dump(obj, f, indent=2)

write_json("mchen_prints.json", {
    "handle": "mchen_prints",
    "display_name": "Mara Chen",
    "platform": "printshop.social",
    "bio": "printmaker. limited runs. originals only.",
    "posts": [
        {"id": 41, "text": "new drop this weekend, come by the studio"},
        {"id": 42, "text": "people keep asking where I keep my recovery codes - I don't write them "
                           "down anywhere online. they're baked into the print's own file. look at "
                           "the metadata of my final print (gallery/final_print.jpg).",
         "pinned": True},
        {"id": 43, "text": "sunset shot didn't make the cut but posting anyway"},
    ],
})
# decoy personas
write_json("jdoe_designs.json", {
    "handle": "jdoe_designs", "display_name": "J. Doe", "platform": "printshop.social",
    "bio": "graphic design", "posts": [{"id": 1, "text": "commissions open"}],
})
write_json("artcollective.json", {
    "handle": "artcollective", "display_name": "The Art Collective", "platform": "printshop.social",
    "bio": "group studio", "posts": [{"id": 1, "text": "open house friday"}],
})

# ---------- the seed: statement.pdf with the handle in its metadata ----------
def make_pdf(path):
    # render text to an image, save as a 1-page PDF, then stamp metadata with pypdf
    im = Image.new("RGB", (1000, 1400), (255, 255, 255))
    d = ImageDraw.Draw(im)
    lines = [
        "PUBLIC STATEMENT", "", "Mara Chen Editions", "",
        "All prints sold under my studio are hand-pulled, limited-run originals.",
        "Any listing claiming otherwise is not authorized by me.", "",
        "For provenance questions, verify against my studio's social account.",
        "", "- M.C.",
    ]
    y = 80
    for ln in lines:
        d.text((80, y), ln, fill=(0, 0, 0)); y += 40
    tmp = os.path.join(OUT, "_tmp.pdf")
    im.save(tmp, "PDF", resolution=100)
    r = PdfReader(tmp); w = PdfWriter()
    for pg in r.pages:
        w.add_page(pg)
    w.add_metadata({
        "/Author": "Mara Chen",
        "/Title": "Public Statement",
        "/Subject": "print authenticity",
        "/Keywords": "editions, provenance, handle:mchen_prints",   # the pivot
        "/Creator": "printshop.social exporter",
        "/Producer": "Scribus 1.6",
    })
    with open(path, "wb") as f:
        w.write(f)
    os.remove(tmp)

make_pdf(os.path.join(OUT, "statement.pdf"))

with open(os.path.join(OUT, "README.txt"), "w") as f:
    f.write("Recovered artifacts from the Mara Chen Editions authenticity dispute.\n"
            "Start with statement.pdf. Everything you need is in these files' metadata.\n")

print("built leak_bundle: statement.pdf + 3 exports + 4 gallery photos (flag in final_print.jpg EXIF)")

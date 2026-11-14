#!/usr/bin/env python3
"""Ghost in the Timeline reference solver.

Two-part case (see README):
  (a) timestomp tell:  debugfs -R "stat /home/jdoe/designs/roadmap.pdf" case_disk.img
      -> mtime/atime are backdated but ctime/crtime are the real (recent) time.
  (b) recover the deleted exfil archive and read the flag.

This script does (b) deterministically: carve the deleted ZIP straight out of the image's
unallocated space and unzip it. (foremost / extundelete / photorec do the same thing.)
"""
import sys, io, re, zipfile


def solve(path):
    data = open(path, "rb").read()
    i = data.find(b"PK\x03\x04")
    j = data.rfind(b"PK\x05\x06")
    if i < 0 or j < 0:
        return None
    blob = data[i:j + 22]
    try:
        z = zipfile.ZipFile(io.BytesIO(blob))
    except Exception:
        return None
    for name in z.namelist():
        m = re.search(rb"H7CTF\{[^}]+\}", z.read(name))
        if m:
            return m.group().decode()
    return None


def main():
    flag = solve(sys.argv[1] if len(sys.argv) > 1 else "case_disk.img")
    print(f"[solve] FLAG = {flag}" if flag else "[solve] no flag recovered")


if __name__ == "__main__":
    raise SystemExit(0 if main() is None else 0)

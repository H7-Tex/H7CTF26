#!/usr/bin/env python3
"""Deleted, Not Gone reference solver.

Recover the deleted chat record from the SQLite freelist and de-obfuscate it with the
key the app leaks in shared_prefs.

Intended tools: FQLite / undark / `sqlite3 messages.db .recover` to pull the deleted row;
this script does the equivalent deterministically (scan freed pages for the stored body,
then hex-decode + XOR with the shared_prefs key).
"""
import sys, re


def solve(db_path, xml_path):
    db = open(db_path, "rb").read()
    key = re.search(r'name="obfuscation_key">([^<]+)<', open(xml_path).read()).group(1).encode()
    for h in set(re.findall(rb"[0-9a-fA-F]{20,}", db)):
        try:
            raw = bytes.fromhex(h.decode())
        except ValueError:
            continue
        dec = bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))
        if re.match(rb"^H7CTF\{[ -~]+\}$", dec):
            return dec.decode()
    return None


def main():
    db = sys.argv[1] if len(sys.argv) > 1 else "messages.db"
    xml = sys.argv[2] if len(sys.argv) > 2 else "secure.xml"
    flag = solve(db, xml)
    print(f"[solve] FLAG = {flag}" if flag else "[solve] no deleted record recovered")


if __name__ == "__main__":
    main()

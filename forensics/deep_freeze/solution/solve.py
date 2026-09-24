#!/usr/bin/env python3
"""Deep Freeze reference solver.

Full intended path (see README):
  1. volatility3 -f memory.lime linux.pslist  -> spot the malware process
  2. aeskeyfind memory.lime                    -> candidate AES key schedules
  3. this script                               -> test candidates vs the .locked, decrypt

Usage:
  aeskeyfind memory.lime > keys.txt
  python3 solve.py Q3_patient_records.pdf.locked keys.txt
"""
import sys, re
try:
    from Crypto.Cipher import AES
except ModuleNotFoundError:
    from Cryptodome.Cipher import AES


def main():
    locked = open(sys.argv[1], "rb").read()
    keys_txt = open(sys.argv[2]).read() if len(sys.argv) > 2 else sys.stdin.read()
    iv, c0 = locked[:16], locked[16:32]
    cands = set(re.findall(r"[0-9a-fA-F]{64}", keys_txt)) | set(re.findall(r"[0-9a-fA-F]{32}", keys_txt))
    for kh in cands:
        k = bytes.fromhex(kh)
        if len(k) != 32:
            continue
        if AES.new(k, AES.MODE_CBC, iv).decrypt(c0).startswith(b"%PDF-"):
            pt = AES.new(k, AES.MODE_CBC, iv).decrypt(locked[16:])
            pt = pt[:-pt[-1]]
            m = re.search(rb"H7CTF\{[^}]+\}", pt)
            open("recovered.pdf", "wb").write(pt)
            print(f"[+] key = {kh}")
            print(f"[+] recovered document -> recovered.pdf")
            print(f"[+] FLAG = {m.group().decode() if m else '(open recovered.pdf)'}")
            return 0
    print("[-] no candidate key decrypted the file")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

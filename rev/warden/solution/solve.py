#!/usr/bin/env python3
# Static solve for Warden. Works straight off the handout binary (no running it, no brute force):
#   1. locate the VM bytecode in .rodata by its block structure
#   2. read the per-byte transform out of each block (XOR imm, ADD imm, ROL n, CMP target)
#   3. invert it -> the 16-byte license
#   4. MD5(license) -> AES-128-CBC (zero IV, PKCS7) decrypt the embedded flag blob
import re, sys, hashlib
from Crypto.Cipher import AES

def ror8(v, r): return ((v >> r) | (v << (8 - r))) & 0xff

def load_arrays(path):
    data = open(path, "rb").read()
    if b"BYTECODE[" in data:                         # a warden_data.h was passed
        t = data.decode()
        g = lambda n: bytes(int(x) for x in re.search(n + r"\[\d+\]\s*=\s*\{([^}]*)\}", t).group(1).split(","))
        return g("BYTECODE"), g("FLAGBLOB")
    # else it's the ELF: find the bytecode by structure; the AES flag blob is the block-aligned
    # entropy chunk immediately before it (its length tracks the flag, so carve a region + probe).
    m = re.search(rb"\x01\x00\x02.\x03\x02.\x04\x05[\x01-\x07]\x06.", data, re.S)
    start = m.start()
    bc = data[start:start + 193]                      # 16 blocks * 12 + HALT
    j = start - 1
    while data[j] == 0:                               # skip alignment padding
        j -= 1
    region = data[j - 95:j + 1]                       # candidate blob region, ends at the blob's last byte
    return bc, region

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else \
        "/home/abu/Main/Projects/CTF26/H7CTF26/rev/warden/challenge/warden"
    bc, blob = load_arrays(path)

    license = bytearray(16)
    pc = 0
    while pc < len(bc) and bc[pc] != 0x00:
        # each block: 01 idx | 02 X | 03 | 02 Y | 04 | 05 R | 06 T
        idx, X, Y, R, T = bc[pc+1], bc[pc+3], bc[pc+6], bc[pc+9], bc[pc+11]
        # forward:  T = rol8(((in ^ X) + Y) & 0xff, R)   ->   in = (ror8(T,R) - Y) ^ X
        license[idx] = ((ror8(T, R) - Y) & 0xff) ^ X
        pc += 12

    lic = bytes(license)
    print("recovered license:", lic.decode(errors="replace"))
    key = hashlib.md5(lic).digest()
    # blob is a suffix of the region ending at the bytecode; probe block-aligned lengths
    flag = None
    for blen in range(16, len(blob) + 1, 16):
        pt = AES.new(key, AES.MODE_CBC, b"\x00" * 16).decrypt(blob[-blen:])
        pad = pt[-1]
        if 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad and b"H7CTF{" in pt:
            flag = pt[:-pad]
            break
    assert flag is not None, "flag blob not recovered"
    print("flag:", flag.decode())

if __name__ == "__main__":
    main()

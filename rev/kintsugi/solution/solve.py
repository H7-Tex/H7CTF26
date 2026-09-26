import os
import sys
import glob
import struct
import hashlib
import zlib
import argparse
import urllib.request

from z3 import BitVec, BitVecVal, Extract, ZeroExt, RotateLeft, Solver, sat, Or, If
from nacl.signing import SigningKey
from nacl.signing import VerifyKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HALT, LDS, LDI, MOV, XOR, ADD, MUL, AND, OR, ROL, SBOX, ASSERT, ANDI, XORI = range(14)
WIDTH = {HALT: 1, LDS: 3, LDI: 6, MOV: 3, XOR: 3, ADD: 3, MUL: 3, AND: 3, OR: 3, ROL: 3, SBOX: 3, ASSERT: 6, ANDI: 6, XORI: 6}


def parse_shard(blob):
    assert blob[:4] == b"KSHD"
    flags = blob[5]
    perm_len = blob[8] | (blob[9] << 8)
    prog_len = blob[10] | (blob[11] << 8)
    self_id = blob[14:30]
    perm_crc = struct.unpack_from("<I", blob, 30)[0]
    next_ptr_ct = blob[34:50]
    off = 50
    perm_stored = blob[off:off + perm_len]
    off += perm_len
    sbox = blob[off:off + 256]
    off += 256
    prog = blob[off:off + prog_len]
    return dict(flags=flags, self_id=self_id, perm_crc=perm_crc, next_ptr_ct=next_ptr_ct,
               perm_stored=perm_stored, sbox=bytes(sbox), prog=bytes(prog))


def run_canon(canon, sbox, secret):
    regs = [0] * 8
    ip = 0
    n = len(canon)
    while ip < n:
        op = canon[ip]
        if op == HALT:
            break
        if op == LDS:
            regs[canon[ip + 1]] = secret[canon[ip + 2]] & 0xFF
            ip += 3
        elif op == LDI:
            regs[canon[ip + 1]] = struct.unpack_from("<I", canon, ip + 2)[0]
            ip += 6
        elif op == MOV:
            regs[canon[ip + 1]] = regs[canon[ip + 2]]
            ip += 3
        elif op == XOR:
            regs[canon[ip + 1]] ^= regs[canon[ip + 2]]
            ip += 3
        elif op == ADD:
            regs[canon[ip + 1]] = (regs[canon[ip + 1]] + regs[canon[ip + 2]]) & 0xFFFFFFFF
            ip += 3
        elif op == MUL:
            regs[canon[ip + 1]] = (regs[canon[ip + 1]] * regs[canon[ip + 2]]) & 0xFFFFFFFF
            ip += 3
        elif op == AND:
            regs[canon[ip + 1]] &= regs[canon[ip + 2]]
            ip += 3
        elif op == OR:
            regs[canon[ip + 1]] |= regs[canon[ip + 2]]
            ip += 3
        elif op == ROL:
            c = canon[ip + 2] & 31
            v = regs[canon[ip + 1]]
            regs[canon[ip + 1]] = ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF if c else v
            ip += 3
        elif op == SBOX:
            regs[canon[ip + 1]] = sbox[regs[canon[ip + 2]] & 0xFF]
            ip += 3
        elif op == ANDI:
            regs[canon[ip + 1]] &= struct.unpack_from("<I", canon, ip + 2)[0]
            ip += 6
        elif op == XORI:
            regs[canon[ip + 1]] ^= struct.unpack_from("<I", canon, ip + 2)[0]
            ip += 6
        elif op == ASSERT:
            if regs[canon[ip + 1]] != struct.unpack_from("<I", canon, ip + 2)[0]:
                return False
            ip += 6
        else:
            raise ValueError("bad op")
    return True


def decode_prog(prog, dec):
    out = bytearray(prog)
    ip = 0
    while ip < len(prog):
        op = dec[prog[ip]]
        out[ip] = op
        ip += WIDTH[op]
    return bytes(out)


def subkey(base, label):
    return hashlib.sha256(base + label).digest()


def ctr(key, data):
    c = Cipher(algorithms.AES(key), modes.CTR(b"\x00" * 16)).encryptor()
    return c.update(data) + c.finalize()


def shard_key(sec):
    return hashlib.sha256(bytes(sec)).digest()


def enumerate_models(canon, sbox):
    secbytes = [BitVec(f"s{i}", 8) for i in range(8)]
    regs = [BitVecVal(0, 32) for _ in range(8)]
    s = Solver()
    counter = [0]

    def apply_sbox(reg):
        counter[0] += 1
        out = BitVec(f"sb{counter[0]}", 8)
        idx = Extract(7, 0, reg)
        expr = BitVecVal(sbox[255], 8)
        for i in range(254, -1, -1):
            expr = If(idx == i, BitVecVal(sbox[i], 8), expr)
        s.add(out == expr)
        return ZeroExt(24, out)

    ip = 0
    n = len(canon)
    while ip < n:
        op = canon[ip]
        if op == HALT:
            break
        if op == LDS:
            regs[canon[ip + 1]] = ZeroExt(24, secbytes[canon[ip + 2]])
            ip += 3
        elif op == LDI:
            regs[canon[ip + 1]] = BitVecVal(struct.unpack_from("<I", canon, ip + 2)[0], 32)
            ip += 6
        elif op == MOV:
            regs[canon[ip + 1]] = regs[canon[ip + 2]]
            ip += 3
        elif op == XOR:
            regs[canon[ip + 1]] = regs[canon[ip + 1]] ^ regs[canon[ip + 2]]
            ip += 3
        elif op == ADD:
            regs[canon[ip + 1]] = regs[canon[ip + 1]] + regs[canon[ip + 2]]
            ip += 3
        elif op == MUL:
            regs[canon[ip + 1]] = regs[canon[ip + 1]] * regs[canon[ip + 2]]
            ip += 3
        elif op == AND:
            regs[canon[ip + 1]] = regs[canon[ip + 1]] & regs[canon[ip + 2]]
            ip += 3
        elif op == OR:
            regs[canon[ip + 1]] = regs[canon[ip + 1]] | regs[canon[ip + 2]]
            ip += 3
        elif op == ROL:
            regs[canon[ip + 1]] = RotateLeft(regs[canon[ip + 1]], canon[ip + 2] & 31)
            ip += 3
        elif op == SBOX:
            regs[canon[ip + 1]] = apply_sbox(regs[canon[ip + 2]])
            ip += 3
        elif op == ANDI:
            regs[canon[ip + 1]] = regs[canon[ip + 1]] & BitVecVal(struct.unpack_from("<I", canon, ip + 2)[0], 32)
            ip += 6
        elif op == XORI:
            regs[canon[ip + 1]] = regs[canon[ip + 1]] ^ BitVecVal(struct.unpack_from("<I", canon, ip + 2)[0], 32)
            ip += 6
        elif op == ASSERT:
            imm = struct.unpack_from("<I", canon, ip + 2)[0]
            s.add(regs[canon[ip + 1]] == BitVecVal(imm, 32))
            ip += 6
        else:
            raise ValueError("bad op")

    if s.check() != sat:
        return []
    m = s.model()
    base = bytearray((m[secbytes[i]].as_long() if m[secbytes[i]] is not None else 0) & 0xFF for i in range(8))
    free = []
    for bit in range(64):
        cand = bytearray(base)
        cand[bit // 8] ^= 1 << (bit % 8)
        if run_canon(canon, sbox, cand):
            free.append(bit)
    models = []
    for combo in range(1 << len(free)):
        cand = bytearray(base)
        for k, bit in enumerate(free):
            if combo & (1 << k):
                cand[bit // 8] ^= 1 << (bit % 8)
        models.append(bytes(cand))
    return models


def load_bundle(bundle):
    shards = {}
    for path in glob.glob(os.path.join(bundle, "*.shard")):
        blob = open(path, "rb").read()
        sh = parse_shard(blob)
        shards[sh["self_id"].hex()] = sh
    return shards


def solve_offline(bundle):
    shards = load_bundle(bundle)
    pubkey = open(os.path.join(bundle, "pubkey.bin"), "rb").read()
    start = None
    for sid, sh in shards.items():
        if sh["flags"] & 1:
            start = sid
            break
    if start is None:
        raise RuntimeError("no start shard")

    recovered = []
    cur = shards[start]
    cur_perm = cur["perm_stored"]
    step = 0
    while True:
        canon = decode_prog(cur["prog"], cur_perm)
        models = enumerate_models(canon, cur["sbox"])
        sys.stderr.write(f"[shard {step}] {cur['self_id'].hex()} models={len(models)}\n")
        if cur["flags"] & 2:
            base = b"".join(recovered)
            pinned = None
            for cand in models:
                if SigningKey(base + cand).verify_key.encode() == pubkey:
                    pinned = cand
                    break
            if pinned is None:
                raise RuntimeError("terminal disambiguation failed")
            recovered.append(pinned)
            break
        pinned = None
        nxt = None
        for cand in models:
            k = shard_key(cand)
            nid = ctr(subkey(k, b"PTR"), cur["next_ptr_ct"]).hex()
            if nid not in shards:
                continue
            target = shards[nid]
            dec_perm = ctr(subkey(k, b"PERM"), target["perm_stored"])
            if (zlib.crc32(dec_perm) & 0xFFFFFFFF) == target["perm_crc"]:
                pinned = cand
                nxt = (nid, dec_perm)
                break
        if pinned is None:
            raise RuntimeError(f"chain disambiguation failed at step {step}")
        recovered.append(pinned)
        cur = shards[nxt[0]]
        cur_perm = nxt[1]
        step += 1

    seed = b"".join(recovered)
    if SigningKey(seed).verify_key.encode() != pubkey:
        raise RuntimeError("recovered seed does not match public key")
    return seed


def attest(url, seed):
    nonce_hex = urllib.request.urlopen(url + "/attest").read().decode().strip()
    nonce = bytes.fromhex(nonce_hex)
    sig = SigningKey(seed).sign(nonce).signature
    data = ("nonce=" + nonce_hex + "&sig=" + sig.hex()).encode()
    resp = urllib.request.urlopen(url + "/attest", data=data).read().decode().strip()
    return resp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--url", default=None)
    args = ap.parse_args()
    seed = solve_offline(args.bundle)
    sys.stderr.write("recovered seed: " + seed.hex() + "\n")
    if args.url:
        print(attest(args.url, seed))


if __name__ == "__main__":
    main()

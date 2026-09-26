import os
import sys
import json
import struct
import random
import hashlib
import argparse

import vmisa
import shardfmt as sf
from nacl.signing import SigningKey

NLANES = 8
ROUNDS = 3
FREE_PLAN = [4, 5, 5, 6]
BODY_TARGET = 600


def derive_seed(flag, team_id):
    return hashlib.sha256(b"kintsugi:token:" + flag.encode() + b"|" + team_id.encode()).digest()


def struct_rng(flag, team_id):
    h = hashlib.sha256(b"kintsugi:struct:" + flag.encode() + b"|" + team_id.encode()).digest()
    return random.Random(int.from_bytes(h, "big"))


def rand_perm(rng):
    p = list(range(256))
    rng.shuffle(p)
    return p


def inverse_perm(enc):
    dec = [0] * 256
    for i, v in enumerate(enc):
        dec[v] = i
    return dec


def pick_free_bits(rng, count):
    bits = rng.sample(range(64), count)
    lane_mask = [0xFF] * NLANES
    for b in bits:
        lane = b // 8
        bit = b % 8
        lane_mask[lane] &= ~(1 << bit) & 0xFF
    return lane_mask


def diffusion_pairs():
    pairs = []
    for i in range(NLANES):
        pairs.append((i, (i + 1) % NLANES))
    for i in range(NLANES):
        pairs.append((i, (i + 3) % NLANES))
    return pairs


def build_real_program(rng, sbox, sec8, lane_mask):
    p = vmisa.Program()
    for i in range(NLANES):
        p.lds(i, i)
    for i in range(NLANES):
        if lane_mask[i] != 0xFF:
            p.xori(i, rng.randint(0, 255))
            p.andi(i, lane_mask[i])
    consts = [rng.randint(0, 255) for _ in range(ROUNDS * NLANES)]
    pairs = diffusion_pairs()
    for r in range(ROUNDS):
        for i in range(NLANES):
            p.sbox(i, i)
        for (i, j) in pairs:
            p.xor(i, j)
        for i in range(NLANES):
            p.xori(i, consts[r * NLANES + i])
    pad_body(p)
    body = p.bytes()
    regs = vmisa.trace_regs(body, sbox, [b & m for b, m in zip(sec8, lane_mask)])
    for i in range(NLANES):
        p.assert_(i, regs[i])
    p.halt()
    return p.bytes()


def pad_body(p):
    while len(p.code) < BODY_TARGET:
        p.mov(0, 0)


def build_decoy_program(rng, sbox, sec8):
    p = vmisa.Program()
    for i in range(NLANES):
        p.lds(i, i)
    for i in range(NLANES):
        p.sbox(i, i)
    for i in range(NLANES):
        p.add(i, (i + 2) % NLANES)
    for i in range(NLANES):
        p.rol(i, rng.randint(1, 30))
    for i in range(NLANES):
        p.mul(i, (i + 5) % NLANES)
    for i in range(NLANES):
        p.or_(i, (i + 1) % NLANES)
    for i in range(NLANES):
        p.xori(i, rng.randint(0, 0xFFFFFFFF))
    pad_body(p)
    body = p.bytes()
    regs = vmisa.trace_regs(body, sbox, sec8)
    for i in range(NLANES):
        p.assert_(i, regs[i])
    p.halt()
    return p.bytes()


def store_program(rng, canonical):
    enc = rand_perm(rng)
    dec = inverse_perm(enc)
    stored = vmisa.permute_opcodes(canonical, enc)
    return stored, bytes(dec)


def brute_free(sec8, lane_mask):
    bit_slots = []
    for i in range(NLANES):
        freemask = (~lane_mask[i]) & 0xFF
        for b in range(8):
            if freemask & (1 << b):
                bit_slots.append((i, b))
    base = [sec8[i] & lane_mask[i] for i in range(NLANES)]
    sols = []
    for combo in range(1 << len(bit_slots)):
        cand = list(base)
        for k, (lane, b) in enumerate(bit_slots):
            if combo & (1 << k):
                cand[lane] |= (1 << b)
        sols.append(bytes(cand))
    return sols, bit_slots


def build_bundle(flag, team_id, outdir):
    seed = derive_seed(flag, team_id)
    sk = SigningKey(seed)
    pubkey = sk.verify_key.encode()

    secs = [seed[i * 8 : i * 8 + 8] for i in range(4)]
    keys = [sf.shard_key(s) for s in secs]

    for attempt in range(64):
        rng = struct_rng(flag, team_id + f"#{attempt}")
        ids = [rng.randbytes(16) for _ in range(4)]
        sboxes = [bytes(rand_perm(rng)) for _ in range(4)]
        masks = [pick_free_bits(rng, FREE_PLAN[i]) for i in range(4)]

        progs = [build_real_program(rng, sboxes[i], secs[i], masks[i]) for i in range(4)]
        stored = [store_program(rng, progs[i]) for i in range(4)]

        if not chain_is_unique(secs, keys, ids, sboxes, stored, masks, pubkey):
            continue

        write_shards(rng, outdir, ids, keys, sboxes, stored, masks)
        write_decoys(rng, outdir)
        with open(os.path.join(outdir, "pubkey.bin"), "wb") as f:
            f.write(pubkey)
        write_manifest(outdir, ids[0], team_id)
        return {"start": ids[0].hex(), "team_id": team_id, "seed": seed.hex()}
    raise RuntimeError("could not build a clean bundle")


def chain_is_unique(secs, keys, ids, sboxes, stored, masks, pubkey):
    for i in range(4):
        dec_perm = stored[i][1]
        canon = vmisa.permute_opcodes_dec(stored[i][0], dec_perm)
        sols, _ = brute_free(secs[i], masks[i])
        if not vmisa.run(canon, sboxes[i], secs[i]):
            return False
        good = [c for c in sols if vmisa.run(canon, sboxes[i], c)]
        if len(good) != (1 << FREE_PLAN[i]):
            return False
        if i < 3:
            matches = 0
            for c in good:
                k = sf.shard_key(c)
                nid = sf.dec_ptr(k, sf.enc_ptr(keys[i], ids[i + 1]))
                if nid != ids[i + 1]:
                    continue
                target = stored[i + 1][1]
                blob = sf.enc_perm(keys[i], target)
                if sf.dec_perm(k, blob) == target and sf.perm_checksum(sf.dec_perm(k, blob)) == sf.perm_checksum(target):
                    matches += 1
            if matches != 1:
                return False
        else:
            matches = 0
            base = secs[0] + secs[1] + secs[2]
            for c in good:
                cand = base + c
                if SigningKey(cand).verify_key.encode() == pubkey:
                    matches += 1
            if matches != 1:
                return False
    return True


def write_shards(rng, outdir, ids, keys, sboxes, stored, masks):
    for i in range(4):
        dec_perm = stored[i][1]
        if i == 0:
            flags = sf.FLAG_START
            perm_stored = dec_perm
        else:
            flags = 0
            perm_stored = sf.enc_perm(keys[i - 1], dec_perm)
        if i == 3:
            flags |= sf.FLAG_TERMINAL
            next_ptr = b"\x00" * 16
        else:
            next_ptr = sf.enc_ptr(keys[i], ids[i + 1])
        blob = sf.pack(ids[i], flags, 0, perm_stored, dec_perm, next_ptr, sboxes[i], stored[i][0])
        with open(os.path.join(outdir, ids[i].hex() + ".shard"), "wb") as f:
            f.write(blob)


def write_decoys(rng, outdir):
    for _ in range(3):
        did = rng.randbytes(16)
        sbox = bytes(rand_perm(rng))
        sec = rng.randbytes(8)
        prog = build_decoy_program(rng, sbox, sec)
        stored, dec_perm = store_program(rng, prog)
        next_ptr = rng.randbytes(16)
        blob = sf.pack(did, 0, 0, dec_perm, dec_perm, next_ptr, sbox, stored)
        with open(os.path.join(outdir, did.hex() + ".shard"), "wb") as f:
            f.write(blob)


def write_manifest(outdir, start_id, team_id):
    text = (
        "Kintsugi Vault shard dump\n"
        "team: " + team_id + "\n"
        "chain start: " + start_id.hex() + "\n"
        "shards are named by content id; order is not preserved on disk\n"
        "the start shard carries its decode table in the clear\n"
        "reassemble the 32 byte custody seed, then re-attest at the live endpoint\n"
    )
    with open(os.path.join(outdir, "MANIFEST.txt"), "w") as f:
        f.write(text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--flag", default=os.environ.get("FLAG", "H7CTF{local_test_flag_0000}"))
    ap.add_argument("--team", default=os.environ.get("TEAM_ID", "team-local"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    info = build_bundle(args.flag, args.team, args.out)
    sys.stderr.write(json.dumps(info) + "\n")


if __name__ == "__main__":
    main()

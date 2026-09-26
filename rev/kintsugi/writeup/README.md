# Kintsugi - author writeup

This document is not shipped to players.

## What the player gets

- `vmrun`: a stripped static ELF interpreter for a small custom VM.
- `N` `.shard` files (4 real, 3 decoy) named by random content id.
- `pubkey.bin`: the per-instance Ed25519 public key.
- `MANIFEST.txt`: names the chain-start shard.
- a live `/attest` endpoint.

## The VM

`vmrun` decodes a tiny bytecode. Reversing it once recovers the ISA:

- registers r0..r7, 32 bit
- `LDS rd, i`  load secret byte i
- `LDI/MOV/XOR/ADD/MUL/AND/OR/ROL`  usual arithmetic (mod 2^32)
- `SBOX rd, rs`  `rd = sbox[rs & 0xff]` where the 256 byte table lives in the shard
- `ANDI/XORI rd, imm32`
- `ASSERT rs, imm32`  require `rs == imm`, otherwise reject
- `HALT`

The opcode byte of every instruction is permuted per shard by a 256 entry
decode table. `vmrun` reads that table from the shard header. Operand bytes are
not permuted, and there are no jumps, so a linear walk by instruction width
decodes the stream once the table is known.

`SBOX` is a secret-indexed table load. Symbolic execution of the native binary
blows up on it; the clean path is to model it in an SMT solver as a lookup.

## Shard layout

Header (50 bytes): magic `KSHD`, lengths, a 16 byte self id, a CRC32 of this
shard's own decode table, and a 16 byte encrypted next-pointer. Then the stored
(possibly encrypted) decode table, a 256 byte SBOX, and the program.

Each real shard carries 8 bytes of the 32 byte custody seed and asserts a mixed
function of them. The mixing per shard is: mask a handful of input bits, then
three rounds of `SBOX` on each lane, a fixed invertible XOR diffusion across
lanes, and a per-round XOR constant, then assert every lane. Because the SBOX is
a permutation and the diffusion is invertible over GF(2), the map is a bijection
on the bits that are not masked. The masked input bits are therefore free: the
per-shard constraint has exactly `2^k` satisfying assignments (k varies 4..6).

## The trap

Solve one shard with an SMT solver and it returns SAT with one model. Take that
model as the answer and you are wrong on the masked bits with probability
`1 - 2^-k`. Worse, the chain does not extend from a wrong model, because:

## The chain

- `K_i = SHA256(sec_i)`.
- Shard `i`'s next-pointer is `AES-CTR(SHA256(K_i + "PTR"), id_{i+1})`.
- Shard `i+1`'s decode table is stored `AES-CTR(SHA256(K_i + "PERM"), table)`.
- Each shard stores CRC32 of its own decrypted decode table.

So shard `i+1` cannot even be lifted until you have the true `K_i`, and `K_i`
needs the full 8 true bytes of shard `i`. The disambiguator: for each of the
`2^k` candidate secrets of shard `i`, derive `K`, decrypt the next-pointer, look
up that file, decrypt its decode table, and check the stored CRC32. Exactly one
candidate matches. That pins the true 8 bytes and simultaneously unlocks the
next shard.

The start shard ships its decode table in the clear, so it is the entry point.
The terminal shard has no successor: its `2^k` candidates are resolved by
deriving the Ed25519 public key from the assembled 32 byte seed and comparing to
`pubkey.bin`.

## Re-attestation

The recovered 32 bytes are an Ed25519 seed. `GET /attest` yields a fresh nonce;
sign it and `POST` `nonce` and `sig`. The verifier checks the signature under
the baked per-instance public key and returns the flag. The nonce is single use,
so a captured signature cannot be replayed and there is no partial feedback to
probe. Because the keypair is per team, a seed or signature from another team
fails; only the recovery tool is shareable.

## Reference solver

`solution/solve.py`:
1. parse all shards, find the start.
2. for each shard: model the decoded program in z3, get one model, then find the
   free bits by flipping each input bit of that model and re-running the program
   (a determined bit always breaks an assert; a masked bit never does), then
   enumerate the `2^k` candidates.
3. walk the chain with the CRC32 next-shard oracle, pin each shard, decrypt the
   next decode table.
4. resolve the terminal shard against `pubkey.bin`, assemble the seed, fetch a
   nonce, sign, and submit.

## Anti-agent notes

- Per instance the seed is a pure function of (FLAG, team_id); `gen.py`
  self-verifies at build that every shard has exactly `2^k` models and that the
  CRC oracle and the terminal pubkey both disambiguate uniquely, re-rolling the
  structural seed on any collision. A bundle that does not solve cleanly is
  never shipped.
- Shards are uniform length; decoys are indistinguishable from real mid-chain
  shards without solving.
- No literal seed byte, flag, or technique name appears in any shipped file.

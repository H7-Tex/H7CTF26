# Kintsugi

**Category:** Rev  **Difficulty:** Hard  **Author:** abu

> A retired key-custody vault shattered its root seed across a mesh of tiny guardian agents and lost the tool that glues them back. The re-attestation socket is still listening.
>
> Put the seed back together and prove it to the socket.

One instance per team over HTTP. Each instance generates its own bundle (`handout.tar.gz`): `vmrun`, seven `.shard` files (four real, three decoys) named by content id, `pubkey.bin`, `MANIFEST.txt` naming the start shard, and `handout/README.md`. The flag comes from `/attest`.

## Solution

`vmrun` is a stripped static interpreter for a small VM. Eight 32 bit registers, `LDS` to load a secret byte, the usual arithmetic, `SBOX rd, rs` (a 256 byte table stored in the shard), `ANDI`/`XORI`, `ASSERT rs, imm` and `HALT`. There are no jumps. The opcode byte is permuted per shard through a 256 entry decode table in the shard header, but operands aren't, so once you have the table a linear walk decodes everything.

Each real shard holds 8 bytes of the 32 byte seed. It masks a few input bits, runs three rounds of SBOX plus an invertible XOR diffusion, and asserts every lane. `SBOX` is a secret indexed load, so symbolic execution of the native binary falls over on it. Modelling it in z3 as an array lookup works fine.

The trap: z3 says SAT and hands you one model, but the masked bits are free. Each shard has `2^k` valid answers (k between 4 and 6), and one model is almost always wrong. You can't tell from the shard alone. The chain tells you:

```
K_i            = SHA256(sec_i)
next_ptr_i     = AES-CTR(SHA256(K_i + "PTR"), id_{i+1})
table_{i+1}    = AES-CTR(SHA256(K_i + "PERM"), real_table)
```

Every shard also stores the CRC32 of its own decrypted decode table. So for each of the `2^k` candidates of shard `i`, derive `K_i`, decrypt the next pointer, open that shard, decrypt its table and check the CRC. Exactly one candidate passes, and that also unlocks the next shard. The start shard has its table in the clear. The last shard has no successor, so its candidates get resolved by deriving the Ed25519 public key from the full seed and comparing against `pubkey.bin`.

To find the free bits we took the z3 model and flipped each input bit one at a time. A bit that matters always breaks an assert; a masked bit never does. Then enumerate.

The 32 bytes are an Ed25519 seed. `GET /attest` gives a single use nonce, sign it, `POST` `nonce` and `sig` in hex, get the flag. Keys are per team, so sharing a seed doesn't help anyone.

```
python3 solution/solve.py --bundle <extracted_dir> --url http://<instance>
```

Flag: dynamic, `H7CTF{...}` per team.

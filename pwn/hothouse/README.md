# Hothouse

**Category:** pwn  **Difficulty:** insane  **Author:** abu

> A firmware control link for a cellular-automaton coprocessor. Load a seed lattice, let it incubate for a few generations, and fire the settled fabric on the core.
>
> Coax the fabric into doing something it was never meant to, and read the flag off the box.

Handout: `handout/hothouse.zip` (stripped static `hothouse` and `RULE.md`, which documents the protocol and the bit packing but not the growth rule).

```
docker build -t hothouse . && docker run --rm -p 1337:1337 -e FLAG='H7CTF{dummy}' hothouse
```

## Solution

The fabric is 128 bytes at the start of an RWX page, a 32x32 bit lattice with `cell(r,c) = bit (c&7) of byte r*4 + (c>>3)`. You can't write it. You `SEED` cells, `INCUBATE` grows them, `FIRE` installs seccomp, closes stdin and jumps to the fabric.

Reversing `INCUBATE`: 7 generations, each cell becomes the XOR of 6 neighbours (N, S, E, W, NE, SW, no center), then a per-cell substrate bit is XORed in. Dead boundary. Over GF(2) that's affine:

```
fabric = M^7 * seed ^ b
```

`M^7` has rank 992 out of 1024. So a random full 128-byte target has no preimage, and a naive Gaussian solve of the whole fabric says "inconsistent". That's the trap.

The leak is in `PROBE r c`. It computes `off = r*4 + (c>>3)` and only checks `r > 31 || c > 31`. Negative `r` reads below the fabric, clamped to the page just under it. That page holds the flag path, `/flag_<16 hex>`. The entrypoint writes `$FLAG` there with mode 0400 and unsets the env var, so you get the path but never the value. Scan the page with negative `r` to read it.

Then:

1. `INCUBATE` with no seed and read the fabric back. That's `b`, which is reseeded per connection.
2. Build `M^7` offline by evolving each of the 1024 unit seeds.
3. Write a small ORW: `openat(AT_FDCWD, path)`, `read`, `write(1)`, `exit_group`, with the leaked path inline and the read buffer past the lattice in the RWX page.
4. Only constrain the payload bytes (around 100), not the whole fabric. It ends in `exit_group`, so the tail never runs. About 800 constrained rows fit inside a rank-992 image, so the reduced system is solvable.
5. Solve `M^7 * seed = payload ^ b` on those rows, `SEED` the bits, `INCUBATE`, `FIRE`.

Dead ends: seeding the shellcode directly (incubate scrambles it), black-box mutate-and-compare (no preimage, and `INCUBATE` is capped at 64), and a tiny `read(0, ...)` stager (stdin is closed before the jump). The solve uses roughly 400 SEED, 2 INCUBATE and 4200 PROBE, well under the caps.

```
python3 solution/solve.py <host> <port>
```

Pure stdlib. Flag is dynamic per team.

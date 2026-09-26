# Hothouse - author writeup

Category: pwn. Difficulty: hard.

This document is for authors and reviewers. It is not shipped to players.

## The service

`hothouse` is a single static x86-64 C service behind socat, one connection per
instance. It models a firmware control link for an additive cellular-automaton
coprocessor of the kind used for on-die pattern generators.

- An executable arena is mapped as two adjacent pages. The high page is a 4096
  byte RWX region; its first 128 bytes are the fabric, a 32x32 bit lattice packed
  as `cell(r,c) = bit (c&7) of byte r*4 + (c>>3)`. The low page is a read-write
  metadata page that holds the flag file path.
- `SEED r c` lights one seed cell. It is the only write primitive and it validates
  coordinates.
- `INCUBATE` runs the growth rule for 7 generations. Each generation each cell
  becomes the XOR of a fixed asymmetric 6-cell stencil (N, S, E, W, NE, SW; the
  center is omitted) of the previous generation, then a fixed per-cell substrate
  bit is XORed in. The boundary is dead. The settled lattice is packed into the
  fabric.
- `PROBE r c` reads back one fabric byte as `Tc: <n>`.
- `RENDER` prints the fabric.
- `FIRE` installs a seccomp allowlist, closes stdin, and jumps to the fabric.

## Why growth is linear

One generation over GF(2) is `g -> M g XOR m` where `M` is the 1024x1024 stencil
operator and `m` is the substrate bias. Seven generations is affine:

    fabric = M^7 * seed  XOR  b,   b = (M^6 + ... + M + I) m

`M^7` for this stencil has rank 992, so its kernel has dimension 32. `M^7` is
singular: its image is a codimension-32 subspace. A randomly chosen full 128 byte
target has no preimage. That is the Garden-of-Eden trap: a naive Gaussian solve of
the whole fabric returns "inconsistent", which reads as impossible.

## The leak

`PROBE` computes `off = r*4 + (c>>3)` with `r`, `c` parsed as signed ints and only
range-checked on the high side (`c > 31 || r > 31`). The negative guard is missing,
so a negative `r` walks `off` below the fabric. The read is clamped to the mapped
arena (`off >= -4096`), so it is a narrow relative-read oracle over the metadata
page directly below the fabric, and nothing else. That page holds the per-instance
flag file path `/flag_<16 hex>`. Scan the page byte by byte to recover it.

The flag value is never in the service. The entrypoint writes `$FLAG` to
`/flag_<hex>`, chmods it 0400, unsets `FLAG`, and passes only the path via
`FLAGPATH`. So the oracle can leak the path but never the flag, and the clamp keeps
it from reaching environ or the binary.

## Intended path

1. Reverse the stripped binary: recover the packing, the 6-cell stencil, `N=7`, and
   note the missing negative guard in `PROBE`.
2. Use `PROBE` with negative `r` to dump the metadata page and recover the flag
   file path.
3. Recover `b`: `INCUBATE` with an all-zero seed and read the fabric back. That is
   `b` directly.
4. Build `M^7` offline by evolving each of the 1024 unit seeds for 7 generations;
   the results are the columns of `M^7`.
5. Write a seccomp-safe ORW payload (`openat(AT_FDCWD, path, O_RDONLY)`, `read`,
   `write(1, ...)`, `exit_group`) with the leaked path embedded and a read buffer
   in the RWX page past the lattice. Do not try to grow the whole 128 byte fabric.
   Constrain only the contiguous payload bytes (about 100 bytes here). Since the
   payload ends in `exit_group`, execution never reaches the uncontrolled tail, so
   those cells are free. That is why the reduced system is consistent: about 800
   constrained output rows sit inside the rank-992 image, and the free cells absorb
   the codimension-32 kernel.
6. Solve `(M^7 * seed) = (payload XOR b)` on the constrained coordinates with GF(2)
   Gaussian elimination. `SEED` the solved bits, `INCUBATE`, `FIRE`.
7. The fabric runs the grown ORW microcode and writes the flag to stdout.

`solution/solve.py` does all of this over a raw socket and needs no third party
libraries. Local run recovers e.g. `H7CTF{test_flag_9f3a7c21e0b4}`.

## Dead ends

- SEED your finished shellcode directly, INCUBATE, FIRE. `INCUBATE` is `M^7`, not
  identity, so the fabric becomes noise and the core faults.
- Black-box search: mutate seed, INCUBATE, compare fabric to the target, repeat.
  The full target is a Garden-of-Eden with no preimage, so this can never converge,
  and the INCUBATE budget is capped at 64 to kill it.
- Read the flag value out of memory with the PROBE oracle. The value is never in
  the process and the oracle is clamped to the arena.

## Notes for reviewers

- The read-stager variant (grow a tiny `read(0, fabric, n); jmp fabric` stub, then
  send the ORW as socket bytes) is deliberately blocked: `FIRE` closes stdin before
  jumping, so there is no fd 0 to stage from. The intended path grows the real ORW.
- Anti-replay: the substrate bias `b` is reseeded per connection and the flag path
  is per instance, so a hardcoded SEED trace from one run grows garbage on the next.
  A parametric solver that re-leaks and re-solves each run is the intended tool.
- Budgets: SEED 4096, INCUBATE 64, PROBE 20000. The intended solve uses about 400
  SEED, 2 INCUBATE, and about 4200 PROBE, all comfortably inside the caps.

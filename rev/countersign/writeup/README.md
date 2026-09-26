# Countersign

Category: rev. Difficulty: insane.

## What ships

Players get the stripped `countersign` ELF and a short protocol note. The live
service runs the same ELF behind `socat`, one fresh process per connection, so
every instance boots its own 16 byte key `K` from `/dev/urandom`, its own 64 bit
nonce, and generates its own program image. `K` never touches disk and is never
emitted. The flag is injected as the `FLAG` environment variable and is only
ever produced by a live `RUN`.

## The core

The core is a basic block VM. Registers are eight 32 bit words. The ISA is about
sixteen opcodes (LDI, MOV, ADD, XOR, AND, OR, ROL, SHR, ADDI, XORI, ANDI,
LOADIN, LOADFLAG, EMIT, HALT). A block is a code stream plus an edge table.

Control flow is attested. At the end of a block the dispatcher computes a one bit
condition value from a register, then, among the edges whose stored condition
matches, it follows the first edge whose 48 bit tag verifies:

    tag == siphash24(K, src16 || dst16 || cond8 || salt32)[:6]

An edge whose tag does not verify is skipped. If nothing verifies the dispatcher
diverges to a stored poison destination instead of crashing.

The program encodes a 24 byte license check: load the input into six words, run
twelve rounds of ARX mixing with a per instance data dependent branch each round,
then compare the final state against a per instance target baked into the last
block. Equal drives LOADFLAG then EMIT; not equal drives a silent reject.

## Why a local emulator lies

The program image is full of poison edges. For every real edge the generator adds
one or two decoy edges that carry the same condition, a plausible destination
that is a real block id, and a random tag. The edge order inside each block is
shuffled, and edge counts vary. Real and poison edges are byte for byte the same
shape. The only thing that separates a real edge from a decoy is whether its tag
verifies under `K`, and `K` is not in any artifact.

So a faithful offline emulator is inert: every MAC fails without `K`. The
tempting fix, ignore the tags and follow the edges, walks into poison, because
poison is interleaved and there is no positional rule that recovers the real
graph. An emulator that guesses runs clean and produces a confident wrong input.

## The intended break

The bug is one helper shared by the edge verifier and a leftover debug command:

    build_tag_msg(buf, domain, data, len) { buf[0] = domain; memcpy(buf, data, len); }

The domain byte written at offset 0 is immediately overwritten by the caller's
data, so domain separation is dead. The `MINT <hex>` command was meant to stamp
its own domain, but through this helper `MINT(m)` returns exactly
`siphash24(K, m)[:6]` for any chosen message up to 16 bytes. The edge tag message
is 9 bytes, well under the limit. `MINT` is therefore a chosen message edge tag
oracle for this instance's key.

## The path

1. Reverse the stripped core: recover the ISA, the blob layout, and the attested
   dispatcher. Notice a local emulator halts on the first edge without `K`.
2. Read the two message builders and spot the dead store. Realise `MINT` signs
   arbitrary bytes under `K`.
3. `GET` the instance image. For every candidate edge, rebuild its 9 byte tag
   message, `MINT` it, and keep only edges whose stored tag matches. This prunes
   the poison shadow and leaves the true CFG (about 130 `MINT` calls here).
4. Lift the real blocks to a bitvector transfer function. Each round is a diamond
   whose two arms reconverge, so the branch is an `If` merge on the condition bit.
   Assert that the final compare falls toward EMIT and solve with z3 for the 24
   byte input. z3 returns in seconds.
5. `RUN` the input on the live service. The real CFG executes, LOADFLAG reads
   `$FLAG`, EMIT prints the per team flag.

`MINT` can never reach EMIT: it only returns a tag and never runs the VM, and the
live service runs its own fixed image that no player can replace, so forged tags
are useful only for offline devirtualization. The nonce bound target forces each
team to run its own solve rather than replay a shared input.

## Reference solver

`solution/solve.py` does the whole path against either a local binary
(`python3 solve.py ./countersign`) or a live service
(`python3 solve.py <host> <port>`). It labels edges purely through `MINT`, never
using `K` or any build time secret, then solves with z3 and submits `RUN`.

## Fixes applied from the design review

- A: real and poison edges share shape; order is shuffled per block and edge
  counts vary, so position leaks nothing. The only distinguisher is the keyed tag.
- B: the branch per round is per edge, so the coherent CFG space is exponential
  and enumerate then RUN is hopeless. Per edge labeling via MINT is the only route.
- C: the tag covers only statically derivable fields (src, dst, cond, per edge
  salt), never a runtime trace counter, so MINT precomputes every candidate tag
  offline.
- D: the ARX check is z3 tractable in seconds while being far beyond brute force
  (24 byte input) and not a clean hand inversion because of the data dependent
  branches. The target is fixed by running the core forward on a throwaway secret
  at boot, so a solution always exists.
- E: the shipped ELF is stripped, so localizing the helper is real RE work.
- G: validated that MINT cannot reach EMIT and that no positional skip MINT
  reconstruction yields a runnable input.

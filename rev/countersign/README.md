# Countersign

**Category:** Rev  **Difficulty:** Insane  **Author:** abu

> Countersign is the attestation core of a licensed firmware module. Slide a pass under the glass and the clerk stamps whatever you hand him, but the core itself only ever walks a route it can vouch for.
>
> Find the input that walks it all the way to the flag.

Handout: `handout/countersign.zip` (the stripped `countersign` ELF and `note.txt`). One instance per team over TCP; the service runs the same ELF behind `socat`, one process per connection.

## Solution

Each process boots its own 16 byte key `K` and 64 bit nonce from `/dev/urandom` and generates its own program image. `K` is never written anywhere. The protocol is `GET` (program image as hex), `NONCE`, `MINT <hex>` and `RUN <hex>`.

The core is a basic block VM: eight 32 bit registers and about sixteen opcodes (LDI, MOV, ADD, XOR, AND, OR, ROL, SHR, ADDI, XORI, ANDI, LOADIN, LOADFLAG, EMIT, HALT). Each block is code plus an edge table. At the end of a block the dispatcher computes a one bit condition, and among the edges with that condition it follows the first one whose 48 bit tag verifies:

```
tag == siphash24(K, src16 || dst16 || cond8 || salt32)[:6]
```

If nothing verifies, it goes to a poison block instead of crashing. The program itself is a 24 byte licence check: load the input into six words, twelve rounds of ARX with a data dependent branch each round, compare against a per instance target. Equal runs LOADFLAG and EMIT.

The problem is that every real edge has one or two decoys next to it with the same condition, a real destination and a random tag. Edge order is shuffled per block. So writing an emulator gets you nowhere: without `K` no tag verifies, and if you ignore tags you walk straight into poison and get a confident wrong answer.

The bug is a helper shared by the edge verifier and the leftover `MINT` debug command:

```c
build_tag_msg(buf, domain, data, len) { buf[0] = domain; memcpy(buf, data, len); }
```

The domain byte gets overwritten by the `memcpy`, so there's no domain separation at all. `MINT(m)` returns exactly `siphash24(K, m)[:6]` for any message up to 16 bytes, and an edge tag message is 9 bytes. That's a tag oracle for this instance's key.

So the path is:

1. Reverse the stripped core: ISA, image layout, the dispatcher. Spot the dead store in the message builder.
2. `GET` the image. For every candidate edge, rebuild its 9 byte message, `MINT` it, keep the edges whose stored tag matches. About 130 `MINT` calls and the real CFG falls out.
3. Lift the real blocks into z3. Each round is a diamond that rejoins, so the branch is just an `If` on the condition bit. Assert the final compare goes to EMIT and solve for the 24 byte input. Takes seconds.
4. `RUN` it on the live service.

`MINT` never runs the VM and the service only runs its own image, so forged tags are only good for recovering the CFG offline. The target depends on the nonce, so every team has to solve their own instance.

```
python3 solution/solve.py <host> <port>
python3 solution/solve.py ./countersign
```

Flag: dynamic, `H7CTF{...}` per team.

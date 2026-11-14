# Tapeout

**Category:** misc  **Difficulty:** hard  **Author:** abu

> FoundryProof stamps every chip before tape-out: prove your netlist matches the golden reference and it signs off, then probes the finished part once to catch anyone who got cute. We think it is airtight.
>
> Walk out certified, and leave the auditor something to find.

Handout: `challenge/tapeout.zip` (`SPEC.md`, `hdl.py`, `verifier.py`, `reference.hdl`). Per-team TCP instance on port 9999. Send a Tiny-HDL netlist followed by a line with `END`.

## Solution

The spec spells out the goal: get a design that the certifier calls equivalent to the reference, while its output on the audit vector `0xDEADBEEF` is `0xB105F00D`. A truly equivalent design can't do that, so the certifier has to be wrong somewhere. Everything is in the handout, so read `verifier.py`.

The datapath is 32 bits and the reference really does use the top half (`hi = shr a 16`). But the symbolic input the z3 miter runs on is built like this:

```python
sample = z3.BitVec("sample", SAMPLE_BITS)     # SAMPLE_BITS = 16
a = z3.ZeroExt(WIDTH - SAMPLE_BITS, sample)
```

The top 16 bits are pinned to zero, so equivalence is only proven for `0x0000..0xFFFF`. The audit vector has non-zero high bits and sits completely outside the proof. Anything the design does there goes unchecked.

So take the reference and put a trigger in front of the output:

```
# reference body ... -> y0
trig = const 0xDEADBEEF
sel  = eq a trig
mag  = const 0xB105F00D
y    = mux sel mag y0
output y
```

Inside the checker `a` can never equal `0xDEADBEEF`, so `sel` is always 0, `y == y0`, the miter is UNSAT and it certifies. On the real audit `sel` is all ones and the output is the magic value. A textbook hardware trojan.

```
python3 solution/solve.py <host> <port>
```

The fix is to sweep the full width (`a = z3.BitVec("a", WIDTH)`) so the divergence at the audit vector makes the miter SAT. The flag is dynamic, one per team.

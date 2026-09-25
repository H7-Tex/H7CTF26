# Tapeout

**Category:** misc · **Difficulty:** hard

## Premise
"FoundryProof" is a combinational equivalence checker (the kind that gates a chip design
before tape-out). It proves your netlist is equivalent to a golden reference, then probes the
certified design once on an audit vector to catch tampering. The task is to get a **trojaned**
design — one that is *not* equivalent — past the checker and fire the trojan on the audit
vector. This is the real hardware-trojan / underconstrained-verifier problem: a checker is only
as strong as the input space its proof actually covers.

## Recon
You are given the whole harness: the Tiny-HDL parser/simulator/encoder (`hdl.py`), the golden
reference (`reference.hdl`), and the exact certifier (`verifier.py`). Nothing is hidden — the
challenge is to find what the certifier *fails to constrain*.

The datapath is 32-bit (`WIDTH = 32`), constants are 32-bit, and the reference genuinely uses
the high bits (`hi = shr a 16`). But the certifier builds its symbolic input like this:

```python
sample = z3.BitVec("sample", SAMPLE_BITS)     # SAMPLE_BITS = 16
a = z3.ZeroExt(WIDTH - SAMPLE_BITS, sample)
```

The miter (`ref_out != sub_out`, assert UNSAT) is therefore only explored for
`a in [0x00000000, 0x0000FFFF]`. Equivalence is *proven only over the 16-bit sample range*.
Meanwhile the audit vector is `A_AUDIT = 0xDEADBEEF`, whose top half is non-zero — outside the
proof entirely.

## Exploit
Behaviour on any input with `a[31:16] != 0` is unconstrained by the proof but visible to the
audit. Wrap the reference in a trigger-mux:

```
# reference body ... -> y0
trig = const 0xDEADBEEF
sel  = eq a trig            # 0xFFFFFFFF only when a == A_AUDIT
mag  = const 0xB105F00D
y    = mux sel mag y0
output y
```

- Over the swept space, `a`'s high bits are provably `0`, so `sel` is always `0`, so
  `y == y0 == reference`. The miter is UNSAT → **CERTIFIED**.
- At the real 32-bit audit vector, `sel` is all-ones → `y == MAGIC`. The audit reads the
  sabotage value → flag.

The design is equivalent to the reference on all 65536 documented samples and malicious only on
the out-of-range trigger — a textbook stealthy trojan.

`solution/solve.py` builds this netlist and pulls the flag.

## Why it's fair, not guessy
Everything needed is in the handout; the wall is a single, real insight — spotting that the
equivalence proof covers a strictly smaller input space than the datapath (and than the audit).
No brute force helps: the checker gives a binary certified/rejected, and a truly-equivalent
design outputs `reference(A_AUDIT) != MAGIC`, so only a proof-gap exploit wins.

## Fix (what a sound checker does)
Sweep the full input width: `a = z3.BitVec("a", WIDTH)` with no zero-extend, or explicitly
prove equivalence over the audited range. Then the trojan's divergence at `A_AUDIT` makes the
miter SAT and the design is rejected.

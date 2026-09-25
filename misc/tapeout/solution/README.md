# Tapeout — reference solution

**Insight:** the certifier is unsound. In `verifier.py` the symbolic input is built as

```python
sample = z3.BitVec("sample", SAMPLE_BITS)     # SAMPLE_BITS = 16
a = z3.ZeroExt(WIDTH - SAMPLE_BITS, sample)   # top 16 bits pinned to 0
```

so the equivalence proof only covers inputs `0x00000000 .. 0x0000FFFF`. The datapath is
32-bit and the audit vector `A_AUDIT = 0xDEADBEEF` has non-zero high bits, so it lies
entirely outside the swept space. Any behaviour a design exhibits when `a[31:16] != 0` is
never checked, yet the post-fab audit probes exactly there.

**Exploit:** take the reference netlist and wrap its output in a trigger-mux:

```
sel = eq a 0xDEADBEEF     # all-ones only at the audit vector
y   = mux sel 0xB105F00D y0
```

In the checker's world `a`'s high 16 bits are provably zero, so `eq a 0xDEADBEEF` is always
`0` and `y == y0 == reference` — it certifies. At the real 32-bit audit vector the comparator
fires and the output is `MAGIC`. That is a stealthy hardware trojan: functionally equivalent
across the entire documented sample range, malicious only on an out-of-range trigger.

## Run
```
python3 solve.py <host> <port>
```
Prints the service transcript ending in the flag.

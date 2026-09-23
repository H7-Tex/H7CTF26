# Rollback: intended solution

Launch the instance, then:
```
python3 solution/solve.py http://<instance>/
```
Reuses leaf 0 via the rollback, recovers its WOTS+ key, forges a backdoored
firmware, deploys it, and prints this instance's per-team `H7CTF{...}`.
(`solution/solve.py` imports the shipped `challenge/lms.py`.)

## Path
1. Read `lms.py`: firmware is signed with WOTS+ leaves under a Merkle tree, and
   each leaf must sign once. `POST /sign` advances the counter; `POST /rollback`
   resets it to 0.
2. Reuse leaf 0: repeat `rollback` then `sign` on distinct benign builds. Each
   signature reveals, for every Winternitz position `i`, the chain value
   `H^{d_i}(sk_i)` at that build's digit `d_i`.
3. Keep, per position, the value at the lowest digit seen. After ~150 reuses
   almost every position has been seen at digit 0, i.e. you hold `sk_i` itself.
   For a target digit `c_i >= min_i`, sign it as `H^{c_i - min_i}(known_i)`.
4. Forge a backdoored build (the marker the notary refuses to sign): grind a nonce
   until `H(firmware)`'s digits all dominate the recovered `min_i` (usually the
   first try), then assemble the WOTS+ signature. Attach leaf 0's Merkle auth path
   (unchanged) and `POST /deploy`. It verifies against the device root and boots.

The one-time rule exists precisely so a single signature cannot be extended (the
Winternitz checksum blocks it); reuse is what breaks it, and the counter reset is
the reuse.

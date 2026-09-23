# The Ledger Never Sleeps: intended solution

Launch the instance, then:
```
python3 solution/solve.py http://<instance>/
```
Collects approvals, recovers the private key, forges the `ADMIN_TRANSFER`
signature, and prints this instance's per-team `H7CTF{...}`.

## Path
1. Probe the reflexes and watch them fail: all `r` distinct (no repeated nonce),
   no top-bit bias, HNP/lattice finds nothing.
2. Query `POST /sign` a few times for benign approvals. From `s = k^-1(z + r d)`,
   each nonce is affine in the key: `k_i = A_i d + B_i` with `A_i = s_i^-1 r_i`,
   `B_i = s_i^-1 z_i`, `z_i = int(sha256(msg_i))`.
3. The nonces are an LCG `k_{i+1} = a k_i + c`. Over four consecutive nonces,
   `a = (k2-k1)/(k1-k0) = (k3-k2)/(k2-k1)`, so `(k2-k1)^2 = (k1-k0)(k3-k2)`,
   which eliminates both `a` and `c`. Substituting the affine `k_i` gives a
   quadratic in `d`; solve it mod `n` (Tonelli-Shanks) and keep the root with
   `d*G == Q`.
4. Forge: pick any nonce `k`, set `r = (kG).x mod n`, `s = k^-1(z_admin + r d)`,
   and `POST /forge {ADMIN_MSG, r, s}` -> the flag.

z3 also solves step 3 directly from the sign/LCG constraints; the reference solver
uses the closed-form quadratic so it needs nothing beyond `ecdsa`.

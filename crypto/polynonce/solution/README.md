# Polynonce: intended solution

Launch the instance, download `signatures.json` and `flag.enc` from
`http://<instance>/`, then:
```
python3 solution/solve.py <dir-with-downloaded-files>
```
Recovers the private key and decrypts `flag.enc` to this instance's
per-team `H7CTF{...}`. (Local test: `FLAG='H7CTF{test}' python3
challenge/gen.py /tmp/inst && python3 solution/solve.py /tmp/inst`.)

## Path
1. Try the reflexes first and watch them fail: no repeated `r`, no top-bit bias,
   HNP/lattice finds nothing. The nonces are not random but not obviously weak.
2. Write each nonce in terms of the unknown key. From `s = k^-1 (z + r d)`:
   `k_i = A_i d + B_i (mod n)` with `A_i = s_i^-1 r_i`, `B_i = s_i^-1 z_i`.
3. Guess the nonces satisfy a low-degree recurrence and sweep the degree. At
   degree 2, `k_{i+1} = c2 k_i^2 + c1 k_i + c0`. Stacking rows
   `[k_i^2, k_i, 1, k_{i+1}]`, the vector `(c2, c1, c0, -1)` is a null vector, so
   every 4x4 block determinant is zero at the true `d`.
4. Each determinant is a polynomial in `d` (the `k_i` are affine in `d`). Take its
   roots mod `n` and keep the one with `d*G == Q`.
5. `key = SHA256(d_be32)`, `iv = SHA256("Qx,Qy")[:12]`, AES-256-GCM decrypt
   `flag.enc`.

Players can do steps 3-4 in one line with SageMath's `GF(n)[]` `.roots()`; the
reference solver ships a pure-Python `roots_mod_p` (gcd with `x^n - x`, then
equal-degree splitting) so no Sage is required to reproduce it.

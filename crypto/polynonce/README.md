# Polynonce

**Category:** crypto  **Difficulty:** hard  **Author:** abu

> Aurum's treasury signer rubber-stamps transfers by the batch, day in and day out. The engineer who wired it up cut a corner to keep the queue moving, then quietly left the company.
>
> The corner he cut is still signing every approval.

Each instance generates a fresh key and serves `signatures.json` and `flag.enc` over HTTP on port 8080.

## Solution

We get eight ECDSA signatures on secp256k1, the public key `Q`, and an encrypted flag. Repeated `r`? No. Biased nonces for a lattice? No. The nonces look clean one at a time.

The trick is that each nonce comes from the previous one through a hidden degree-2 recurrence (the Kudelski Polynonce attack from DEF CON 31):

```
k_{i+1} = c2*k_i^2 + c1*k_i + c0   (mod n)
```

From the signature equation every nonce is affine in the private key: `k_i = A_i*d + B_i` with `A_i = r_i/s_i` and `B_i = z_i/s_i`.

The recurrence is linear in the unknown coefficients, so `(c2, c1, c0, -1)` is a null vector of the matrix with rows `[k_i^2, k_i, 1, k_{i+1}]`. Any 4x4 window of it has determinant zero. Substitute `k_i = A_i*d + B_i` and that determinant becomes a polynomial in `d` of degree at most 4. Its roots mod `n` are the key candidates; keep the one with `d*G == Q`.

In Sage it's a few lines:

```python
R.<x> = GF(n)[]
P = Matrix([[(A[i]*x+B[i])^2, A[i]*x+B[i], 1, A[i+1]*x+B[i+1]] for i in range(t, t+4)]).det()
cands = [r for r, _ in P.roots()]
```

If you try degree 1 first (plain LCG) you get nothing; it has to be degree 2. The reference solver does the root finding in pure Python so it doesn't need Sage.

Decrypt the flag with:

```
key = SHA256(d as 32-byte big-endian)
iv  = SHA256("Qx,Qy")[:12]     (decimal coordinates)
flag.enc = AES-256-GCM ciphertext || 16-byte tag
```

```
python3 solution/solve.py <dir with signatures.json and flag.enc>
```

Local:

```
FLAG='H7CTF{test}' python3 challenge/gen.py /tmp/inst
python3 solution/solve.py /tmp/inst
```

Flag is dynamic, per team.

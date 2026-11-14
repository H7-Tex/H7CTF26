# The Ledger Never Sleeps

**Category:** crypto  **Difficulty:** hard  **Author:** abu

> The Aurum treasury signer is online. Send it an approval and it signs, but it always refuses an admin transfer. To shave a step off every signature, a former engineer reworked the signing routine, and the audit never noticed.
>
> Recover the signing key from the approvals it issues, then authorize the transfer it would never sign.

Per-team HTTP instance on port 8080: `GET /pubkey`, `POST /sign {msg}`, `POST /forge {msg, r, s}`.

## Solution

It's an ECDSA signer on secp256k1. The usual checks come up empty: every `r` is different so there's no repeated nonce, and the nonces have no bias, so HNP/lattice stuff finds nothing. The weakness is in how consecutive nonces relate to each other.

The nonce is an LCG, `k_{i+1} = a*k_i + c (mod n)`, with secret `a` and `c`.

From `s = k^-1 (z + r*d)`, every nonce is affine in the key:

```
k_i = A_i*d + B_i   with   A_i = r_i/s_i,  B_i = z_i/s_i,  z_i = sha256(msg_i)
```

Over four consecutive nonces, `a = (k2-k1)/(k1-k0) = (k3-k2)/(k2-k1)`, so

```
(k2 - k1)^2 = (k1 - k0)(k3 - k2)
```

which gets rid of both `a` and `c`. Plug in `k_i = A_i*d + B_i` and it's a quadratic in `d` mod `n`. Solve it with Tonelli-Shanks and keep the root where `d*G == Q`. z3 also gets there if you just throw the constraints at it.

With `d`, sign the admin message yourself: random `k`, `r = (k*G).x`, `s = k^-1 (z_admin + r*d)`, and send it to `/forge`.

```
python3 solution/solve.py http://<instance>/
```

Local:

```
FLAG='H7CTF{test}' PORT=8080 python3 challenge/app.py &
python3 solution/solve.py http://127.0.0.1:8080
```

This is the degree-1 version of Polynonce. Flag is dynamic, per team.

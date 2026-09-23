# The Ledger Never Sleeps: writeup

## The setup
A live ECDSA signer (secp256k1, order `n`) exposes `POST /sign {msg}` and hands
back `(r, s)`. It refuses to sign an `ADMIN_TRANSFER`. The story: to skip an RNG
call per signature, the nonce is a deterministic chain. The audit checked the two
usual things (no repeated nonce, no bit bias) and both pass, because they are true.

## Why the reflexes fail
- **Repeated `k`**: every `r` is distinct, no shared-nonce recovery.
- **Biased nonce / HNP / LLL**: the nonces have no fixed leading zeros or short
  range, so most-significant-bit lattices find nothing.
- The weakness is the **linear relation between** consecutive nonces, not any one
  signature.

## The idea
The nonce is an LCG: `k_{i+1} = a*k_i + c (mod n)` with secret `a, c`. Two facts:

1. From `s_i = k_i^{-1}(z_i + r_i d)`,

       k_i = s_i^{-1}(z_i + r_i d) = A_i d + B_i   (mod n)

   with `A_i = s_i^{-1} r_i`, `B_i = s_i^{-1} z_i`, `z_i = int(sha256(msg_i))`.
   Every nonce is affine in the single unknown key `d`.

2. Eliminate `a` and `c`. Over three steps,

       a = (k2 - k1)/(k1 - k0) = (k3 - k2)/(k2 - k1)

   so

       (k2 - k1)^2 = (k1 - k0)(k3 - k2).

## Recovering d
Substitute `k_i = A_i d + B_i`. Both sides are quadratic in `d`, so this is a
single quadratic

       alpha*d^2 + beta*d + gamma = 0   (mod n)

with
       alpha = (A2-A1)^2 - (A1-A0)(A3-A2)
       beta  = 2(A2-A1)(B2-B1) - [(A1-A0)(B3-B2) + (B1-B0)(A3-A2)]
       gamma = (B2-B1)^2 - (B1-B0)(B3-B2)

Solve mod `n` with the quadratic formula (a modular square root via
Tonelli-Shanks), and keep the root satisfying `d*G == Q`. Any four consecutive
signatures work; the `d*G == Q` check removes the spurious root.

## Forging the admin approval
With `d` known, ECDSA is fully forgeable:

    k = random nonce
    r = (k*G).x mod n
    s = k^{-1} (sha256(ADMIN_MSG) + r*d) mod n

`POST /forge {ADMIN_MSG, r, s}` verifies and returns this instance's per-team flag.

## Notes
- This is the degree-1 cousin of a polynomial-nonce recurrence. If the chain were
  degree 2 you would need the polynomial-elimination route (see the Polynonce
  challenge); here degree 1 collapses to one quadratic.
- Real basis: LCG / related-nonce ECDSA key recovery (Trail of Bits, "ECDSA:
  handle with care"; LadderLeak, eprint 2020/615).

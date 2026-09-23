# Shared Blood: writeup

## The setup
VoltEye's camera cloud gives every device an RSA identity cert and, during
provisioning, RSA-encrypts an admin bootstrap token to that device's public key.
You have the whole fleet's public certs (`GET /fleet`) and one intercepted
provisioning payload (`GET /captured`) addressed to a specific device. The token
inside unlocks the admin console.

## The bug
Embedded devices generate keys with very little entropy at first boot. When two
devices seed their RNG similarly, they can generate the **same prime**. Two RSA
moduli that share a prime are both trivially factored:

    gcd(N_i, N_j) = p   =>   q_i = N_i / p,   q_j = N_j / p

No single modulus is weak (no small factor, no Fermat-close primes); the weakness
is *relational*, visible only across the fleet. This is "Mining your Ps and Qs"
(Heninger, Durumeric, Wustrow, Halderman, USENIX 2012), which found exactly this
in the wild on routers and other embedded devices.

## The attack
1. Read the target device's modulus `N` (its serial is named in the captured
   payload) and all the other fleet moduli.
2. Batch-GCD: compute `gcd(N, N_i)` for every other device. Exactly one returns a
   non-trivial common factor `p` (the target's weak-RNG sibling). Then `q = N/p`.
3. Reconstruct the private key: `d = e^{-1} mod (p-1)(q-1)`.
4. Decrypt the intercepted PKCS1v1.5 payload with the private key to recover the
   admin bootstrap token.
5. `POST /admin` with the token -> the console authenticates and returns the flag.

At this fleet size a pairwise GCD of the target against the rest is instant; for a
real fleet of thousands you would use a product-tree batch-GCD (Bernstein), e.g.
`fastgcd`.

## Fix
Generate keys with proper entropy (hardware RNG, seeded after enough entropy is
collected), and never ship a fleet whose devices can collide on a prime. 1024-bit
RSA is also below modern minimums regardless.

## Notes
- Dead ends by design: the target modulus alone resists small-factor / Fermat /
  factordb; only the cross-fleet GCD works.
- Real basis: Heninger et al., "Mining your Ps and Qs: Detection of Widespread Weak
  Keys in Network Devices" (USENIX Security 2012).

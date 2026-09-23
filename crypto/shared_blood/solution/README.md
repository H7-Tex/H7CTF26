# Shared Blood: intended solution

Launch the instance, then:
```
python3 solution/solve.py http://<instance>/
```
Batch-GCDs the fleet, factors the target device key, decrypts the intercepted
payload, and logs in with the recovered admin token to print this instance's
per-team `H7CTF{...}`.

## Path
1. `GET /fleet` (all device moduli) and `GET /captured` (the intercepted
   provisioning payload + the target device's serial).
2. Try the reflexes on the target modulus alone and watch them fail: no small
   factor, primes are not Fermat-close, factordb has nothing. The weakness is not
   in one key.
3. Batch-GCD: `gcd(N_target, N_i)` across the fleet. Exactly one device shares a
   prime with the target (weak RNG), so one GCD comes back > 1. That is a prime
   factor `p` of `N_target`; `q = N_target / p`.
4. Rebuild the RSA private key `(N, e, d=e^{-1} mod (p-1)(q-1))`, decrypt the
   captured PKCS1v1.5 payload to the admin token.
5. `POST /admin {token}` -> the console unlocks and returns the flag.

For a large fleet, use a product-tree batch-GCD (`fastgcd`); at this fleet size a
pairwise GCD of the target against the rest is instant.

# Shared Blood

**Category:** crypto  **Difficulty:** medium  **Author:** abu

> VoltEye ships a whole fleet of identical cameras, cranked out on the same assembly line, in the same hurry. Somewhere in that crowd is one device whose console you'd very much like to open.
>
> Family resemblance runs deeper than you'd think.

Per-team HTTP instance on port 8080: `GET /fleet`, `GET /captured`, `POST /admin {token}`.

## Solution

`/fleet` gives the RSA public keys of 30 cameras (1024-bit). `/captured` is an intercepted provisioning payload, PKCS#1 v1.5 encrypted to one named device, carrying the admin bootstrap token.

The target key alone holds up: no small factors, primes aren't close enough for Fermat, factordb doesn't know it. The hint is in the title. Cheap embedded devices generate keys with almost no entropy at first boot, and two of them ended up with the same prime ("Mining your Ps and Qs", Heninger et al. 2012).

So GCD the target modulus against everyone else:

```python
for n in fleet:
    g = gcd(N_target, n)
    if 1 < g < N_target:
        p = g
```

Exactly one device shares a prime. `q = N/p`, `d = e^-1 mod (p-1)(q-1)`, decrypt the payload, and send the token to `/admin`. With 30 devices pairwise GCD is instant; for a real fleet you'd use a product-tree batch GCD like `fastgcd`.

```
python3 solution/solve.py http://<instance>/
```

Local:

```
FLAG='H7CTF{test}' PORT=8080 python3 challenge/app.py &
python3 solution/solve.py http://127.0.0.1:8080
```

Flag is dynamic, per team.

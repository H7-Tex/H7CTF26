# GridWatch

**Category:** hardware  **Difficulty:** insane  **Author:** abu

> GridWatch is the operator console for a 33kV substation feeder, and only one operator can hold the seat at a time.
>
> King of the Hill: take the operator seat and hold it. The seat resets periodically, so expect to take it again.

One shared instance for everyone. No flag; the platform polls `GET /koth/status` (`{"holder": ..., "since": ...}`) and gives hold-time points to whichever team token is in the seat.

## Solution

Logging in (`viewer`/`viewer` works, and so does `operator`/`substation`) gets you an RS256 JWT with `role: viewer`, which can't claim the seat. `POST /api/operator/claim` wants `role: admin`.

The verifier trusts the `alg` in the header, and for `HS256` it uses the PEM of its RSA public key as the HMAC secret. Classic RS256 to HS256 confusion. The catch is that the console never gives you the public key.

So we recover it. The key uses `e = 3`, and every viewer token is a signature we can check against: `s^e - PKCS1v15(SHA256(header.payload))` is a multiple of `n`. Grab a few viewer tokens, take the gcd, and you have `n`. Rebuild the PEM from `(n, 3)`, sign an `HS256` token with `role: admin` using that PEM as the key, and claim:

```
POST /api/operator/claim
Authorization: Bearer <forged token>
{"holder_token": "<your team token>"}
```

The key rotates on every reset, so a cached key or a replayed token dies at the round boundary and you have to redo the recovery each round. Login and claim are rate-limited per IP and claim has a short per-token cooldown, so spamming doesn't help much.

```
python3 solution/exploit.py http://<host>:8080 <TEAM-TOKEN>
```

Local test:

```
KOTH_SELFHEAL=5 python3 challenge/app.py
python3 solution/exploit.py http://127.0.0.1:8080 TEAM-A-TOKEN
```

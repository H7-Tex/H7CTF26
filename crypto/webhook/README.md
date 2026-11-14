# Owner's Draw

**Category:** crypto  **Difficulty:** medium  **Author:** abu

> OrionPay does exactly what it's told, provided the paperwork looks right. The owner's draw is the one payout nobody else is supposed to touch. You walked away with a single genuine slip and a lot of curiosity.
>
> The rest is between you and the accountant.

Per-team HTTP instance on port 8080: `GET /sample`, `POST /webhook`, `POST /v2/webhook`.

## Solution

`/sample` hands over one captured webhook: a body ending in `&role=guest` and its `X-Signature`. The index page says how that signature is made: `SHA256(secret || body)`. A body with `role=owner` pays out.

`SHA256(secret || body)` is the textbook length extension setup. SHA-256 is Merkle-Damgard, so the digest is the internal state after the padded input. Resume from that state and you can compute

```
SHA256(secret || body || glue || "&role=owner")
```

without knowing the secret, where `glue` is the SHA-256 padding for `secret || body`. The only thing missing is the secret length, which goes into the padding, so just try them all (the solver sweeps 1-40; the real one is 10-20 bytes).

For each length, send the raw `body || glue || &role=owner` with the forged signature to `/webhook`. The right length verifies. The server takes the last value for a repeated key, so `role=owner` wins, and the glue bytes just end up as junk inside the previous parameter's value.

`/v2/webhook` uses HMAC-SHA256, which doesn't extend. It's the fixed version and a dead end.

`hashpumpy` or `hash_extender` do this in one call. The reference solver has its own resumable SHA-256 so it only needs the stdlib.

```
python3 solution/solve.py http://<instance>/
```

Local:

```
FLAG='H7CTF{test}' PORT=8080 python3 challenge/app.py &
python3 solution/solve.py http://127.0.0.1:8080
```

Flag is dynamic, per team.

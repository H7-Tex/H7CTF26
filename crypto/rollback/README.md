# Take Two

**Category:** crypto  **Difficulty:** hard  **Author:** abu

> Helios firmware boots only with the notary's blessing, and the notary blesses only the builds it trusts. The one you have in mind will never make that list.
>
> Lucky for you, it is not above a second take.

Players get `challenge/lms.py` and a per-team HTTP instance on port 8080: `GET /root`, `POST /sign {firmware}`, `POST /rollback`, `POST /deploy {firmware, sig}`.

## Solution

`lms.py` is an LMS-style scheme: WOTS+ one-time keys (w=16) as leaves of a Merkle tree, and the device trusts the root. `/sign` signs with the current leaf and moves the counter forward. It refuses any build containing `BACKDOOR`. `/deploy` boots anything that verifies.

The one rule of stateful hash-based signatures is that a leaf signs once. `/rollback` resets the counter to 0. That's the bug.

Why reuse matters: WOTS+ signs each base-16 digit `d_i` of the hash as `H^{d_i}(sk_i)`. One signature can't be pushed to another message because the checksum digits move the opposite way and you can't walk a hash chain backwards. With many signatures from the same leaf, though, we just keep the lowest digit we've seen at every position:

```
known_i = H^{min_i}(sk_i)
```

Any target digit `c_i >= min_i` can then be signed as `H^{c_i - min_i}(known_i)`. After around 150 rollback+sign rounds on different benign builds, almost every position has hit digit 0, which means we hold `sk_i` itself.

Then build a firmware with the `BACKDOOR` marker, grind a nonce in it until every hash digit is at least `min_i` (usually the first try), chain each `known_i` forward, and attach leaf 0's auth path from any of the collected signatures. The leaf hasn't moved, so it still verifies against the root. `/deploy` boots it and returns the flag.

```
python3 solution/solve.py http://<instance>/
```

Local:

```
FLAG='H7CTF{test}' PORT=8080 python3 challenge/app.py &
python3 solution/solve.py http://127.0.0.1:8080
```

Two signatures from one leaf are not enough at these parameters; the rollback letting you do it over and over is what makes it work. Flag is dynamic, per team.

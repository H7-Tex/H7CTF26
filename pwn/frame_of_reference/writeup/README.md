# Frame of Reference - author writeup

Category: pwn (with a crypto steering step). Difficulty: insane.

This document is for authors and reviewers. It is not shipped to players.

## The service

`attest` is a single-binary TCP menu written in C++20. It models an async notary
that overlaps slow key finalization with network I/O.

- `1 prepare` reads `e`, `p`, `q` as hex, allocates a `KeyMaterial` out of a fixed
  slab, and launches `finalize(const KeyMaterial& km, Session&)`, a C++20 coroutine.
  The coroutine runs up to its first `co_await` (waiting for the document) and
  suspends. `prepare` then releases the staging cell back to the slab and returns.
- `2 submit` resumes the suspended coroutine. On resume it reads `km`, prints the
  recombined modulus, computes the private exponent, and writes it back into the
  `p` slot as scratch.
- `3 cipher` allocates a post-processing object. `Notary` (and its hidden subclass
  `EscrowAudit`) come out of the same slab as `KeyMaterial`. `B64`/`Rot` are plain
  heap objects in a different size class and never alias anything.
- `4 sign` invokes `signer->run(msg)` through the object's vtable.

## The bug

`finalize` takes its key material **by reference**. A C++20 coroutine stores a
by-reference parameter in the heap coroutine frame as a raw pointer, not a copy.
`prepare` frees the `KeyMaterial` cell as soon as the coroutine is airborne, so the
suspended frame holds a dangling pointer into a freed slab cell. This is a
use-after-free / type confusion on a suspended coroutine frame, not a classic
tcache reuse.

`KeyMaterial` is 288 bytes with `p` first (so `p.limbs[0]` is at offset 0). `Notary`
is polymorphic, so its vptr is at offset 0 and it writes only its first 56 bytes
(vptr plus a small scratch array). Placing a `Notary` (menu option 3) between
`prepare` and `submit` pops the freed cell:

- `km.p.limbs[0]` now aliases the `Notary` vptr.
- `km.q` (offset 56) is beyond what the `Notary` constructor touches, so the small
  value submitted in `prepare` survives there.

## Leak: exact division, not discrete log

On resume, `finalize` computes and prints `n' = p' * q'`, where `p'` is read from
`km.p` (the aliased vptr) and `q'` is the small survivor in `km.q`. Because `q'` is
a small factor the attacker chose, the leak is a single exact division:

```
p' = n' / q'   ->  the ASLR'd Notary vtable pointer
```

The tempting wrong move is to treat `n'` as an RSA modulus and take a discrete log
or factor it. The intended leak is just `n' / q'`.

## Write: aim a modular inverse at a vtable

`finalize` performs exactly one store into the aliased cell:

```
km.p = d,  where  d = inv(e', lambda'),  lambda' = lcm(p'-1, q'-1)
```

That store overwrites the 8-byte `Notary` vptr. If we make `d` equal the
`EscrowAudit` vtable pointer, then `sign` dispatches `run()` into
`EscrowAudit::run`, which reads `$FLAG`, XORs it against the submitted message and
returns the hex. Submitting a zero message returns the flag directly.

The target address is `p' + off`, where `off` is the fixed link-time distance
between the two vtables. Read it from the handout binary:

```
off = &_ZTV11EscrowAudit - &_ZTV6Notary   (e.g. via nm)
```

At runtime both object vptrs are `vtable_symbol + 16`, so the same `off` maps the
leaked `Notary` vptr to the `EscrowAudit` vptr.

## The number theory that actually matters

We only get to pick `e'` and `q'`. The server computes `d = inv(e', lambda')`, and
`d` is reduced mod `lambda'`. To make `d` equal `target = p' + off` we set
`e' = inv(target, lambda')`, so `d = inv(e', lambda') = target` **only if**:

1. `gcd(target, lambda') = 1` (so the inverse exists), and
2. `target < lambda'` (so `target` is its own reduced residue, not
   `target mod lambda'`).

Two traps live here:

- `target` is 8-byte aligned, hence even. `lambda' = lcm(p'-1, q'-1)` is a multiple
  of `p'-1` (which is odd) and of `q'-1`. If `q'` is an odd prime then `q'-1` is
  even and `lambda'` is even, so `gcd(target, lambda')` is even and no inverse
  exists. Fix: choose `q'` **even** (so `q'-1` is odd), keeping `lambda'` odd.
- If we take the natural `q' = 2` then `lambda' = p'-1 < target`, and the server
  writes `target mod (p'-1) = off + 1`, a tiny integer, not the address. Fix: pick
  `q'` so that `lambda' = lcm(p'-1, q'-1) > target`. Any `q' = r + 1` with `r` a
  large odd number (e.g. `r = 1000003`) gives `lambda' ~= (p'-1) * r`, far above
  `target`.

Necessary condition on the leak: `gcd(target, p'-1) = gcd(off + 1, p'-1)`. With
`off = 48`, that is `gcd(49, p'-1)`, so the layout is unusable only when
`7 | (p'-1)` (about 1 in 7). Since every connection is a fresh `socat` fork with
fresh ASLR, the solver just reconnects until it draws a workable `p'`.

## Why offline / static attacks fail

- `$FLAG` is injected at runtime and read only inside `EscrowAudit::run`, so it is
  absent from the binary, strings and handout.
- The only write into the aliased cell is one algebraically constrained integer,
  not attacker bytes, so there is no fake-vtable / arbitrary-write path and no ROP.
- The write value must equal the per-connection ASLR'd `EscrowAudit` vptr, so no
  precomputed or offline answer exists. Leak, solve and write must all happen live
  in one connection.

## Reference solver

`solution/solve.py` (no dependencies) does: read `off` from the binary, leak `p'`
by exact division, verify `gcd(49, p'-1) = 1` (else reconnect), pick a workable
even `q'` with `lambda' > target`, solve `e' = inv(target, lambda')`, regroom,
resume to land the write, then `sign` with a zero message and decode the flag.

Validated end to end natively, over `socat`, and against the built Docker
container. First-blood realistically needs one reconnect on average.

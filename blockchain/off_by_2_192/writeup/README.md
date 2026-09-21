# Off By 2^192 — writeup

## The vulnerability

`add_liquidity` computes what you owe via `required_tokens`, which shifts the requested
liquidity left by 64 (a Q64.64 fixed-point conversion) through a *checked* helper:

```move
public fun checked_shlw(n: u256): (u256, bool) {
    let mask = 0xffffffffffffffffu256 << 192;   // == (2^64 - 1) << 192, i.e. ~2^256
    if (n > mask) {
        (0, true)          // report overflow
    } else {
        (n << 64, false)   // "safe"
    }
}
```

`n << 64` overflows a `u256` for **any** `n >= 2^192`. The correct guard is therefore
`n >= (1 << 192)` (equivalently `(n >> 192) != 0`, or `n & mask != 0`). But the code compares
`n > mask`, and `mask = (2^64 - 1) << 192` is almost the largest `u256` there is. So every
`n` in `[2^192, (2^64-1)<<192]` — an enormous range — passes the check with `overflow == false`
and is then shifted, wrapping modulo 2^256. The guard is present; it guards the wrong boundary.

This is exactly the Cetus bug (May 2025, ~$223M): a `checked_shlw` in their `integer-mate`
math whose overflow mask let a crafted liquidity value truncate, so the pool asked for almost
no tokens in return for an enormous position.

## The exploit

Pick `lp_amount = 1 << 192`:

- `checked_shlw(1<<192)`: `1<<192 > (2^64-1)<<192` is **false** → no overflow reported.
- `(1<<192) << 64 = 1 << 256 = 0` (mod 2^256) → the shifted value is `0`.
- `required_tokens = (0 >> 64) as u64 = 0`.

So `add_liquidity` mints you `1<<192` LP for a **zero** token payment. That dwarfs the pool's
honest `total_lp`, so your share is essentially the whole pool. `remove_liquidity` then pays
you `reserve * (1<<192) / (total_lp + 1<<192) ≈ reserve` — the entire reserve, for free.

`sui move test` proves it end-to-end (`drains_pool_via_overflow`): seed 1,000,000, mint LP for
0, redeem ≥ 999,000, pool left with ≤ 1,000.

## The fix

Guard the real overflow boundary:

```move
public fun checked_shlw(n: u256): (u256, bool) {
    if ((n >> 192) != 0) { (0, true) }   // any bit at position >= 192 overflows on << 64
    else { (n << 64, false) }
}
```

or check `n & (0xffffffffffffffffu256 << 192) != 0`. The point is that the mask must select
the bits that *would be lost*, and the test must be `!= 0` (any such bit), not `> mask`.

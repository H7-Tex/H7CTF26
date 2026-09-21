# Tidepool — writeup

`cetus checked_shlw, but you have to slip past three guards`

#### the guards (all real)

`add_liquidity` looks buttoned up:

```move
assert!(lp_amount <= (1u256 << 200), E_TOO_MUCH);   // hard cap
let required = required_tokens(lp_amount);
assert!(required > 0, E_NO_FREE);                     // no free liquidity
```

and `required_tokens` runs through a *checked* shift that aborts on overflow. so the naive cetus move — `lp_amount = 1 << 192`, mint a mountain of lp for zero — dies twice: `required` comes out `0` (→ `E_NO_FREE`), and if you go bigger you hit the cap. dead end.

#### the actual bug

`checked_shlw` guards the wrong boundary:

```move
public fun checked_shlw(n: u256): (u256, bool) {
    let mask = 0xffffffffffffffffu256 << 192;   // ~2^256
    if (n > mask) { (0, true) } else { (n << 64, false) }
}
```

`n << 64` overflows a u256 for **any** `n >= 2^192`, but the check only trips at `n > ~2^256`. so everything in `[2^192, ~2^256]` shifts and wraps with `overflow == false`. this is the real cetus bug (~$220m, may 2025) — the mask should have selected the bits that get lost.

now line up the three guards:
- cap is `1 << 200`, which is **above** `2^192` — so the overflow range `[2^192, 2^200]` sails under the cap. the cap looks protective; it isn't.
- `required = (n << 64) >> 64` = the low 192 bits of `n`. for `n = 2^192` that's `0` (→ E_NO_FREE). for `n = 2^192 + k` it's exactly `k`.

so pick `lp_amount = 2^192 + 1`: `required = 1` (passes E_NO_FREE), `lp_amount <= 2^200` (passes the cap), the shift wraps undetected, and you're credited `~2^192` lp for **1 token**.

#### the play

1. `add_liquidity(2^192 + 1, coin_of_1)` → pay 1, get a `2^192`-scale LP position that dwarfs `total_lp`.
2. `remove_liquidity(lp)` → `reserve * lp / total_lp ≈ reserve`. whole pool, for 1 token.

`sui move test` proves it, and that `1 << 192` (required 0) is rejected — you have to reason to `+ k`.

#### the fix

`if ((n >> 192) != 0) { (0, true) }` — flag any bit at position ≥ 192. and don't lean on a cap that sits above the overflow point.

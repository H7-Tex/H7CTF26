# Tidepool

**Category:** blockchain (Sui Move)  **Difficulty:** hard  **Author:** abu

> tidepool is a sui liquidity pool: mint liquidity, pay what it says you owe, and redeem your share of the reserve later. it looks locked down. the obvious ways in are all closed off.
>
> walk out with the whole reserve.

Provided: `challenge/sources/pool.move`, `challenge/Move.toml`. The server is built on otter-sec's sui-ctf-framework (vendored with a small patch under `server/vendor/`, pinned to Sui `devnet-v1.49.0`). It publishes the pool, shares it, then reads your compiled solve module over TCP and calls `solution::solve(pool, payment)` followed by `pool::flag(pool)`.

Build note: the image needs Rust 1.88 and a cold build takes over an hour, so on Cloud Build use `--machine-type=E2_HIGHCPU_32 --timeout=7200s`.

## Solution

`add_liquidity` has three guards and they all hold: a cap of `1 << 200` on the LP amount, a `required > 0` check so liquidity isn't free, and a "checked" shift in the conversion that's supposed to abort on overflow. So the straight Cetus move (`lp_amount = 1 << 192`) fails, `required` comes out 0.

The checked shift is the Cetus `checked_shlw` bug, with the mask on the wrong boundary:

```move
public fun checked_shlw(n: u256): (u256, bool) {
    let mask = 0xffffffffffffffffu256 << 192;
    if (n > mask) { (0, true) } else { (n << 64, false) }
}
```

`n << 64` loses bits for any `n >= 2^192`, but this only flags `n` above roughly `2^256`. Everything from `2^192` up wraps silently. And the cap at `2^200` sits above that, so it doesn't help.

`required` works out to the low 192 bits of `n`. For `2^192` that's 0, but for `2^192 + k` it's exactly `k`. So `lp_amount = 2^192 + 1` costs 1 token, passes the cap and the no-free check, and credits us about `2^192` LP, which dwarfs everyone else's.

```move
let lp = pool::add_liquidity(pool, (1u256 << 192) + 1, &mut payment, ctx);
let loot = pool::remove_liquidity(pool, lp, ctx);
```

`remove_liquidity` then pays out `reserve * lp / total_lp`, which is the whole reserve.

```
cd solution/solve && sui move build
cat build/solution/bytecode_modules/solve.mv | nc <host> <port>
```

Use a `devnet-v1.49.0` Sui CLI or the bytecode won't load. `sui move test` in `challenge/` runs the same drain.

Flag is dynamic per instance (`H7CTF{...}`).

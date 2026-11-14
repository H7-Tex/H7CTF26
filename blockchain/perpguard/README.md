# Perp Guard

**Category:** blockchain (Solana)  **Difficulty:** hard  **Author:** abu

> perpguard is a solana lending market: post collateral, open positions, borrow.
>
> you're a borrower who plans to default, and your collateral is about to be marked down. end up underwater on a loan no keeper can ever claw back.

Provided: `challenge/program/src/lib.rs`, `challenge/program/Cargo.toml`. The TCP service takes your solve program first, then prints the program, user, market and obligation addresses and runs your instructions.

## Solution

The safety model is "every underwater position can be liquidated". Obligations are capped at `MAX_POSITIONS = 20_000`, so the textbook unbounded-loop DoS looks closed. The loop is bounded, just not bounded low enough.

`liquidate` walks every position and does u128 math on each:

```rust
for i in 0..count {
    let value = (rd_u64(&data, off) as u128).saturating_mul(price) / PRICE_SCALE;
    allowed_debt = allowed_debt.saturating_add(value.saturating_mul(LTV_NUM) / LTV_DEN);
    total_debt   = total_debt.saturating_add(rd_u64(&data, off + 8) as u128);
}
```

u128 mul/div on SBF costs roughly 150-200 CU per position, and a transaction gets 1.4M CU. So `liquidate` runs out somewhere around 7-8k positions, well under the cap. Meanwhile opening positions is cheap: `OpenMany` just writes raw slots.

1. The server opens our real max-LTV position. Later the oracle marks the collateral down and we're underwater.
2. We call `OpenMany { collateral: 0, debt: 0, count: 15000 }` via a small CPI program (`solution/solve/`). Zero-value positions add nothing, so we're still underwater in aggregate.
3. The keeper's `liquidate` has to walk ~15,001 positions, blows the compute budget and reverts.

The server checks underwater status natively (no CU limit) and that on-chain `liquidate` fails, so you can't fake it with a healthy obligation.

```
cd solution/solve && cargo build-sbf
SOLVE_SO=target/deploy/solve.so HOST=<host> PORT=<port> python3 ../solve.py
```

`challenge/program/tests/exploit.rs` does the same locally.

Flag is dynamic per instance (`H7CTF{...}`).

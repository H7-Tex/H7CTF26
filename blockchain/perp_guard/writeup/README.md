# Perp Guard — writeup

`compute-budget dos, hiding behind a position cap that doesn't actually save the keeper`

#### the trap

obligations are capped at `MAX_POSITIONS = 20_000`. so the textbook "unbounded liquidation loop" dos looks off the table — the keeper's loop is bounded. it just isn't bounded *low enough*.

#### the bug

`liquidate` walks every position and values each with u128 mul+div:

```rust
for i in 0..count {
    let value = (rd_u64(&data, off) as u128).saturating_mul(price) / PRICE_SCALE;
    allowed_debt = allowed_debt.saturating_add(value.saturating_mul(LTV_NUM) / LTV_DEN);
    total_debt   = total_debt.saturating_add(rd_u64(&data, off + 8) as u128);
}
```

u128 mul+div on sbf is pricey (~150–200 cu/position), and a transaction gets 1.4M cu total. so `liquidate` blows the budget somewhere around **~7–8k positions — well under the 20,000 cap.** the cap bounds the loop to a length that still can't finish in one tx. opening is O(1) and cheap (raw slot write; `OpenMany` batches it), liquidating is O(n) with per-position math — that asymmetry is the whole thing.

#### the play

1. the server opens your real max-ltv position; the oracle later marks collateral down → you're underwater.
2. `OpenMany { 0, 0, ~15000 }` — pad the obligation with zero-value positions (cheap, and the cap allows it). ~15,001 positions, still underwater in aggregate (the zeros add nothing).
3. keeper calls `liquidate` → has to walk 15,001 positions → exceeds 1.4M cu → reverts. underwater **and** un-liquidatable → flag.

the server confirms underwater in native rust (no cu limit) and that on-chain `liquidate` errors, so the win can't be faked with a bogus "healthy" obligation.

#### the fix

liquidation has to be O(1) or paginated — keep running aggregate collateral/debt in the obligation header and update it on open/close, so `liquidate` never loops. or set the cap *below* the cu-crossing point (and actually know where that is).

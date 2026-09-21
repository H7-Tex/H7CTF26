# Perp Guard — writeup

## The vulnerability

PerpGuard's solvency model rests on one invariant: any underwater obligation can be
liquidated. `Liquidate` enforces that by walking every position in the obligation to
recompute aggregate health:

```rust
Ix::Liquidate => {
    let count = rd_u64(&data, COUNT_OFF) as usize;
    for i in 0..count {                       // unbounded, attacker-controlled
        let off = HEADER + i * POS_SIZE;
        let value = (rd_u64(&data, off) as u128) * price / PRICE_SCALE;   // per-position valuation
        allowed_debt += value * LTV_NUM / LTV_DEN;
        total_debt   += rd_u64(&data, off + 8) as u128;
    }
    if total_debt <= allowed_debt { return Err(...) }   // not liquidatable
    ...
}
```

There is no cap on how many positions an obligation may hold, and `OpenPosition` appends in
**O(1)** — it writes one 16-byte slot and bumps a counter, never touching the rest of the
array:

```rust
let count = rd_u64(&data, COUNT_OFF) as usize;
let off = HEADER + count * POS_SIZE;
wr_u64(&mut data, off, collateral);
wr_u64(&mut data, off + 8, debt);
wr_u64(&mut data, COUNT_OFF, (count + 1) as u64);
```

So growing the array is cheap for the borrower, but `Liquidate` grows linearly with it. And
`OpenMany` appends in bulk — `count` positions per instruction, still O(1) each — so the array
can be inflated to tens of thousands of entries in a single transaction while `Liquidate`
still has to walk every one of them in a single transaction of its own. That asymmetry
(cheap, batchable append vs. all-at-once linear liquidation) is the whole bug.
Push the position count high enough and `Liquidate` exceeds the transaction compute budget
(1.4M CU) and reverts *every time it is called*. The obligation becomes permanently
un-liquidatable. The per-position health check in `OpenPosition` never lets you open a single
underwater position, so the underwater state has to come from a price move — but once the
oracle marks the collateral down, the keeper is helpless: it knows you are underwater and
physically cannot seize you.

This is not a missing check. Every account is validated, every signer is required, all math
is saturating. A static scanner sees nothing wrong. The flaw is an algorithmic-complexity
bug in the *design* of `Liquidate` against attacker-growable state — a real Solana class
(compute exhaustion / liquidation griefing).

## The exploit

1. The server opens the borrower's real max-LTV position (collateral 1_000_000, debt 800_000,
   healthy at the opening price of 1.0).
2. Pad the obligation with thousands of zero-value positions. Zero positions pass the
   per-position health check (`0 <= 0`) and add nothing to collateral or debt, so the
   obligation stays underwater once the price drops — but the position *count* explodes.
   `OpenMany { collateral: 0, debt: 0, count }` appends `count` positions in a single
   instruction — each append is O(1) (one raw slot write + a counter bump), so ~30k fit under
   one 1.4M-CU transaction. Zero positions pass the per-position health check and add nothing
   to collateral or debt, so the obligation stays underwater once the price drops while its
   position count explodes. One `OpenMany` tx is enough. (This deliberately sidesteps Solana's
   64-instruction-trace cap, which would throttle a CPI loop of single `OpenPosition` calls to
   ~60 per tx.) The reference solve is a tiny program that CPIs `OpenMany` once;
   `solution/solve.py` uploads it and fires a single round. `count` / `OBLIGATION_BYTES` are
   set from the SBF measurement so the padded obligation pushes `Liquidate` past 1.4M CU
   (~56 CU/position → crosses at ≈25k positions for the aggregate liquidate; lower with the
   per-position valuation).
3. The server drops the oracle price to 0.5. The real position is now underwater
   (debt 800_000 > collateral 1_000_000 · 0.5 · 0.8 = 400_000).
4. The server confirms — in native code, with no compute limit — that the obligation is
   underwater, then calls `Liquidate` on-chain. `Liquidate` runs out of compute and reverts.
   Underwater **and** un-liquidatable ⇒ flag.

`solution/solve/` is the padding program; `solution/solve.py` uploads it and drives the
framework socket (upload solve `.so` → read the addresses → send the padding rounds →
half-close → read the flag).

## Tuning (build-time, on SBF)

The exact numbers are calibrated on the real SBF runtime, not natively:
- `OBLIGATION_BYTES` (server) sizes the obligation account; full-fill must push `Liquidate`
  comfortably past 1.4M CU.
- `COUNT` / `ROUNDS` (solve.py) fill it; `COUNT` per round is bounded by how many
  `OpenPosition` CPIs fit in one 1.4M-CU transaction.

Measure `Liquidate`'s CU at a few position counts, set `OBLIGATION_BYTES` so a full obligation
exceeds the budget with margin, then size `ROUNDS`·`COUNT` to fill it.

## The fix

- Cap positions per obligation, or
- Store running aggregate collateral/debt in the obligation header and update them in O(1) on
  every `OpenPosition` / close, so `Liquidate` is O(1) and never has to iterate, or
- Make liquidation paginate / process a bounded slice of positions per call.

Any of these removes the unbounded per-liquidation work and restores the "always
liquidatable" invariant.

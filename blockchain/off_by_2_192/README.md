# Off By 2^192

**Category:** blockchain (Sui / Move)
**Difficulty:** insane

A constant-sum-ish liquidity pool on Sui. To mint `lp_amount` of liquidity you call
`add_liquidity` and pay the token amount the pool computes you owe. That amount is derived with
a **checked** fixed-point left-shift — the kind that is supposed to abort rather than let a
number silently wrap. Redeem your LP later and you get back your share of the reserve.

You start with nothing. Walk away with the pool's entire reserve.

## Goal

Drain the pool's reserve. When it can no longer pay out, the flag is yours.

## Connect

Launch an instance from the platform and connect to the endpoint. You get the published
package id, the shared `Pool` object id, and the keypair + gas you control, plus a channel to
submit your solve transaction.

## Provided

- `challenge/sources/pool.move` — the pool module
- `challenge/Move.toml`

## Notes

This is the shape of a real, nine-figure Sui exploit. The bug is one comparison operator in a
helper that everything downstream trusts. No missing assertion, no unchecked arithmetic that a
linter would flag — the overflow guard is *present*, it just guards the wrong boundary.

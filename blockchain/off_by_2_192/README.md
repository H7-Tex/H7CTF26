# Tidepool

**Category:** blockchain (Sui / Move)
**Difficulty:** insane

Tidepool is a liquidity pool on Sui. To mint `lp_amount` of liquidity you call `add_liquidity`
and pay the token amount the pool computes you owe — an amount derived through a **checked**
fixed-point conversion that is meant to abort rather than let a number wrap. Redeem your LP
later and you get back your share of the reserve.

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

Every account is validated and every arithmetic path is guarded. There is no missing check to
find. Read the conversion the pool trusts, and the numbers it produces at the edges.

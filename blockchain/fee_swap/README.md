# Fee Swap

**Category:** blockchain (Solana)
**Difficulty:** hard

FeeSwap is a 1:1 swap desk between two SPL tokens. Send `amount` of token A and it sends you
`amount` of token B out of its reserve; send B and it sends you A. Nothing exotic — no curve,
no slippage, just a pool that pays out exactly what you swap in.

You hold token A. The pool has a reserve of token B. Take it.

## Goal

Drain the pool's B reserve. When the pool can no longer honour its B side, the flag is yours.

## Connect

Launch an instance from the platform and connect to the endpoint. You are handed the program
id, the pool and vault addresses, the two mints, and the keypair + funded token accounts you
control, plus a channel to submit your solve transactions.

## Provided

- `challenge/program/src/lib.rs` — the FeeSwap program
- `challenge/program/Cargo.toml`

## Notes

Every transfer here is a real `transfer_checked`; every account is validated; the pool only
ever pays what it is told to. There is no missing check to find. The question is whether the
number the pool *acts on* is the number that actually moved — and what your particular token
does to that number in flight.

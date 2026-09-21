# Perp Guard

**Category:** blockchain (Solana)
**Difficulty:** insane

PerpGuard is an on-chain lending market. You post collateral into an obligation, open
positions against it, and borrow. The market stays solvent through one rule: any position
that falls below its liquidation threshold can be seized by a keeper, who repays the debt
and takes the collateral. Every position must always be liquidatable — that is the invariant
the whole thing rests on.

You are a borrower who intends to default. The oracle is about to mark your collateral down.
Your job is to walk away with a loan the keepers can never claw back.

## Goal

End with an obligation that is underwater at the oracle price **and** that the keeper's
`Liquidate` can no longer process. Break the "always liquidatable" invariant, and the flag
is yours.

## Connect

Launch an instance from the platform and connect to the endpoint. You are handed the deployed
program id, the keypair you control, and a channel to submit your solve transactions.

## Provided

- `challenge/program/src/lib.rs` — the PerpGuard program
- `challenge/program/Cargo.toml`

## Notes

There is no missing signature check, no arithmetic overflow, and no unchecked account here —
a scanner will find nothing. The flaw is in what the program *does*, not in what it forgot to
verify. Read `Liquidate` and ask what an obligation is allowed to look like by the time a
keeper needs it.

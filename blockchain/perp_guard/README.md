# Perp Guard

`blockchain` `solana` `insane`

perpguard is a solana lending market. post collateral, open positions, borrow against them. the one rule holding the whole thing up: any position that goes underwater can be liquidated by a keeper. every position must stay liquidatable. that's the safety model. and obligations are capped, so a keeper's liquidation can't loop forever.

you're a borrower who plans to default. the oracle's about to mark your collateral down. take a loan the keepers can never claw back.

#### connect
spin up an instance, connect over the endpoint. you get the program id, the keypair you control, and a channel to send solve txs. break "always liquidatable" and the flag is yours.

#### provided
- `challenge/program/src/lib.rs`
- `challenge/program/Cargo.toml`

#### notes
no missing signer, no overflow, nothing a scanner trips on. the position cap looks like it bounds the keeper's work. do the arithmetic on what one liquidation actually costs to run, and where that lands against a transaction's budget.

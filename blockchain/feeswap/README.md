# Fee Swap

**Category:** blockchain (Solana)  **Difficulty:** medium  **Author:** abu

> feeswap is a tiny two-asset pool: send it token A, get token B back. a clean 1:1 desk with a healthy B reserve it's sure it can always cover.
>
> you're holding token A. walk out with the pool's entire B reserve.

Provided: `challenge/program/src/lib.rs`, `challenge/program/Cargo.toml`. The instance is a TCP service: it prints the program id, pool, vaults, mints and your token accounts, then takes one instruction from you.

## Solution

The usual holes are closed. `read_pool` checks the account owner, `InitPool` is one-shot, the signer bump is derived in the program, and every swap skims a 1% fee.

The bug is in `SwapAToB`. It pays out based on the `amount` we asked to swap, not on what actually arrived in the vault:

```rust
invoke(&in_ix, ...)?;                                   // user -> vault_a, `amount`
let payout = amount - amount * SWAP_FEE_BPS / 10_000;   // 99% of amount
invoke_signed(&out_ix, ...)?;                           // vault_b -> user, `payout`
```

Token A is a Token-2022 mint with a 5% transfer fee. Send `amount` of A and the vault only receives 95% of it, but we get paid 99%. The 1% swap fee looks like the pool protecting itself, it just doesn't cover the 5% lost in transit. The pool bleeds 4% of value per swap.

There's no need to loop. One `SwapAToB(reserve_b)` pays out 99% of the B reserve in a single shot, which is enough to count as drained.

```
HOST=<host> PORT=<port> python3 solution/solve.py
```

`solve.py` reads the addresses and `reserve_b` from the banner and sends instruction `1` with `reserve_b` as a little-endian u64. `challenge/program/tests/exploit.rs` has the same thing as a test.

Flag is dynamic per instance (`H7CTF{...}`).

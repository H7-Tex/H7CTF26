# Fee Swap writeup

`token-2022 transfer-fee confusion, hiding behind a swap fee that doesn't cover it`

#### the shut doors

the obvious holes are closed: `read_pool` checks `owner == program`, `InitPool` is one-time (`initialized` flag), the signer bump is derived in-program not read from the struct. and every swap skims a 1% swap fee. looks like the pool guards its reserve.

#### the bug

`SwapAToB` pays out on the `amount` you *asked* to swap, not the amount that actually *arrived*:

```rust
// in: user -> vault_src, `amount`  (token-2022 transfer_checked)
invoke(&in_ix, ...)?;
let payout = amount - amount * SWAP_FEE_BPS / 10_000;   // amount * 99/100
// out: vault_dst -> user, `payout`
invoke_signed(&out_ix, ...)?;
```

token A is a token-2022 mint with a **5% transfer fee**. send `amount` A and the pool's vault only receives `amount * 0.95`, but the payout is figured off the full `amount` (minus just the 1% swap fee). the pool hands you `amount * 0.99` B for `amount * 0.95` of A. it loses **4% of value on every swap.**

that 1% swap fee is the whole trap: it *looks* like the pool takes a cut to stay solvent, but 1% < the 5% transfer fee, so it still bleeds. do the subtraction.

#### the play

one `SwapAToB(reserve_b)`: the pool pays out `0.99 * reserve_b` B and drops its reserve to ~1%. you fund it with `reserve_b` of A (5% withheld to the fee authority). reserve drained → flag. `drains_reserve_via_fee_mint` proves it, and `read_pool`/one-time-init close the earlier unintended path.

#### the fix

price the payout on the **received** amount, not the requested one: snapshot the vault balance before and after the incoming transfer and pay on the delta. never trust the caller's `amount` for a fee-bearing mint, and if you skim a fee, it has to actually cover what the asset does in transit.

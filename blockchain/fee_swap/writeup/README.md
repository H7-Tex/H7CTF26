# Fee Swap — writeup

## The vulnerability

`SwapAToB` moves the user's input in and pays the output out, and it uses the **same**
`amount` for both legs:

```rust
// in: user -> pool vault (user signs)
let in_ix = transfer_checked(token_program, user_src, mint_src, vault_src, user, &[], amount, DECIMALS)?;
invoke(&in_ix, ...)?;

// out: pool vault -> user (pool PDA signs)
let out_ix = transfer_checked(token_program, vault_dst, mint_dst, user_dst, authority, &[], amount, DECIMALS)?;
invoke_signed(&out_ix, ..., &[&[AUTH_SEED, &[p.bump]]])?;
```

The pool pays out `amount` of the destination token, assuming it received `amount` of the
source token. For a plain SPL token that holds. But **Token-2022 mints can carry a transfer
fee** — with a `TransferFeeConfig` extension, a `transfer_checked` of `amount` credits the
recipient only `amount − fee` (the fee is withheld in the destination account). So when the
source token has a transfer fee, the pool receives `amount − fee` but still pays out the full
`amount` of the other side.

Every `transfer_checked` here is correct and every account is validated. The bug is that the
program **acts on the amount it was asked to move, not the amount that actually arrived** — a
real, widely-hit Token-2022 integration mistake (AMMs and vaults had to switch to measuring
`balance_after − balance_before` when fee-bearing mints appeared).

## The exploit

1. You hold token A, a Token-2022 mint with a transfer fee. The pool holds a reserve of
   token B (no fee).
2. Call `SwapAToB(amount)` repeatedly. Each call: the pool receives `amount·(1−fee)` of A
   but sends you the full `amount` of B. It over-pays `amount·fee` of B every swap.
3. Keep swapping until the pool's B vault is empty. You walk away holding its entire B
   reserve, having only ever funded it with fee-discounted A. `solution/solve.py` drives it;
   `solution/solve/` is the on-chain helper that issues the swap CPIs.

The win check reads the pool's B vault balance server-side (native, authoritative) and
releases the flag once it is drained.

## The fix

Measure what actually arrived. Snapshot the destination vault's balance before the incoming
`transfer_checked` and again after, and price/pay the output on the delta — never on the
caller-supplied `amount`:

```rust
let before = token_balance(vault_src);
invoke(&in_ix, ...)?;                 // amount in (fee may apply)
let received = token_balance(vault_src) - before;
// pay out based on `received`, not `amount`
```

For fee-bearing mints this is the only correct accounting; it also naturally handles any
future transfer extension that changes the delivered amount.

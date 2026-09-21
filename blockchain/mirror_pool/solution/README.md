# Mirror Pool — reference solve

The proven reference exploit is the passing forge test at `../challenge/test/Solve.t.sol`
(`forge test` is green): it deploys `Setup`, runs the full attack, and asserts `isSolved()`.

## Exploit — read-only reentrancy across two clean contracts

`MirrorLend` prices LP collateral off `Pool.get_virtual_price()` live. `Pool.removeLiquidity()`
sends ETH to the caller **before** it updates its reserves, so mid-callback the virtual price is
skewed high.

1. Add liquidity to the `Pool`, take the LP tokens, and deposit them into `MirrorLend` as
   collateral.
2. Call `Pool.removeLiquidity()`. It transfers ETH to you first; your `receive()` runs while the
   pool's reserves are momentarily inconsistent, so `get_virtual_price()` reports an inflated
   LP price.
3. Inside that callback, call `MirrorLend.borrow()`. It values your LP collateral at the
   inflated price and lets you borrow far more than it is worth.
4. Let `removeLiquidity()` finish; the price snaps back but you have already over-borrowed. The
   lender is insolvent ⇒ `isSolved()`.

## Against a live instance

`GET /` on the launched instance returns the RPC endpoint, your private key, and the `Setup`
address. Replay with a forge script (`--rpc-url $RPC --private-key $KEY --broadcast`) or `cast`,
then `GET /flag`.

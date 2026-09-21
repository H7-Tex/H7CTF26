# Mirror Pool — writeup

**Class:** read-only reentrancy. Two individually-correct contracts; the bug lives only in their composition.

## Where the bug is

Neither contract is reentrant in its own logic. `MirrorLend.borrow()` only makes a `staticcall` to `pool.get_virtual_price()`. The pool's `removeLiquidity` is the pivot:

1. it burns your LP (`totalSupply` drops),
2. it sends your ETH share with `msg.sender.call{value: ethOut}("")` — handing you control,
3. *then* it sends your token share.

Between steps 2 and 3, `totalSupply` is already reduced but the token half of your withdrawal is still sitting in the pool. Since `get_virtual_price() = (address(this).balance + token.balanceOf(this)) * 1e18 / totalSupply`, the price is **inflated** during your ETH-receive callback.

## The exploit

1. Add liquidity → receive LP.
2. Deposit part of your LP into MirrorLend as collateral.
3. Call `pool.removeLiquidity()` on the rest. In your `receive()`, the virtual price is skewed high, so `MirrorLend.borrow()` lets you borrow far more than your collateral is honestly worth. The lender is now under-secured.

`isSolved` = total debt exceeds total collateral value at the honest (post-exploit) virtual price — a state impossible to reach without the skew.

## Fix

Don't trust a manipulable live price mid-transaction. Read `get_virtual_price()` behind the pool's own reentrancy lock (Curve's `remove_liquidity(0, [0,0])` idiom trips the lock before reading), or price collateral from a manipulation-resistant oracle.

## Reference solve

`challenge/test/Solve.t.sol` — run `forge test` in `challenge/`. Deploys `Setup`, runs the reentrant exploit from `receive()`, asserts `Setup.isSolved()`.

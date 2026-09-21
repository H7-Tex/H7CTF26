# Mirror Pool — writeup

`read-only reentrancy — two clean contracts, the bug lives in the seam`

#### where it hides

neither contract is reentrant on its own. `MirrorLend.borrow()` only does a `staticcall` to `pool.get_virtual_price()`. the pivot is `Pool.removeLiquidity()`:

1. it burns your lp — `totalSupply` drops,
2. it sends your eth share with `msg.sender.call{value: ethOut}("")` — you get control,
3. *then* it sends your token share.

between 2 and 3, `totalSupply` is already down but the token half of your withdrawal is still sitting in the pool. and `get_virtual_price() = (balance + token.balanceOf(this)) * 1e18 / totalSupply`. so during your eth-receive callback the price is inflated. read either contract cold and it looks fine — that's the point.

#### why the obvious move dead-ends

donate to pump the virtual price then over-borrow? the borrow check reads the *same* price, so it scales right along with your collateral — you never come out ahead. you need the price to be one number when you borrow and a different number when the solvency check settles. read-only reentrancy hands you exactly that window.

#### the play

1. add liquidity → get lp.
2. deposit part of the lp into `MirrorLend` as collateral.
3. call `pool.removeLiquidity()` on the rest. inside your `receive()` the virtual price is skewed high, so `MirrorLend.borrow()` lets you borrow far past what your collateral is honestly worth. lender's now under-secured.
4. let `removeLiquidity()` finish — price snaps back, you've already over-borrowed.

`isSolved` = debt exceeds collateral value at the honest post-exploit price — a state you can't reach without the skew.

#### the fix

don't trust a manipulable live price mid-tx. read `get_virtual_price()` behind the pool's own reentrancy lock (curve's `remove_liquidity(0, [0,0])` idiom trips the lock before reading), or price collateral off a manipulation-resistant oracle.

#### reference solve
`challenge/test/Solve.t.sol` — `forge test` in `challenge/`. deploys `Setup`, runs the reentrant exploit from `receive()`, asserts `isSolved()`.

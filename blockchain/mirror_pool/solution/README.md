# Mirror Pool reference solve

proven exploit is the green forge test at `../challenge/test/Solve.t.sol`. `forge test` deploys `Setup`, runs the full attack, asserts `isSolved()`.

#### the play: read-only reentrancy across two clean contracts

`MirrorLend` prices lp collateral off `Pool.get_virtual_price()` live. `Pool.removeLiquidity()` sends you eth *before* it finishes settling reserves, so mid-callback the virtual price reads high.

1. add liquidity to the `Pool`, take the lp, deposit it into `MirrorLend` as collateral.
2. call `Pool.removeLiquidity()`. it sends eth first, your `receive()` runs while `totalSupply` is already down but the token half is still in the pool, so `get_virtual_price()` reports an inflated lp price.
3. inside that callback, call `MirrorLend.borrow()`. it values your collateral at the inflated price and lets you borrow far past its worth.
4. let `removeLiquidity()` finish, price snaps back, you've already over-borrowed. lender's insolvent ⇒ `isSolved()`.

#### against a live instance
`GET /` returns the rpc endpoint, your private key, and the `Setup` address. replay with a forge script (`--rpc-url $RPC --private-key $KEY --broadcast`) or `cast`, then `GET /flag`.

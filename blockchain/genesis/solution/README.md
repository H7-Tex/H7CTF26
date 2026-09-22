# Genesis reference solve

proven exploit is the green forge test at `../challenge/test/Solve.t.sol`. `forge test` deploys `Setup`, runs the full attack, asserts `isSolved()`. there's a second test proving the naive donation (no `sync()`) leaves the victim with real shares. that's the trap.

#### the play: erc-4626 inflation you have to re-arm

`totalAssets()` returns an internal `reserve` counter, not `asset.balanceOf(this)`, so a bare donation is invisible until someone calls the unguarded `sync()` that slams `reserve` up to the real balance. re-arm it, then the classic first-depositor inflation is live.

1. `deposit(1, you)`: supply 0 → 1 share, `reserve` = 1.
2. `transfer(vault, 100 ether)`: real balance jumps, `reserve` still 1 (donation dormant).
3. `sync()`: `reserve` = 100e18 + 1. armed.
4. victim's `victimDeposit()` → `convertToShares(100e18) = 100e18 * 1 / (100e18+1) = 0`. they get **0 shares**, their 100 ether stays in the vault.
5. `redeem(1)`: you own 100% of supply, take the whole reserve.

victim shares 0, vault drained → `isSolved()`.

#### against a live instance
`GET /` returns the rpc endpoint, your private key, and the `Setup` address. replay with a forge script (`--rpc-url $RPC --private-key $KEY --broadcast`) or `cast`, then `GET /flag`.

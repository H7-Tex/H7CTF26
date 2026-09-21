# Genesis — writeup

**Class:** ERC-4626 first-depositor / donation inflation, hidden behind a disguised "safe-looking" guard.

## The disguise

`GenesisVault` reads like a standard, inflation-protected ERC-4626 vault — it has `_decimalsOffset()` and even uses `10 ** _decimalsOffset()` inside `convertToShares`. But the offset returns **0**, so `10**0 = 1`: the "virtual shares" multiplier does nothing, and it only ever applies to the very first deposit. The ongoing share math is the naive `assets * totalSupply / totalAssets()`, and `totalAssets()` reads `asset.balanceOf(address(this))` — which anyone can inflate with a raw `transfer`. There are no real virtual shares or virtual assets. A reviewer who pattern-matches "has `_decimalsOffset()` → OZ-protected" walks right past it.

## The exploit

1. Deposit 1 wei → mint 1 share (you now own ~100% of a near-empty vault).
2. Donate a large amount directly to the vault (`token.transfer(vault, 100e18)`) → `totalAssets` is now huge while `totalSupply` is still 1.
3. The anchor investor deposits `100e18`: `shares = 100e18 * 1 / (100e18 + 1) = 0` (floor). They receive **0 shares**; their funds are now sitting in the vault.
4. Redeem your 1 share → `convertToAssets(1)` returns the entire vault balance, including the victim's deposit.

## Fix

Wire real virtual shares/assets into the share math (OpenZeppelin's approach: `_decimalsOffset() >= 6` with a `+1` virtual asset in both directions), and track `totalAssets` from internal accounting rather than `balanceOf`, which is donatable.

## Reference solve

`challenge/test/Solve.t.sol` — run `forge test` in `challenge/`. It deploys `Setup`, runs the exploit, and asserts `Setup.isSolved()`.

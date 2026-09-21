# Genesis — reference solve

The proven reference exploit is the passing forge test at `../challenge/test/Solve.t.sol`
(`forge test` is green): it deploys `Setup`, runs the full attack, and asserts `isSolved()`.

## Exploit — ERC-4626 first-depositor inflation

The vault's inflation guard is a no-op (`_decimalsOffset()` returns 0), and `totalAssets()`
reads the raw token balance, which anyone can inflate with a bare transfer.

1. As the first depositor, `deposit` 1 wei of the asset → you mint 1 share.
2. Donate a large amount of the asset straight to the vault (a plain `transfer`, not a
   `deposit`). `totalAssets()` jumps while `totalSupply` stays 1.
3. The anchor investor's `victimDeposit()` now computes `assets * totalSupply / totalAssets()`,
   which rounds their whole deposit **down to 0 shares** — their assets are absorbed into your
   single share.
4. Redeem your share and drain the vault. `isSolved()` holds:
   `victimDeposited && vault.balanceOf(victim) == 0 && token.balanceOf(vault) < 1 ether`.

## Against a live instance

`GET /` on the launched instance returns the RPC endpoint, your private key, and the `Setup`
address. Replay the steps above with a forge script (`--rpc-url $RPC --private-key $KEY
--broadcast`) or `cast`, then `GET /flag`.

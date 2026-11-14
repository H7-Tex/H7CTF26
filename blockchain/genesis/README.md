# Genesis

**Category:** blockchain (EVM)  **Difficulty:** medium  **Author:** abu

> genesis vault opened this morning: a fresh yield vault, the sort that's been audited a hundred times over. a big anchor investor is about to move in with a very large stake.
>
> "the beginning is the most important part of the work." by the time the anchor's deposit settles, own the vault outright and leave their stake worth exactly nothing.

Provided: `challenge/src/Setup.sol`, `GenesisVault.sol`, `Token.sol`. Each instance runs on the shared EVM harness (`../harness`): `GET /` gives the RPC url, your key and the Setup address, `GET /flag` checks `isSolved()`.

## Solution

Fresh ERC-4626 vault, big depositor incoming, so the first thing anyone tries is first-depositor inflation: deposit 1 wei, donate a pile of tokens straight to the vault, let the victim's shares round down to zero. Here it does nothing. The victim gets normal shares.

The reason is `totalAssets()`. It returns an internal `reserve` counter, not `asset.balanceOf(this)`, so a raw transfer to the vault is invisible to the share math:

```solidity
function totalAssets() public view returns (uint256) { return reserve; }
function convertToShares(uint256 assets) public view returns (uint256) {
    uint256 supply = totalSupply;
    return supply == 0 ? assets : assets * supply / reserve;
}
```

But there's also this, with no access control:

```solidity
function sync() external { reserve = asset.balanceOf(address(this)); }
```

So the donation just needs re-arming. The full sequence:

1. `deposit(1, me)`: 1 share, `reserve = 1`.
2. `token.transfer(vault, 100 ether)`: real balance jumps, `reserve` is still 1.
3. `sync()`: `reserve = 100e18 + 1`.
4. `setup.victimDeposit()`: `100e18 * 1 / (100e18 + 1) = 0` shares for the anchor, and their 100 ether lands in the vault anyway.
5. `redeem(1, me, me)`: we hold the whole supply, so we take the whole reserve.

Victim has 0 shares and the vault is empty, so `isSolved()` is true. The reference solve is `challenge/test/Solve.t.sol`; there's a second test in there showing that skipping `sync()` leaves the victim with real shares.

```
cd challenge && forge test
```

Against a live instance we replayed the same five calls with `cast send --rpc-url $RPC --private-key $KEY` and then hit `GET /flag`.

Flag is dynamic per instance (`H7CTF{...}`).

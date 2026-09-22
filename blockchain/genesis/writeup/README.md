# Genesis writeup

`erc-4626 inflation, but you have to re-arm it first`

#### the trap

everyone's first instinct on a fresh vault: first-depositor inflation. deposit 1 wei, donate a pile of the asset straight to the vault, watch the next depositor's shares round to 0. try it here and it does nothing.

why: `totalAssets()` returns `reserve`, an internal counter, not `asset.balanceOf(this)`. a raw `transfer` to the vault bumps the real balance but not `reserve`, so `convertToShares` never sees your donation. the victim gets normal shares. dead end.

```solidity
uint256 public reserve;
function totalAssets() public view returns (uint256) { return reserve; }
function convertToShares(uint256 assets) public view returns (uint256) {
    uint256 supply = totalSupply;
    return supply == 0 ? assets : assets * supply / reserve;   // uses reserve, not balanceOf
}
```

#### the real bug

there's a `sync()`:

```solidity
function sync() external { reserve = asset.balanceOf(address(this)); }
```

it re-arms your donation. `sync()` slams `reserve` up to the real balance (donation included), no access control, callable by anyone. now the inflation is live.

#### the play

1. `deposit(1, you)`: supply 0 → 1 share, `reserve` = 1.
2. `transfer(vault, 100 ether)`: real balance jumps, `reserve` still 1.
3. `sync()`: `reserve` = 100e18 + 1. armed.
4. `victimDeposit()` → `convertToShares(100e18) = 100e18 * 1 / (100e18+1) = 0`. anchor gets **0 shares**, their 100 ether lands in the vault anyway.
5. `redeem(1)` → you own 100% of supply, you take the whole reserve.

victim shares 0, vault drained → `isSolved()`. `forge test` proves both the solve and that step 2 alone (no sync) leaves the victim with real shares.

#### the fix

don't let anyone re-sync accounting to a manipulable balance. track `reserve` internally only (drop `sync()`, or restrict + validate it), or use virtual shares/offset so a lone donation can't round anyone to zero.

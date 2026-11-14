# Trompe-l'œil

**Category:** blockchain (EVM)  **Difficulty:** hard  **Author:** abu

> MirrorLend lets you borrow against your Mirror LP tokens, and it holds a real reserve for its lenders. On paper, every figure reconciles.
>
> A good trompe-l'oeil only has to hold for as long as the eye is on it. The reserve won't notice you leaving.

Provided: `challenge/src/*.sol`. Runs on the shared EVM harness (`../harness`), `GET /` for connection info, `GET /flag` once `Setup.isSolved()` is true.

## Solution

Two contracts, and read on their own both look fine. `MirrorLend.borrow()` values LP collateral with a plain view call to `pool.get_virtual_price()`:

```solidity
get_virtual_price() = (address(this).balance + token.balanceOf(this)) * 1e18 / totalSupply
```

Donating to pump the price is a dead end, since the solvency check in `isSolved()` reads the same price and scales right along with your collateral. What we need is a moment where the price we borrow at and the honest price disagree.

`Pool.removeLiquidity()` gives us that:

```solidity
balanceOf[msg.sender] -= lp;
totalSupply -= lp;
(bool ok, ) = msg.sender.call{value: ethOut}("");   // we get control here
require(token.transfer(msg.sender, tokenOut), "tok");
```

Inside our `receive()`, `totalSupply` has already dropped and the ETH is gone, but the token half of our withdrawal is still sitting in the pool. The virtual price reads high. Classic read-only reentrancy, the bug lives in the seam between the two contracts.

1. `addLiquidity{value: 100 ether}(100 ether)`, get 200 LP (pool starts at 10 ETH + 10 tokens, 20 LP).
2. Deposit 100 LP into MirrorLend.
3. `removeLiquidity(100 ether)` on the other half.
4. In `receive()`: price is `(55 + 110) / 120 = 1.375`, so `borrow(collateralLP * price / 1e18)` hands us 137.5 tokens against collateral worth 100.
5. `removeLiquidity` finishes, the price snaps back to 1, and `totalDebt` is now above the collateral value.

Reference solve is `challenge/test/Solve.t.sol` (`forge test` in `challenge/`). On a live instance, deploy an attacker contract with the same `receive()`, fund it with the 100 tokens and 100 ETH, run the steps from a normal function (not the constructor, `receive()` won't fire there), then `GET /flag`.

Flag is dynamic per instance (`H7CTF{...}`).

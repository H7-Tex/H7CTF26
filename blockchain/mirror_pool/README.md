# Mirror Pool

- **Category:** blockchain (EVM)
- **Difficulty:** insane
- **Author:** h7

MirrorLend lets you borrow against your Mirror LP tokens. It prices your collateral straight from the pool's own `get_virtual_price()` — the number every integrator trusts. Read the lending contract: it's clean. Read the pool: it's clean too.

Borrow more than your collateral is worth, and drain the lender.

**Files:** `Setup.sol`, `Pool.sol`, `MirrorLend.sol`, `Token.sol`, `IERC20.sol`

**Connect:** launch your instance and connect over the provided endpoint; the flag is revealed when `Setup.isSolved()` returns true.

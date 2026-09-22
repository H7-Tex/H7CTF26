# Mirror Pool

`blockchain` `evm` `insane`

mirrorlend lets you borrow against your mirror lp tokens. it prices your collateral straight off the pool's own `get_virtual_price()`, the number every integrator trusts. read the lender: clean. read the pool: clean too.

borrow more than your collateral is worth, drain the lender.

#### connect
launch an instance, point your rpc at the endpoint. you get the rpc, your key, the setup address. flag drops when `Setup.isSolved()` goes true.

#### provided
- `challenge/src/*.sol`

#### notes
the obvious move (donate to pump the virtual price, then over-borrow) is a dead end; the price only ever moves the wrong way for you, and the borrow check scales with it. you need a *moment* where the price you borrow at and the price the check later sees don't agree.

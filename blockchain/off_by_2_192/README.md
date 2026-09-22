# Tidepool

`blockchain` `sui` `insane`

a sui liquidity pool. mint liquidity, pay what it says you owe, redeem your share of the reserve later. the amount you owe runs through a *checked* fixed-point conversion that aborts on overflow, there's a hard cap on how much you can mint at once, and it won't hand out liquidity for free. looks locked down.

walk out with the whole reserve.

#### connect
spin up an instance, connect to the endpoint. you get the package id, the shared `Pool` object, your keypair + gas, and a channel to send your solve tx. drain it, grab the flag.

#### provided
- `challenge/sources/pool.move`
- `challenge/Move.toml`

#### notes
every guard here actually holds: the cap, the overflow check, the no-free-liquidity check. that's the point. the conversion is where the numbers stop behaving; work out what it does right at the edge, and which inputs walk straight between all three guards.

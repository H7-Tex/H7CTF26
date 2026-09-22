# Genesis

`blockchain` `evm` `hard`

fresh erc-4626 vault, just went live. some anchor investor is about to drop a fat first deposit into it. you got there first.

make their deposit yours.

#### connect
spin up an instance, point your rpc at the endpoint. you get the rpc url, your private key, and the setup address (`GET /`). solve it, then `GET /flag`.

#### provided
- `challenge/src/Setup.sol`
- `challenge/src/GenesisVault.sol`
- `challenge/src/Token.sol`

#### notes
the textbook inflation trick faceplants here. the vault doesn't price what it doesn't know it's holding. read how it decides what it holds. that's the whole game.

# Fee Swap

`blockchain` · `solana` · `hard`

feeswap is a tiny two-asset pool. send it token A, get token B back — minus a small swap fee the pool skims for itself. clean 1:1 desk, healthy B reserve it's confident it can always cover.

you're holding token A. leave with the pool's B reserve.

#### connect
spin up an instance, connect over the endpoint. you get the program id, the pool + vault + mint addresses, your funded token accounts + keypair, and a channel to send solve txs. drain B, grab the flag.

#### provided
- `challenge/program/src/lib.rs`
- `challenge/program/Cargo.toml`

#### notes
the obvious holes are shut — the pool checks its own object's owner, inits once, derives its own signer, and takes a fee on every swap. the real question is whether the number it *pays out* is the number that actually *arrived* — and whether the cut it skims covers what your particular token does in transit.

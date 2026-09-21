# sui hosting harness notes (off_by_2_192, cross_collateral)

both sui challenges host on **otter-sec/sui-ctf-framework**, which pins **devnet-v1.49.0**. the framework nominally targets rust 1.86, but a dep in the 1.49 tree needs 1.88, so the images build on **rust 1.88**. the move packages must be built with a **sui devnet-v1.49.0** cli so the bytecode matches the framework's `move-binary-format @ 1.49`.

#### verified locally (sui 1.49.0)
all four move packages build/test on sui devnet-v1.49.0 (old-style Move.toml, edition `2024.alpha`, explicit `Sui rev = devnet-v1.49.0`; solves pin the same sui rev explicitly or they resolve a newer, 1.49-unparseable framework):
- `off_by_2_192/challenge` — `sui move test` PASS (`drains_pool_via_overflow`)
- `off_by_2_192/solution/solve` — `sui move build` OK
- `cross_collateral/challenge` — `sui move test` PASS (`cross_type_drain`)
- `cross_collateral/solution/solve` — `sui move build` OK

#### layout per challenge
- `challenge/` — the move package (built → `build/<pkg>/bytecode_modules/*.mv` + `debug_info/*.json`)
- `server/` — the sui-ctf-framework server (rust; publishes challenge modules, reads the player's compiled solve module over tcp :1337, publishes it, runs the call sequence, validates)
- `solution/solve/` — the reference solve move module (what a player uploads, compiled to `.mv`)
- `Dockerfile` — rust:1.88-slim + clang/libclang-dev/cmake + sui devnet-v1.49.0 cli → `sui move build` the package → `cargo build` the server

#### call sequences
**off_by_2_192:** publish `pool` → `pool::create_and_share(seed: Coin<SUI>)` → publish solve → `solution::solve(pool, payment: Coin<SUI>)` → `pool::flag(pool)` (aborts unless reserve drained → no abort = win).

**cross_collateral:** publish `bank`+`cheap` (cheap::init mints a `TreasuryCap<CHEAP>` to challenger) → `bank::create_and_share()` → `bank::fund<SUI>(bank, seed)` → `cheap::mint(treasury, 1_000_000, solver)` → publish solve → `solution::solve(bank, cheap_coin)` → `bank::flag<SUI>(bank)` (aborts unless sui drained → no abort = win).

#### adapter-specific unknowns (marked `ADAPTER-SPECIFIC` / `TODO(finals)` in the servers)
only these need pinning on the actual `move-transactional-test-runner` object numbering; the rest of the flow is fixed:
- the seed `Coin<SUI>` (~1_000_000) — must be **minted/split as a distinct object**, not the gas coin reused (a doubled gas coin trips `MutableObjectUsedMoreThanOnce`); its FakeID
- the shared object ids (Pool / Bank) after `create_and_share`
- (cross_collateral) the `TreasuryCap<CHEAP>` FakeID from `cheap::init`, the minted CHEAP coin's FakeID, the solver account address, and the `SuiValue` encoding for `cheap::mint`'s pure args (`amount: u64`, `recipient: address`)

flag: when the validating `flag`/`flag<SUI>` call succeeds (no abort), the server emits `$FLAG`.

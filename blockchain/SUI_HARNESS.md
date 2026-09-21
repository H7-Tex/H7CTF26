# Sui hosting harness notes (off_by_2_192, cross_collateral)

Both Sui challenges host on **otter-sec/sui-ctf-framework**, which pins **devnet-v1.49.0** +
**rust 1.86**. The Move packages must be built with a **sui devnet-v1.49.0** CLI so the
bytecode matches the framework's `move-binary-format @ 1.49`.

## Verified locally (sui 1.49.0)
All four Move packages build/test on sui devnet-v1.49.0 (old-style Move.toml, edition
`2024.alpha`, explicit `Sui rev = devnet-v1.49.0`; solves pin the same Sui rev explicitly or
they resolve a newer, 1.49-unparseable framework):
- `off_by_2_192/challenge` — `sui move test` PASS (`drains_pool_via_overflow`)
- `off_by_2_192/solution/solve` — `sui move build` OK
- `cross_collateral/challenge` — `sui move test` PASS (`cross_type_drain`)
- `cross_collateral/solution/solve` — `sui move build` OK

## Layout per challenge
- `challenge/` — the Move package (built → `build/<pkg>/bytecode_modules/*.mv` + `debug_info/*.json`)
- `server/` — the sui-ctf-framework server (Rust; publishes challenge modules, reads the
  player's compiled solve module over TCP :1337, publishes it, runs the call sequence, validates)
- `solution/solve/` — the reference solve Move module (what a player uploads, compiled to `.mv`)
- `Dockerfile` — rust:1.86 + sui devnet-v1.49.0 CLI → `sui move build` the package → `cargo build` the server

## Call sequences
**off_by_2_192:** publish `pool` → `pool::create_and_share(seed: Coin<SUI>)` → publish solve →
`solution::solve(pool)` → `pool::flag(pool)` (aborts unless reserve drained → no abort = win).

**cross_collateral:** publish `bank`+`cheap` (cheap::init mints a `TreasuryCap<CHEAP>` to
challenger) → `bank::create_and_share()` → `bank::fund<SUI>(bank, seed)` →
`cheap::mint(treasury, 1_000_000, solver)` → publish solve → `solution::solve(bank, cheap_coin)`
→ `bank::flag<SUI>(bank)` (aborts unless SUI drained → no abort = win).

## Adapter-specific unknowns (marked `ADAPTER-SPECIFIC` / `TODO(finals)` in the servers)
Only these need pinning on the actual `move-transactional-test-runner` object numbering; the
rest of the flow is fixed:
- the seed `Coin<SUI>` (~1_000_000) — source from the challenger gas coin / a split; its FakeID
- the shared object ids (Pool / Bank) after `create_and_share`
- (cross_collateral) the `TreasuryCap<CHEAP>` FakeID from `cheap::init`, the minted CHEAP coin's
  FakeID, the solver account address, and the `SuiValue` encoding for `cheap::mint`'s pure args
  (`amount: u64`, `recipient: address`)

Flag: on the validating `flag`/`flag<SUI>` call succeeding (no abort), the server emits `$FLAG`.

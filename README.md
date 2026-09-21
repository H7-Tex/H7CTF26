# H7CTF'26 — Challenges

source for the h7ctf'26 qualifier challenges. private during dev, public after the event — clone it, rebuild any challenge locally, learn from the lot.

#### layout
category-first, one dir per challenge `<category>/<name>/`:
```
<category>/<name>/
├── challenge.yml   metadata + deploy contract (see contributing.md)
├── README.md       the public card: title, author, difficulty, blurb
├── challenge/      source + real flag (flag stays private till release)
├── solution/       reference solve — recovers the flag on a fresh instance
└── writeup/        intended solution
```
categories: `crypto` `pwn` `web` `rev` `forensics` `misc` `osint` `blockchain` `hardware` `mobile` `cloud`

#### the bar
every challenge ships a working reference solve + a writeup, no exceptions. realistic, zero guess-the-flag, bugs a scanner won't catch — each one a real bug class with a trap so it can't be pattern-matched cold. `challenge.yml` maps 1:1 to the anvil importer; schema + the flag/secrets rule live in [contributing.md](CONTRIBUTING.md).

#### blockchain [`cooked`]
6, all hard+:
- `genesis` — evm · erc-4626 reserve-accounting inflation (sync re-arms a donation)
- `mirror_pool` — evm · read-only reentrancy, borrow-vs-check price gap
- `perp_guard` — solana · compute-budget liquidation dos behind a position cap
- `fee_swap` — solana · token-2022 transfer-fee confusion under a too-small swap fee
- `tidepool` — sui · cetus `checked_shlw` overflow past three guards
- `cross_collateral` — sui · inverted cross-asset conversion ratio

#### license
code [AGPL-3.0](LICENSE); writeups, descriptions, assets [CC BY-SA 4.0](LICENSE-CONTENT.md).

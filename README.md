`H7CTF'26`

source for the h7ctf'26 qualifier challenges. private while we build, public once the event's done. clone it and rebuild any challenge locally on the same toolchain the live infra runs.

#### layout
category first, one dir per challenge `<category>/<name>/`:
```
<category>/<name>/
├── challenge.yml   metadata + deploy contract (see contributing.md)
├── README.md       the public card: title, author, difficulty, blurb
├── challenge/      source + the real flag (flag stays private till release)
├── solution/       reference solve, recovers the flag on a fresh instance
└── writeup/        how it's meant to go
```

#### blockchain [`cooked`]
6 challenges, all hard+. each runs on its own throwaway instance: foundry for evm, an sbf program behind a sol-ctf-framework tcp server for solana, sui-ctf-framework on devnet-v1.49.0 for move.
- `genesis` (evm) erc-4626 reserve-accounting inflation, `sync` re-arms a donation you already redeemed
- `mirror_pool` (evm) read-only reentrancy, the borrow path reads a price the check path just invalidated
- `perp_guard` (solana) liquidation walks every position o(n), so pad the book past the compute budget and the position can never be closed
- `fee_swap` (solana) token-2022 transfer-fee accounting confusion when the pool's swap fee is smaller than the token's own fee
- `tidepool` (sui) cetus `checked_shlw` overflow, reachable past three guards that look like they close it
- `cross_collateral` (sui) inverted cross-asset conversion ratio, worthless collateral pulls real reserves out

#### license
code [AGPL-3.0](LICENSE), writeups + descriptions + assets [CC BY-SA 4.0](LICENSE-CONTENT.md).

# Hostile Takeover (blockchain KotH #2)

On-chain King of the Hill. The throne is one storage slot (`Throne.king`); the only way to
move it is a governance takeover. Teams flash-loan voting power to pass a hostile proposal
that seats them as DAO Guardian, and hold the seat while rivals coup back. Hold-time scores.
The engine polls `/koth/status`; the governor epoch rotates each round so a static replay bot
breaks and must re-solve. Companion to GridWatch (KotH #1) in a different domain.

## Layout
```
challenge/src/   GovToken (live votes, no snapshot) / FlashLender / Governor (no timelock,
                 epoch-gated execute) / Throne / Setup       <- provided to players
challenge/test/  Takeover.t.sol (3 forge tests)
server/server.py the RPC bridge (only exposed service)
entrypoint.sh    anvil (gasprice 0) + deploy Setup + run the bridge
Dockerfile       foundry base + python/flask; build context = this dir
solution/        Coup.sol + exploit.sh (reference)
```

## How the arena works
- One shared Anvil node (localhost, instamine). Never exposed. NB: anvil still advertises ~1 gwei
  on eth_gasPrice even under `--gas-price 0` (foundry-version quirk) and cast/forge won't build a
  0-price send, so teams drive their exploit from a pre-funded standard dev account (the default
  foundry test mnemonic funds accts 0-9 with 10000 ETH; use index 1-9, acct0 is the operator).
- The bridge is the only reachable service:
  - `GET /koth/info` -> chainId, contract addresses, current governor epoch.
  - `POST /rpc/<team-koth-token>` -> JSON-RPC proxy (read + `eth_sendRawTransaction` only,
    default-deny allowlist), authenticated + rate-limited per team token. Teams send exploit
    txns here; attribution is by the token (which is also the crown tag).
  - `GET /koth/status` -> `{holder, since}` (holder = the king's tag decoded = the team token;
    null if unheld). The engine polls this.
  - `POST /koth/reset` (Bearer `KOTH_ADMIN_TOKEN`) -> rotate the governor epoch + clear the
    seat (round boundary).

## The vulnerability (the seize)
The Governor reads voting power LIVE at `castVote` (no snapshot/`getPastVotes`) and has NO
timelock, so a flash loan buys a controlling vote for one transaction: borrow the gov-token
pool -> delegate to self -> propose `crown(you, tag)` -> vote (live power clears quorum) ->
execute -> repay. Real DAOs prevent exactly this with checkpointed voting (Beanstalk, ~$181M)
and a timelock. The one guard that matters: a proposal is bound to the epoch it was created
in, and `execute` requires that epoch to still be current -> a round reset (`rotateEpoch`)
kills stale proposals and replayed txns, so holding is skill-bounded, not uptime-bounded.

## Build / deploy (Finals)
`docker build -t h7ctf26/hostile-takeover blockchain/hostile_takeover`. `scoring: koth`,
`instancing: static` (one shared arena), http :8080 -> a public web route (no VPN). Inject
`KOTH_ADMIN_TOKEN` (gates /koth/reset) and, in prod, `KOTH_VERIFY_URL` = the engine's
token->team_id endpoint so only issued buy-in tokens can play. The engine drives `/koth/reset`
at round boundaries.

## Validation
Verified end to end locally (Foundry 1.8.3): `forge test` = 3/3 (flash-loan takeover seizes,
contested re-seize A->B, epoch rotation breaks replay); and the live arena (anvil + deploy +
bridge) with the shipped `solution/exploit.sh` seizes the seat, `/koth/status` reports the
team, `/koth/reset` rotates the epoch + clears the seat, re-run re-seizes in the new epoch;
the RPC allowlist blocks admin methods and reset-auth is enforced.

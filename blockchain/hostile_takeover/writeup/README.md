# Hostile Takeover - writeup

Goal: hold the DAO Guardian seat (`Throne.king`). The only mutator is `Throne.crown()`, gated
`onlyGovernor` - no access-control backdoor. So you must make the Governor execute a proposal
that calls `crown(you, yourTag)`.

## Recon
`GET /koth/info` gives the contract addresses and the current governor epoch. Read the
provided sources. Two flaws in the governance stack:
1. `GovToken.getVotes` is a LIVE tally (no checkpoint / `getPastVotes`) - flash-borrowed,
   same-tx-repaid tokens count as votes.
2. `Governor` has NO timelock - `propose` + `castVote` + `execute` can all run in one tx.
And a `FlashLender` holds the whole gov-token supply, lent atomically.

## The takeover (one transaction)
In an attacker contract's flash-loan callback:
1. borrow the full pool from `FlashLender`,
2. `GovToken.delegate(self)` -> live voting power = the borrowed stake,
3. `Governor.propose(throne, crown(you, yourKothToken), governor.epochNonce())`,
4. `Governor.castVote(id)` -> `forVotes` = borrowed stake, clears quorum,
5. `Governor.execute(id)` -> `Throne.crown(you, yourKothToken)`,
6. repay the flash loan.

You are now `king`, tagged with your team token; `GET /koth/status` reports your team as the
holder and the engine accrues your hold-time. See `solution/Coup.sol` + `solution/exploit.sh`:

```
./exploit.sh <bridge_url> <your_koth_token> <your_privkey>
```

Send everything through `POST /rpc/<your_koth_token>` (the only reachable RPC).

## Holding it (the round rotation)
Rivals re-run the same takeover to overwrite `king` - the seat is contested. Each round the
engine calls `/koth/reset`, which `rotateEpoch()`s the Governor and clears the seat. A proposal
is bound to the epoch it was created in and `execute` requires that epoch to still be current,
so a hardcoded/replayed attack from a prior round reverts (`stale epoch`). Re-read
`governor.epochNonce()` (the reference does this live) and re-fire each round. Holding is
therefore skill-bounded, not a static-bot uptime race.

## The lesson
This is the Beanstalk (~$181M) class: governance that counts live balance with no snapshot and
no timelock is takeover-able by a flash loan. Real DAOs use checkpointed voting power measured
at the proposal block (`ERC20Votes`/`getPastVotes`) plus a timelock between passing and
execution - either one alone defeats this attack.

# Hostile Takeover

**Category:** blockchain (EVM, King of the Hill)  **Difficulty:** insane  **Author:** abu

> GENESIS DAO owns a treasury, and one privileged seat controls it: the Guardian. This is King of the Hill on-chain - seize the Guardian seat, install your team, and hold it while rivals fight to take it back.
>
> The seat resets each round, so expect to take it more than once.
>
> Arena: your instance exposes a bridge. GET /koth/info for the chain id, contract addresses and current epoch; send your exploit transactions to POST /rpc/<your-koth-token>. Buy-in also gives you a private rpc secret: every /rpc call must carry it as the X-Koth-Secret header (foundry: set ETH_RPC_HEADERS="X-Koth-Secret: <secret>", or --rpc-headers), or the write is refused - your token alone is public and cannot write. It is a shared Anvil chain - the standard foundry/hardhat dev accounts (the default test mnemonic, indices 1-9) are funded, so drive your exploit from one of those to pay gas. Account 0 is the arena operator; do not use it.

Finals KotH. One shared Anvil node behind `server/server.py`, which is the only exposed service (JSON-RPC allowlist, per-team token + secret, rate limiting). The engine polls `GET /koth/status` for the holder and calls `POST /koth/reset` (Bearer `KOTH_ADMIN_TOKEN`) at each round boundary, which rotates the governor epoch and clears the seat.

```
docker build -t h7ctf26/hostile-takeover .
```

Set `KOTH_ADMIN_TOKEN`, and in prod `KOTH_VERIFY_URL` so only issued buy-in tokens can write.

## Solution

The seat is `Throne.king`, and the only thing that writes it is `Throne.crown()`, which is `onlyGovernor`. No backdoor, so the Governor has to execute a proposal calling `crown(me, myTag)`.

Reading the sources, the governance stack has two problems:

- `GovToken.getVotes` is a live balance tally, no checkpoints, no `getPastVotes`. Tokens borrowed and repaid in the same transaction still count.
- `Governor` has no timelock. `propose`, `castVote` and `execute` can all happen in one transaction.

And `FlashLender` holds the entire gov-token supply. That's Beanstalk. Everything goes in one flash-loan callback:

1. Borrow the whole pool from `FlashLender`.
2. `GovToken.delegate(self)`.
3. `Governor.propose(throne, crown(tx.origin, tag), governor.epochNonce())`.
4. `castVote(id)`, the borrowed stake clears quorum.
5. `execute(id)`, which calls `Throne.crown`.
6. Repay.

`solution/src/Coup.sol` is the contract and `solution/exploit.sh` deploys it through the bridge and fires it:

```
./exploit.sh <bridge_url> <koth_token> <rpc_secret> <funded_dev_privkey>
```

Holding it is the actual game. Rivals run the same takeover to overwrite `king`, and every round reset rotates the epoch. Proposals are bound to the epoch they were created in, so a hardcoded or replayed transaction from the last round reverts with `stale epoch`. `Coup.sol` reads `epochNonce()` live, so re-running the script each round re-seizes.

`challenge/test/Takeover.t.sol` covers the takeover, a contested re-seize between two teams, and the epoch rotation breaking replay (`forge test` in `challenge/`).

No flag; scoring is hold time.

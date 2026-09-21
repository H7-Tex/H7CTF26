# _evm_harness — shared EVM challenge harness

Reusable per-team-instance hosting for EVM challenges. One container = one team = one anvil.

- `anvil` on `127.0.0.1:8545` (never exposed), random accounts, instamine, base fee 0.
- `server.py` on `0.0.0.0:$PORT` — the only reachable service, exposed as one Traefik web route:
  - `POST /` — JSON-RPC proxy to anvil with a default-deny allowlist (only `web3`/`eth`/`net`, minus signing methods; batch elements validated). Players send exploit txs via `eth_sendRawTransaction`.
  - `GET /` — connection info: RPC url (this URL), player private key, Setup address.
  - `GET /flag` — `cast call Setup isSolved()`; returns `$FLAG` if true.
- `entrypoint.sh` — starts anvil, reads player (acct 0) + system (acct 1) keys from anvil's log, deploys `Setup(player)` as the system key via `forge create` (value = `$SETUP_VALUE`), writes `/run/instance.json`.

## Per-challenge usage
Each EVM challenge ships `challenge/Dockerfile`:
```dockerfile
FROM h7ctf26/evm-harness:latest
COPY foundry.toml /project/foundry.toml
COPY src /project/src
RUN forge build
ENV CHALL=<name> SETUP_VALUE=<wei>
```
`SETUP_VALUE` = wei the payable `Setup` constructor requires (0 if non-payable). The platform injects `$FLAG` and routes one web hostname to `$PORT`. anvil stays on localhost; `$FLAG` never touches the chain.

Build the base: `docker build -t h7ctf26/evm-harness blockchain/_evm_harness`.

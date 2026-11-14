# harness

Shared base image for the EVM challenges. One container is one team's instance with its own anvil.

- `entrypoint.sh` starts haveged and runs `harness.py`.
- `harness.py` starts anvil on `127.0.0.1:8545` (never exposed) with two random accounts and base fee 0. Account 0 is the player and account 1 deploys `Setup(player)` from `/setup.bytecode` with `$SETUP_VALUE` wei. The instance info goes to `/run/instance.json`.
- It then serves on `0.0.0.0:$PORT`:
  - `POST /`: JSON-RPC proxy to anvil. Only `web3_`/`eth_`/`net_` methods are allowed, and the signing ones are blocked. Batch elements get checked one by one.
  - `GET /`: RPC url, player key, Setup address.
  - `GET /flag`: calls `Setup.isSolved()` and returns `$FLAG` if it's true.

Each EVM challenge ships a `challenge/Dockerfile` like this:

```dockerfile
FROM h7ctf26/evm-harness:latest
COPY foundry.toml /project/foundry.toml
COPY src /project/src
RUN forge build && forge inspect src/Setup.sol:Setup bytecode > /setup.bytecode
ENV CHALL=<name> SETUP_VALUE=<wei>
```

The platform injects `$FLAG`, and the flag never touches the chain. Build the base with `docker build -t h7ctf26/evm-harness blockchain/harness` (or `cloudbuild-evm.yaml`).

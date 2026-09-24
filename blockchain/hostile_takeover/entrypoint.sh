#!/bin/sh
set -e
haveged -w 1024 >/dev/null 2>&1 || true

RPC=http://127.0.0.1:8545
# deterministic anvil dev account 0 = arena system/admin (rich; owns the Governor)
SYS_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ADMIN=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

# shared arena: instamine, gas price 0 so any team account (0 ETH) can transact for free.
# node stays on localhost; only the bridge (server.py) is exposed.
anvil --host 127.0.0.1 --port 8545 --gas-price 0 --base-fee 0 --silent &
until cast block-number --rpc-url $RPC >/dev/null 2>&1; do sleep 0.3; done

cd /project
SETUP=$(forge create src/Setup.sol:Setup --private-key $SYS_KEY --rpc-url $RPC --broadcast --json --constructor-args $ADMIN | python3 -c 'import sys,json;print(json.load(sys.stdin)["deployedTo"])')

export SYS_KEY ANVIL_RPC=$RPC
export TOKEN_ADDR=$(cast call $SETUP "token()(address)" --rpc-url $RPC)
export LENDER_ADDR=$(cast call $SETUP "lender()(address)" --rpc-url $RPC)
export GOVERNOR_ADDR=$(cast call $SETUP "governor()(address)" --rpc-url $RPC)
export THRONE_ADDR=$(cast call $SETUP "throne()(address)" --rpc-url $RPC)
export PORT=${PORT:-8080}
echo "arena ready: setup=$SETUP throne=$THRONE_ADDR governor=$GOVERNOR_ADDR"

exec python3 /server.py

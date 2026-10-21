#!/bin/sh
set -e
haveged -w 1024 >/dev/null 2>&1 || true

RPC=http://127.0.0.1:8545
# anvil dev acct 0 = arena system/admin
SYS_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
ADMIN=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
# anvil dev acct 2 = bot EOA (key is public; intentional for D2 discovery)
BOT_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
# anvil dev acct 1 = published delegatee (anyone who replays the sig redirects bot votes here)
DELEGATEE=0x70997970C51812dc3A010C7d01b50e0d17dc79C8
# max uint40 so the sig never expires
EXPIRY=281474976710655

# start anvil: instamine, gas-free, localhost only; server.py is the only external face
anvil --host 127.0.0.1 --port 8545 --gas-price 0 --base-fee 0 --silent &
until cast block-number --rpc-url $RPC >/dev/null 2>&1; do sleep 0.3; done

cd /project
SETUP_ADDR=$(forge create src/Setup.sol:Setup \
    --private-key $SYS_KEY --rpc-url $RPC --broadcast --json \
    --constructor-args $ADMIN $ADMIN \
    | python3 -c 'import sys,json;print(json.load(sys.stdin)["deployedTo"])')

TOKEN_ADDR=$(cast call $SETUP_ADDR "token()(address)"    --rpc-url $RPC)
LENDER_ADDR=$(cast call $SETUP_ADDR "lender()(address)"  --rpc-url $RPC)
GOVERNOR_ADDR=$(cast call $SETUP_ADDR "governor()(address)" --rpc-url $RPC)
THRONE_ADDR=$(cast call $SETUP_ADDR "throne()(address)"  --rpc-url $RPC)
VAULT_ADDR=$(cast call $SETUP_ADDR "vault()(address)"    --rpc-url $RPC)
TIMELOCK_ADDR=$(cast call $SETUP_ADDR "timelock()(address)" --rpc-url $RPC)
BOT_ADDR=$(cast wallet address --private-key $BOT_KEY)

# transfer BOT_SUPPLY from Setup to bot EOA, then bot self-delegates
cast send $SETUP_ADDR "setupBot(address)" $BOT_ADDR \
    --private-key $SYS_KEY --rpc-url $RPC --silent
cast send $TOKEN_ADDR "delegate(address)" $BOT_ADDR \
    --private-key $BOT_KEY --rpc-url $RPC --silent

# compute EIP-712 sig for bot's delegation to DELEGATEE (D2 published sig)
BOT_ADDR=$BOT_ADDR BOT_KEY=$BOT_KEY TOKEN_ADDR=$TOKEN_ADDR \
DELEGATEE=$DELEGATEE EXPIRY=$EXPIRY \
    python3 /compute_sig.py

. /tmp/bot_sig.env
cast send $SETUP_ADDR \
    "setBotSig(address,address,uint256,uint256,uint8,bytes32,bytes32)" \
    $BOT_ADDR $DELEGATEE 0 $EXPIRY $BOT_V $BOT_R $BOT_S \
    --private-key $SYS_KEY --rpc-url $RPC --silent

echo "arena ready: setup=$SETUP_ADDR throne=$THRONE_ADDR governor=$GOVERNOR_ADDR vault=$VAULT_ADDR timelock=$TIMELOCK_ADDR"

export SYS_KEY ANVIL_RPC=$RPC
export SETUP_ADDR TOKEN_ADDR LENDER_ADDR GOVERNOR_ADDR THRONE_ADDR VAULT_ADDR TIMELOCK_ADDR
export BOT_ACCOUNT=$BOT_ADDR BOT_DELEGATEE=$DELEGATEE BOT_NONCE=0 BOT_EXPIRY=$EXPIRY
export BOT_V BOT_R BOT_S
export PORT=${PORT:-8080}

exec python3 /server.py

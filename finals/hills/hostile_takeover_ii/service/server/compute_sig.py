#!/usr/bin/env python3
# compute EIP-712 delegation sig for the bot and write to /tmp/bot_sig.env
import os, subprocess

rpc        = "http://127.0.0.1:8545"
token_addr = os.environ["TOKEN_ADDR"]
bot_key    = os.environ["BOT_KEY"]
delegatee  = os.environ["DELEGATEE"]
expiry     = int(os.environ["EXPIRY"])
nonce      = 0


def cast_call(addr, sig):
    r = subprocess.run(["cast", "call", addr, sig, "--rpc-url", rpc],
                       capture_output=True, text=True, timeout=10)
    return r.stdout.strip()


def keccak_hex(data_hex):
    # data_hex is a 0x-prefixed hex string; returns 0x-prefixed keccak256
    r = subprocess.run(["cast", "keccak", data_hex],
                       capture_output=True, text=True, timeout=5)
    return r.stdout.strip()


domain_sep = cast_call(token_addr, "DOMAIN_SEPARATOR()(bytes32)")   # 0x...
typehash   = cast_call(token_addr, "DELEGATION_TYPEHASH()(bytes32)")  # 0x...

# struct hash = keccak256(abi.encode(DELEGATION_TYPEHASH, delegatee, nonce, expiry))
delegatee_padded = delegatee[2:].lower().zfill(64)
nonce_padded     = format(nonce,  "064x")
expiry_padded    = format(expiry, "064x")
struct_input     = "0x" + typehash[2:] + delegatee_padded + nonce_padded + expiry_padded
struct_hash      = keccak_hex(struct_input)

# EIP-712 digest = keccak256("\x19\x01" || domainSeparator || structHash)
digest_input = "0x1901" + domain_sep[2:] + struct_hash[2:]
digest       = keccak_hex(digest_input)

# sign the raw digest (--no-hash: digest is already keccak'd; cast must NOT hash again)
r = subprocess.run(
    ["cast", "wallet", "sign", "--private-key", bot_key, "--no-hash", digest],
    capture_output=True, text=True, timeout=10)
sig_hex = r.stdout.strip()

sig_bytes = bytes.fromhex(sig_hex[2:])
r_hex = "0x" + sig_bytes[:32].hex()
s_hex = "0x" + sig_bytes[32:64].hex()
v     = sig_bytes[64]
if v < 27:
    v += 27  # normalise to Ethereum recovery id

with open("/tmp/bot_sig.env", "w") as f:
    f.write(f"BOT_V={v}\nBOT_R={r_hex}\nBOT_S={s_hex}\n")

print(f"bot sig: v={v} r={r_hex[:18]}... s={s_hex[:18]}...", flush=True)

import os, re, json, time, subprocess, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from eth_account import Account
from eth_abi import encode as abi_encode
from web3 import Web3

ANVIL = "http://127.0.0.1:8545"
CHAIN_ID = int(os.environ.get("CHAIN_ID", "31337"))
PORT = int(os.environ.get("PORT", "1337"))
SETUP_VALUE = int(os.environ.get("SETUP_VALUE", "0"))
ALLOWED_NS = {"web3", "eth", "net"}
BLOCKED = {
    "eth_sign", "eth_signTransaction", "eth_signTypedData",
    "eth_signTypedData_v3", "eth_signTypedData_v4",
    "eth_sendTransaction", "eth_sendUnsignedTransaction",
}


def start_anvil():
    subprocess.Popen(
        ["anvil", "--host", "127.0.0.1", "--port", "8545", "--chain-id", str(CHAIN_ID),
         "--accounts", "2", "--balance", "100000", "--block-base-fee-per-gas", "0", "--mnemonic-random"],
        stdout=open("/run/anvil.log", "w"), stderr=subprocess.STDOUT)


def wait_ready(w3):
    for _ in range(600):
        try:
            if w3.is_connected():
                w3.eth.get_block("latest")
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError("anvil never became ready")


def provision():
    start_anvil()
    w3 = Web3(Web3.HTTPProvider(ANVIL))
    wait_ready(w3)
    keys = re.findall(r"0x[0-9a-fA-F]{64}", open("/run/anvil.log").read())
    player_key, system_key = keys[0], keys[1]
    system = Account.from_key(system_key)
    player = Account.from_key(player_key).address
    bytecode = open("/setup.bytecode").read().strip()
    data = bytecode + abi_encode(["address"], [player]).hex()
    tx = {
        "from": system.address, "value": SETUP_VALUE,
        "nonce": w3.eth.get_transaction_count(system.address),
        "gas": 29_000_000, "gasPrice": 0, "chainId": CHAIN_ID, "data": data,
    }
    signed = system.sign_transaction(tx)
    txh = w3.eth.send_raw_transaction(signed.raw_transaction)
    setup = w3.eth.wait_for_transaction_receipt(txh, timeout=120).contractAddress
    json.dump({"player_key": player_key, "setup": setup}, open("/run/instance.json", "w"))
    print("setup deployed at %s, player %s" % (setup, player), flush=True)


def allowed(m):
    return isinstance(m, str) and m.split("_")[0] in ALLOWED_NS and m not in BLOCKED


def err_resp(item):
    return {"jsonrpc": "2.0", "id": item.get("id") if isinstance(item, dict) else None,
            "error": {"code": -32601, "message": "method not allowed"}}


def forward(body):
    req = urllib.request.Request(ANVIL, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def is_solved(setup):
    w3 = Web3(Web3.HTTPProvider(ANVIL))
    sel = Web3.keccak(text="isSolved()")[:4]
    out = w3.eth.call({"to": Web3.to_checksum_address(setup), "data": sel})
    return len(out) >= 32 and int.from_bytes(out[-32:], "big") == 1


INST = json.load(open("/run/instance.json")) if os.path.exists("/run/instance.json") else {}


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/plain"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path.rstrip("/") == "/flag":
            ok = False
            try:
                ok = is_solved(INST["setup"])
            except Exception:
                ok = False
            self._send(200, os.environ.get("FLAG", "H7CTF{no_flag_set}") + "\n" if ok else "not solved yet\n")
        else:
            self._send(200,
                "H7CTF'26 :: %s\n\n"
                "rpc endpoint : POST this same URL (json-rpc)\n"
                "chain id     : %s\n"
                "private key  : %s\n"
                "setup        : %s\n\n"
                "use cast/forge, or import the key into MetaMask (add this rpc + chain id) and drive it from Remix.\n"
                "solve it, then GET /flag\n" % (
                    os.environ.get("CHALL", "challenge"), CHAIN_ID, INST["player_key"], INST["setup"]))

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._send(400, "bad json")
        try:
            if isinstance(body, list):
                passthrough = [x for x in body if isinstance(x, dict) and allowed(x.get("method", ""))]
                by_id = {}
                if passthrough:
                    r = json.loads(forward(passthrough))
                    for resp in (r if isinstance(r, list) else [r]):
                        by_id[resp.get("id")] = resp
                out = [by_id.get(x.get("id"), err_resp(x)) if isinstance(x, dict) and allowed(x.get("method", "")) else err_resp(x) for x in body]
                self._send(200, json.dumps(out).encode(), "application/json")
            elif isinstance(body, dict) and allowed(body.get("method", "")):
                self._send(200, forward(body), "application/json")
            else:
                self._send(200, json.dumps(err_resp(body)).encode(), "application/json")
        except Exception:
            self._send(502, "upstream error")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    provision()
    INST = json.load(open("/run/instance.json"))
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()

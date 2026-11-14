#!/usr/bin/env python3
import os, socket, sys

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "1337"))

NEED = {"program", "user", "pool", "authority", "mint_a", "mint_b",
        "vault_a", "vault_b", "user_a", "user_b", "token_program"}


def main():
    s = socket.create_connection((HOST, PORT))
    f = s.makefile("rwb")

    addr = {}
    reserve_b = None
    while (NEED - addr.keys()) or reserve_b is None:
        line = f.readline()
        if not line:
            print("server closed before setup", file=sys.stderr)
            sys.exit(1)
        t = line.decode(errors="replace").strip()
        k, sep, v = t.partition(":")
        if not sep:
            continue
        k, v = k.strip(), v.strip()
        if k in NEED:
            addr[k] = v
        elif k == "reserve_b":
            reserve_b = int(v)

    ix_data = bytes([1]) + reserve_b.to_bytes(8, "little")
    metas = [
        ("r", addr["pool"]),
        ("r", addr["authority"]),
        ("s", addr["user"]),
        ("w", addr["user_a"]),
        ("w", addr["user_b"]),
        ("w", addr["vault_a"]),
        ("w", addr["vault_b"]),
        ("r", addr["mint_a"]),
        ("r", addr["mint_b"]),
        ("r", addr["token_program"]),
    ]

    payload = f"{len(metas)}\n".encode()
    for flag, pk in metas:
        payload += f"{flag} {pk}\n".encode()
    payload += f"{len(ix_data)}\n".encode()
    payload += ix_data
    f.write(payload)
    f.flush()

    s.shutdown(socket.SHUT_WR)
    print(f.read().decode(errors="replace"))


if __name__ == "__main__":
    main()

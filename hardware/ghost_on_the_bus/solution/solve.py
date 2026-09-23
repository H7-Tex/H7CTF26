#!/usr/bin/env python3
# reference solve for Ghost on the Bus. parse the VCD, decode UART (the boot log
# tells you the plan), SPI (part A = flash read), and I2C (part B = EEPROM read),
# then XOR the two halves to get the provisioning key = flag. players do the same
# with PulseView + sigrok's SPI/I2C/UART decoders.
import sys, pathlib

SR = 2_000_000
DT = int(1e9 / SR)

def parse_vcd(text):
    sym2ch, trans, t = {}, None, 0
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        l = lines[i].strip()
        if l.startswith("$var"):
            p = l.split(); sym2ch[p[3]] = p[4]
        elif l == "$enddefinitions $end":
            i += 1; break
        i += 1
    trans = {ch: [] for ch in sym2ch.values()}
    while i < len(lines):
        l = lines[i].strip()
        if l.startswith("#"):
            t = int(l[1:])
        elif l and l[0] in "01":
            ch = sym2ch.get(l[1:])
            if ch is not None:
                trans[ch].append((t // DT, int(l[0])))
        i += 1
    maxs = max((tr[-1][0] for tr in trans.values() if tr), default=0) + 16
    arrs = {}
    for ch, tr in trans.items():
        a = bytearray(maxs); cur = 0; idx = 0
        for s, v in tr:
            for k in range(idx, s):
                a[k] = cur
            cur = v; idx = s
        for k in range(idx, maxs):
            a[k] = cur
        arrs[ch] = a
    return arrs

def decode_uart(bits, baud=115200):
    spb = SR // baud; out = bytearray(); i = 1; n = len(bits)
    while i < n:
        if bits[i] == 0 and bits[i - 1] == 1:
            c = i + spb // 2
            if c + 9 * spb >= n:
                break
            byte = sum((bits[c + (k + 1) * spb] & 1) << k for k in range(8))
            out.append(byte); i = c + 9 * spb
        else:
            i += 1
    return bytes(out)

def decode_spi(clk, mosi, miso, cs):
    mo, mi, bits_o, bits_i = bytearray(), bytearray(), [], []
    for i in range(1, len(clk)):
        if cs[i] == 0 and clk[i] == 1 and clk[i - 1] == 0:
            bits_o.append(mosi[i]); bits_i.append(miso[i])
    for off in range(0, len(bits_o) - 7, 8):
        mo.append(sum(bits_o[off + k] << (7 - k) for k in range(8)))
        mi.append(sum(bits_i[off + k] << (7 - k) for k in range(8)))
    return bytes(mo), bytes(mi)

def decode_i2c(sda, scl):
    n = len(sda)
    starts = [i for i in range(1, n) if scl[i] == 1 and sda[i] == 0 and sda[i - 1] == 1]
    if not starts:
        return b""
    rises = [i for i in range(starts[0], n) if scl[i] == 1 and scl[i - 1] == 0]
    bits = [sda[i] for i in rises]
    out = bytearray()
    for off in range(0, len(bits) - 8, 9):   # 8 data + 1 (n)ack
        out.append(sum(bits[off + k] << (7 - k) for k in range(8)))
    return bytes(out)

def main():
    base = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "handout")
    vcd = (base / "capture.vcd").read_text() if base.is_dir() else base.read_text()
    ch = parse_vcd(vcd)
    log = decode_uart(ch["UART_TX"])
    _, miso = decode_spi(ch["SPI_CLK"], ch["SPI_MOSI"], ch["SPI_MISO"], ch["SPI_CS"])
    i2c = decode_i2c(ch["SDA"], ch["SCL"])
    part_a = miso[4:]                 # skip the 4-byte opcode+address response window
    part_b = i2c[1:]                  # skip the addr+R byte
    m = min(len(part_a), len(part_b))
    flag = bytes(a ^ b for a, b in zip(part_a[:m], part_b[:m]))
    # trim to a clean H7CTF{...}
    s = flag.split(b"}")[0] + b"}" if b"H7CTF{" in flag else flag
    print(f"[solve] UART log lines: {log.count(chr(10).encode())}; SPI partA {len(part_a)}B, I2C partB {len(part_b)}B")
    print(f"[solve] FLAG = {s.decode(errors='replace')}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# per-instance capture generator for Ghost on the Bus. synthesizes an 8-channel
# boot capture: a UART boot log, an SPI-flash read, and an I2C-EEPROM read, all on
# one timeline. the provisioning key ($FLAG) is XOR-split across the SPI read and
# the I2C read; the UART log says how to combine them. emits VCD (PulseView imports
# it). the flag is never present in any single decode.
import os, sys, secrets, pathlib

SR = 2_000_000  # 2 MHz sample rate
CH = ["UART_TX", "SCL", "SDA", "SPI_CLK", "SPI_MOSI", "SPI_MISO", "SPI_CS", "AUX"]

class Cap:
    def __init__(self, channels):
        self.names = channels
        self.data = {c: bytearray() for c in channels}
        self.cur = {c: 1 for c in channels}
        self.cur["SPI_CLK"] = 0  # SPI mode 0 idles clock low
    def hold(self, n):
        for c in self.names:
            self.data[c].extend(bytes([self.cur[c]]) * n)
    def set(self, c, v):
        self.cur[c] = v
    def vcd(self):
        syms = {c: chr(33 + i) for i, c in enumerate(self.names)}
        out = ["$timescale 1ns $end"]
        out += [f"$var wire 1 {syms[c]} {c} $end" for c in self.names]
        out.append("$enddefinitions $end")
        n = len(self.data[self.names[0]])
        prev = {c: None for c in self.names}
        dt = int(1e9 / SR)
        for s in range(n):
            ch = [(syms[c], self.data[c][s]) for c in self.names if self.data[c][s] != prev[c]]
            if ch:
                out.append(f"#{s*dt}")
                out += [f"{v}{sym}" for sym, v in ch]
                for c in self.names:
                    prev[c] = self.data[c][s]
        return "\n".join(out) + "\n"

def uart_tx(cap, data, baud=115200):
    spb = SR // baud
    cap.set("UART_TX", 1); cap.hold(spb * 2)
    for byte in data:
        cap.set("UART_TX", 0); cap.hold(spb)
        for i in range(8):
            cap.set("UART_TX", (byte >> i) & 1); cap.hold(spb)
        cap.set("UART_TX", 1); cap.hold(spb)
    cap.hold(spb * 2)

def spi_read(cap, mosi_bytes, miso_bytes, hz=1_000_000):
    # mode 0: CPOL=0 CPHA=0, sample on rising edge, MSB first. CS active low.
    hp = max(SR // (2 * hz), 2)
    cap.set("SPI_CS", 0); cap.set("SPI_CLK", 0); cap.hold(hp)
    n = max(len(mosi_bytes), len(miso_bytes))
    mo = list(mosi_bytes) + [0] * (n - len(mosi_bytes))
    mi = list(miso_bytes) + [0] * (n - len(miso_bytes))
    for bo, bi in zip(mo, mi):
        for k in range(7, -1, -1):
            cap.set("SPI_MOSI", (bo >> k) & 1); cap.set("SPI_MISO", (bi >> k) & 1)
            cap.set("SPI_CLK", 0); cap.hold(hp)
            cap.set("SPI_CLK", 1); cap.hold(hp)   # data valid on rising edge
    cap.set("SPI_CLK", 0); cap.hold(hp)
    cap.set("SPI_CS", 1); cap.hold(hp)

def i2c_read(cap, addr7, data, hz=100_000):
    q = max(SR // (4 * hz), 2)
    def scl(v): cap.set("SCL", v)
    def sda(v): cap.set("SDA", v)
    sda(1); scl(1); cap.hold(q)
    sda(0); cap.hold(q)                                   # START
    def clock_byte(b, drive):
        for i in range(7, -1, -1):
            scl(0); cap.hold(q)
            sda((b >> i) & 1); cap.hold(q)
            scl(1); cap.hold(2 * q)
            scl(0); cap.hold(q)
        scl(0); sda(1 if not drive else 0); cap.hold(q)   # (n)ack slot
        scl(1); cap.hold(2 * q); scl(0); cap.hold(q)
    clock_byte((addr7 << 1) | 1, drive=True)              # addr + READ, slave ACK
    for j, b in enumerate(data):
        clock_byte(b, drive=(j != len(data) - 1))         # master ACK all but last (NACK)
    scl(1); cap.hold(q); sda(1); cap.hold(2 * q)          # STOP

def make_capture(flag: bytes):
    n = len(flag)
    spi_half = secrets.token_bytes(n)
    i2c_half = bytes(a ^ b for a, b in zip(spi_half, flag))   # spi ^ i2c == flag
    log = (b"\r\n[boot] NoiseGate bootloader v2.1\r\n"
           b"[prov] reading key material...\r\n"
           b"[prov]   part A <- SPI flash READ(0x03) @ 0x001A00, %d bytes\r\n"
           b"[prov]   part B <- I2C EEPROM 0x50 (read), %d bytes\r\n"
           b"[prov]   provisioning_key = part_A XOR part_B\r\n"
           b"[prov] key installed. continuing boot.\r\n" % (n, n))
    cap = Cap(CH)
    uart_tx(cap, log)
    spi_read(cap, mosi_bytes=bytes([0x03, 0x00, 0x1A, 0x00]) + bytes(n), miso_bytes=bytes(4) + spi_half)
    i2c_read(cap, 0x50, i2c_half)
    uart_tx(cap, b"[boot] done.\r\n")
    return cap.vcd()

if __name__ == "__main__":
    flag = os.environ.get("FLAG", "H7CTF{local_test_flag_ghost_on_the_bus}").encode()
    outdir = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "handout")
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "capture.vcd").write_text(make_capture(flag))
    print(f"[gen] wrote {outdir/'capture.vcd'} (8ch, UART+SPI+I2C, flag XOR-split)")

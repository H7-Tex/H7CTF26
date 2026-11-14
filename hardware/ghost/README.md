# Ghost on the Bus

**Category:** hardware  **Difficulty:** medium  **Author:** abu

> We clipped onto a NoiseGate board and let it boot while we wrote down everything the chips muttered to each other. Somewhere in that wake-up routine the device hands its provisioning key across.
>
> It never says the whole thing in one place. Ghosts are like that.

Per-team instance over HTTP that serves `capture.vcd`, an 8-channel logic capture at 2 MHz.

## Solution

Load it in PulseView. Three buses are active during boot: UART on `UART_TX`, SPI on `SPI_CLK/MOSI/MISO/CS`, and I2C on `SCL/SDA`.

Start with the UART decoder at 115200 8N1. The boot log tells you the whole plan:

```
[prov] part A <- SPI flash READ(0x03) @ 0x001A00, N bytes
[prov] part B <- I2C EEPROM 0x50 (read), N bytes
[prov] provisioning_key = part_A XOR part_B
```

SPI is mode 0, CS active low, MSB first. MOSI sends `03 00 1A 00`; the MISO bytes after those four command bytes are part A.

On I2C, after the `0x50` read address, the data bytes are part B.

XOR the two and you get the flag. Decoding any single bus only gives you random-looking half of a XOR, which is the whole point of the challenge.

```
python3 solution/solve.py <dir-with-capture.vcd>
```

The solver has its own little UART/SPI/I2C decoders so it doesn't need sigrok. Local test:

```
FLAG='H7CTF{test}' python3 challenge/gen.py /tmp/gob
python3 solution/solve.py /tmp/gob
```

Flag is dynamic, per team.

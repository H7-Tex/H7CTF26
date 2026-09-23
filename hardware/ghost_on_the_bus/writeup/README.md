# Ghost on the Bus: writeup

## The setup
A single 8-channel logic capture (`capture.vcd`, 2 MHz) of a NoiseGate device
booting. Three buses run at once:
- `UART_TX` - the boot log (115200 baud, 8N1).
- `SPI_CLK / SPI_MOSI / SPI_MISO / SPI_CS` - an SPI flash read.
- `SCL / SDA` - an I2C EEPROM read.

## Why one decoder is not enough
The provisioning key is XOR-split: half is served on the SPI flash read, half on the
I2C EEPROM read. Decoding any single bus gives you a random-looking half, never the
key. The flag exists only when you combine the two, and the way to combine them is
stated in the third bus (the UART log). A `strings`/`grep` finds nothing (the file
is binary transitions), and running one protocol decoder finds half of a XOR.

## Solve
1. **UART** (the plan). Decode `UART_TX` at 115200. The log says:
   ```
   [prov] part A <- SPI flash READ(0x03) @ 0x001A00, N bytes
   [prov] part B <- I2C EEPROM 0x50 (read), N bytes
   [prov] provisioning_key = part_A XOR part_B
   ```
2. **SPI** (part A). SPI mode 0: sample on the rising clock edge, MSB first, while
   `SPI_CS` is low. `SPI_MOSI` carries the command `03 00 1A 00` (READ + 24-bit
   address); during those 4 bytes `SPI_MISO` is idle, then it returns the response.
   The bytes after that command window are **part A**.
3. **I2C** (part B). Sample `SDA` on rising `SCL`. After the `0x50` read address
   byte, the data bytes read out of the EEPROM are **part B**.
4. **Combine.** `flag = part_A XOR part_B`.

## Notes
- The capture is synthesized in Python but is a genuine, decodable VCD: PulseView
  and sigrok's stock UART/SPI/I2C decoders read it directly (this is the "you don't
  need to own a logic analyzer" point - the bench is virtual, the skill is real).
- Anti-agent: binary transition format + three muxed protocols + a flag computed
  *across* buses. The stuck-point for an automated solver is exactly the cross-bus
  synthesis, which is the intended human insight.
- Real basis: multi-bus board-bring-up captures; XOR-split secrets across flash and
  EEPROM is a real (if naive) provisioning pattern.

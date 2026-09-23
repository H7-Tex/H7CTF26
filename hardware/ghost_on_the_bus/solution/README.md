# Ghost on the Bus: intended solution

Launch the instance, download `capture.vcd`, then:
```
python3 solution/solve.py <dir-with-capture.vcd>
```
Parses the VCD, decodes all three buses, XORs the two halves, prints the flag.
Players do the same in PulseView with sigrok's UART/SPI/I2C decoders.

## Path
1. Open `capture.vcd` in PulseView (2 MHz). Eight channels; three buses are active.
2. **UART_TX**: add the UART decoder, find the baud (115200). The boot log spells
   out the plan: part A from an SPI flash `READ(0x03) @ 0x001A00`, part B from an
   I2C EEPROM `0x50` read, and `provisioning_key = part_A XOR part_B`.
3. **SPI** (`SPI_CLK/MOSI/MISO/CS`): add the SPI decoder, mode 0 (CPOL=0, CPHA=0),
   CS active-low, MSB-first. MOSI shows the `03 00 1A 00` read command; `SPI_MISO`
   returns the response - the bytes after the 4-byte command window are **part A**.
4. **I2C** (`SCL/SDA`): add the I2C decoder. After the `0x50` read address, the data
   bytes are **part B**.
5. XOR part A with part B -> the provisioning key = the flag. Submit it.

The point: no single decoder reveals the key; it only appears when you combine the
SPI and I2C reads the way the UART log describes.

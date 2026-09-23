# Ghost on the Bus

`hardware` / `medium` / on-demand per-team instance (docker, HTTP), dynamic flag.

An 8-channel logic capture of a device boot with three buses active at once (UART
boot log + SPI flash read + I2C EEPROM read). The provisioning key is XOR-split:
half comes back on the SPI flash READ (`SPI_MISO`), half on the I2C EEPROM read
(`SDA`), and the UART log states `provisioning_key = part_A XOR part_B`. The flag
is in *no single decode* - you must decode all three buses and combine across them.
Answers "we don't own a logic analyzer": the capture is synthesized, but
sample-indistinguishable from a real one and decodes in real sigrok/PulseView.

## Delivery
Per-team live instance. On launch the container generates a fresh capture with
`$FLAG` XOR-split across the SPI and I2C reads, and serves `capture.vcd` over HTTP.
Download it, solve offline, submit the recovered key.

## Files
- `challenge.yml` : definition (dynamic flag, on-demand docker, http:8080).
- `challenge/gen.py` : the capture synthesizer (Cap + UART/SPI/I2C emitters + VCD; XOR-splits `$FLAG`).
- `challenge/serve.py` : instance entrypoint (generate + serve `capture.vcd`).
- `challenge/Dockerfile` : the instance image (`h7ctf26/ghost-on-the-bus`). stdlib only.
- `solution/solve.py` : reference solver (parse VCD, decode UART/SPI/I2C, XOR).
- `writeup/README.md` : full explanation.

## Local test (no Docker needed)
```
FLAG='H7CTF{test}' python3 challenge/gen.py /tmp/gob     # writes /tmp/gob/capture.vcd
python3 solution/solve.py /tmp/gob                       # -> recovers the flag
```
Validated 5/5 across random flags. Players use PulseView + sigrok's UART/SPI/I2C
protocol decoders; the reference solver ships its own decoders so it needs no
system tools. (The Dockerfile can also emit `.sr` via sigrok-cli at Cloud Build if
we want a native sigrok session file alongside the VCD.)

## Fairness / anti-agent notes
- Per-team dynamic flag; per-team capture with a fresh XOR split.
- Binary transition format (VCD), not text: `strings`/`grep` yield nothing.
- Three muxed protocols: running one decoder is not enough; you need UART (find the
  baud + read the plan), SPI (infer mode 0, read `SPI_MISO`), and I2C (read `SDA`).
- The flag is computed *across* buses (XOR), so it exists in no single decode - the
  key anti-agent property.
- Real, teachable skill: driving a logic analyzer and its protocol decoders.

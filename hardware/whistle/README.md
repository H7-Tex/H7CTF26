# Dog Whistle

**Category:** hardware  **Difficulty:** insane  **Author:** abu

> Aria takes orders it can hear, and the equalizer is the only guard the vendor left you. Lately it keeps obeying instructions nobody in the room ever gave.
>
> Get it to give up the flag it keeps in firmware.

Handout: `handout/dog_whistle.zip` (the `aria` binary, `SPEC.md`, `eq.cfg`, `reference_ping.wav`). Per-team TCP instance, one `aria` process per connection.

## Solution

`aria` is a fake smart speaker. You send it a base64 WAV (24-bit, 96 kHz, mono) and it runs it through an EQ, a safety interlock, an analog front end model (gain, then `y = 0.98x + 0.05x^2 + 0.005x^3`, a 7 kHz low-pass, decimate to 16 kHz), a 16-tone MFSK demodulator and finally a TLV command parser.

The obvious move after reading the modem spec is to play the engineering frame as audible tones. That gets you `SAFETY LOCKOUT` every time. The interlock runs a Goertzel scan over 300-3400 Hz on the audio as captured, before the front end, so anything that already exists as audible tones gets caught.

The trick is the `0.05x^2` term. A square-law stage is a mixer: feed it two tones and you get their difference frequency out. So we put both tones up in the 18-22 kHz pairing band, where the interlock never looks, and pick the spacing so `f2 - f1` lands on the MFSK tone we want. The 7 kHz low-pass keeps the difference and throws away the originals and the sum. The demodulator then reads a frame that was never audible. We fix `f1 = 19000` and set `f2 = 19000 + tone(nibble)` per symbol.

Now the memory bug. The binary is PIE with full RELRO, so we need a leak first.

- `SELECT_PROFILE(0x0E)` binds the factory calibration region and echoes its first 16 bytes as `CAL ECHO`. The first 8 bytes are the runtime address of `factory_diag`.
- `SET_CAL_VECTOR` does `memcpy(region->data, values, count*2)` into a 32-byte region. `count` is only checked against the frame length, never the region size, and the region sits right below the DSP `effect_chain`, whose `process` pointer gets called at the end of every capture.

The two facts live in different opcodes, so the memcpy looks bounded if you only read one of them.

Full chain, in one connection (ASLR changes per process):

1. Ultrasonic capture carrying `SELECT_PROFILE(0x0E)`, read `CAL ECHO`, take the first 8 bytes little-endian.
2. Ultrasonic capture carrying `SET_CAL_VECTOR` with count 28: 48 filler bytes, then the leaked address.
3. The end-of-capture call is now `factory_diag`, which prints `$FLAG`.

```
python3 solution/solve.py <host> <port>
```

The solver only needs numpy. To run it locally:

```
make -C challenge OUT=/tmp/aria
cd /tmp && FLAG='H7CTF{test}' socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/tmp/aria
python3 solution/solve.py 127.0.0.1 9999
```

Flag is dynamic, per team.

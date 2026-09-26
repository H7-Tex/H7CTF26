# Dog Whistle - intended solve

Category: hardware (DSP + binary exploitation). Difficulty: insane.

## What the box is

`aria` is a modeled smart-speaker firmware served one process per TCP
connection. It ingests a base64 24-bit/96 kHz mono WAV and runs a fixed
pipeline:

1. 8-band parametric EQ (from `eq.cfg`, flat on the quals instance).
2. Safety interlock: a Goertzel scan of the audible control band (300 to 3400
   Hz) of the captured audio. If it decodes a frame carrying an engineering
   opcode (`SELECT_PROFILE` or `SET_CAL_VECTOR`) it quarantines the capture.
3. Analog front end: gain g = 4.0, then the transducer polynomial
   `y = 0.98*x + 0.05*x^2 + 0.005*x^3`, then a 6th-order Butterworth low-pass at
   7 kHz, then decimation 96k -> 16k.
4. A 16-tone MFSK demodulator over the codec band recovers a control frame.
5. A TLV codec services the frame.

## The trap

The obvious move after reversing the modem is to encode the engineering frame as
audible MFSK tones (800 to 2000 Hz) and play it. Step 2 sees that energy in the
captured audio and returns `SAFETY LOCKOUT`. The interlock runs on the audio as
captured, before the analog front end, so any command that already exists as
audible tones is caught. Brute forcing tone combinations never gets past it.

## The signal insight

The interlock only inspects the captured audio. The `0.05*x^2` term of the
transducer polynomial is a square-law mixer: drive it with two near-ultrasonic
tones

```
s(t) = A*cos(2*pi*f1*t) + A*cos(2*pi*f2*t)
```

and the square term produces a component at the difference frequency `f2 - f1`
that did not exist in the captured audio. Put both tones in the 18 to 22 kHz
pairing band (so the interlock's 300 to 3400 Hz scan sees nothing) and choose
the spacing so `f2 - f1` lands exactly on a codec MFSK tone. The 7 kHz anti-alias
keeps the difference and kills the originals and the sum, decimation follows, and
the demodulator reads the engineering frame that was never audible.

The solver fixes `f1 = 19000` and sets `f2 = 19000 + tone(nibble)` per symbol,
sweeping the spacing to clock out the frame. Because the intended tones are exact
Goertzel bins, an argmax receiver decodes with enormous margin regardless of the
EQ scaling.

## The memory bug

`aria` is PIE with full RELRO, so nothing is at a fixed address.

- `SELECT_PROFILE(0x0E)` binds the factory calibration region and echoes its
  first 16 bytes as `CAL ECHO`. The region carries a stamped internal handler
  address: the first 8 bytes are the runtime address of `factory_diag`. This is
  the leak that defeats ASLR and it must be read live, per connection.
- `SET_CAL_VECTOR` copies `count` int16 samples into the 32-byte region with
  `memcpy(region->data, values, count*2)`. `count` is checked against the frame
  payload length only, never against the region size. The region sits directly
  below the DSP `effect_chain` object, so the copy overflows into
  `effect_chain->process`, the function pointer the pipeline calls at the end of
  every capture.

Writing 48 filler bytes then the 8-byte leaked address redirects `process` to
`factory_diag`, which reads `$FLAG` and prints it. The two facts (region size and
copy length) live in different opcodes, so a single-frame static read of the
memcpy looks bounded and unreachable.

## Full chain

1. Send an ultrasonic two-tone capture carrying `SELECT_PROFILE(0x0E)`. Read the
   `CAL ECHO`, take the first 8 bytes little-endian as `factory_diag`.
2. Send an ultrasonic two-tone capture carrying `SET_CAL_VECTOR` with count = 28:
   48 filler bytes followed by the leaked address.
3. The end-of-capture effect call is now `factory_diag`, which prints the flag.

Both captures happen in one connection because ASLR re-randomizes every process,
so a hardcoded address from a previous run fails. See `solution/solve.py`.

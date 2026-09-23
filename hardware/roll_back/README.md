# Roll Back

`hardware` / `hard` / on-demand per-team instance (docker, HTTP), dynamic flag.

A cheap 433 MHz "rolling code" garage remote whose rolling code does not actually roll
safely. Eight button presses are delivered as raw complex baseband (`capture.cf32`,
interleaved float32 I/Q, fs = 1 MHz, on-off keyed). The player demodulates the OOK
envelope, decodes the PWM bit encoding, parses the frame (serial + counter + button +
checksum), sees the counter increment predictably, and predicts the next code. Sending
that predicted code to the live receiver (`POST /unlock`) opens the door and returns
the flag. A straight replay of a captured press is rejected.

## Delivery
Per-team live instance. On launch the container derives a per-team device (serial,
counter base, step, button) from `$FLAG`, synthesizes the 8-press OOK capture, serves
`capture.cf32`, and runs the receiver. The flag is never in the handout: it is returned
by `POST /unlock` only when the submitted code is the correct next code.

## Files
- `challenge.yml` : definition (dynamic flag, on-demand docker, http:8080).
- `challenge/proto.py` : shared frame format (pack/unpack + checksum), device derivation, receiver validation.
- `challenge/gen.py` : the capture synthesizer (OOK + PWM bit encoding + AWGN).
- `challenge/serve.py` : instance entrypoint (serve `capture.cf32` + `POST /unlock`).
- `challenge/Dockerfile` : the instance image (`h7ctf26/roll-back`, numpy only).
- `solution/solve.py` : reference solver (envelope demod, PWM decode, frame parse, predict, unlock).
- `writeup/README.md` : full explanation.

## Local test (no Docker needed)
```
FLAG='H7CTF{test}' python3 challenge/gen.py /tmp/rb      # writes /tmp/rb/capture.cf32
python3 solution/solve.py /tmp/rb                        # demods 8 frames, predicts next code
python3 solution/solve.py /tmp/rb http://host:port       # also POSTs /unlock -> flag
```
Validated 30/30 across random devices (all 8 frames recovered, predicted code accepted
by the receiver). The reference solver ships its own DSP so it needs no SDR toolchain.

## The signal (spoiler)
OOK on a +50 kHz carrier, PWM bits at 1 kBaud (bit period 1000 samples at 1 MHz):
short-high = 0, long-high = 1. Each frame is 48 bits = serial(24) | counter(16) |
button(4) | checksum(4, nibble sum), followed by a sync high and a long low inter-frame
gap. The counter increments by a fixed step (1/3/5/7) each press. The receiver accepts
any unseen counter in a forward window with a matching serial/button and valid checksum.

## Fairness / anti-agent notes
- Per-team dynamic flag; per-team device and capture.
- The flag is not in the handout at all; it is behind a correct prediction, so it
  cannot be `strings`ed, and a captured code cannot be replayed.
- Recovering the code requires real RF work (OOK envelope, PWM timing, frame parse) and
  then understanding the counter scheme + checksum to forge a valid next frame. Both the
  serial (24-bit) and the checksum must be right, so brute-forcing `/unlock` without
  demodulating is infeasible.
- Real basis: cheap 433 MHz remotes with weak/predictable rolling codes, and the
  capture/predict style of the RollJam class of attacks.

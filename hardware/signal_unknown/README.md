# Signal, Unknown

`hardware` / `medium` / on-demand per-team instance (docker, HTTP), dynamic flag.

One RF burst captured off the air from an unidentified device, delivered as raw
complex baseband (`capture.cf32`, interleaved float32 I/Q, fs = 1 MHz). No datasheet,
no stated modulation. The player has to recognize the modulation (2-FSK), find the
burst in the noise, measure the symbol rate, lock onto the preamble/sync word, and
demodulate to bytes. The flag is the transmitted payload.

## Delivery
Per-team live instance. On launch the container synthesizes a fresh capture with
`$FLAG` framed into the payload (preamble + sync + length + flag + CRC-16, 2-FSK) and
serves `capture.cf32` over HTTP. Download it, demodulate offline, submit the payload.

## Files
- `challenge.yml` : definition (dynamic flag, on-demand docker, http:8080).
- `challenge/gen.py` : the capture synthesizer (CPFSK modulator + framing + AWGN).
- `challenge/serve.py` : instance entrypoint (generate + serve `capture.cf32`).
- `challenge/Dockerfile` : the instance image (`h7ctf26/signal-unknown`, numpy only).
- `solution/solve.py` : reference demodulator (burst detect, FSK discriminator, symbol
  sync, sync-word search, CRC check).
- `writeup/README.md` : full explanation.

## Local test (no Docker needed)
```
FLAG='H7CTF{test}' python3 challenge/gen.py /tmp/su      # writes /tmp/su/capture.cf32
python3 solution/solve.py /tmp/su                        # -> recovers the flag
```
Validated 20/20 across random flags, plus 8-char and 87-char payloads. Players use
inspectrum / URH / GNU Radio; the reference solver ships its own DSP so it needs no
SDR toolchain.

## The signal (spoiler)
2-FSK, continuous-phase. Tuned +60 kHz off DC (SDR tune offset to dodge the DC spike),
deviation +/-25 kHz, 10 kBaud (100 samples/symbol at 1 MHz). Frame: 6-byte `0xAA`
preamble, `0x2DD4` sync word, one length byte, the flag, CRC-16/CCITT. ~19 dB SNR.

## Fairness / anti-agent notes
- Per-team dynamic flag; per-team capture (fresh noise + framing each launch).
- Binary IQ, not text: `strings`/`grep` yield nothing.
- No metadata: modulation, symbol rate, deviation, sync word are all unstated; the
  player measures them from the signal (spectrum shows two tones -> 2-FSK; transition
  spacing -> symbol rate). That measure-from-signal step is the anti-agent moat: a
  blind universal demodulator does not just fall out.
- CRC-16 gates a correct demod, so a near-miss decode is self-evidently wrong.

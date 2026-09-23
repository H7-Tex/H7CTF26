# Signal, Unknown: writeup

## The setup
A single RF burst, captured as raw complex baseband (`capture.cf32`: interleaved
float32 I/Q, fs = 1 MHz). No datasheet, no protocol, no stated modulation. This mirrors
the real first hour of reversing an unknown ISM-band device: you have a `.cf32` off an
rtl-sdr or HackRF and nothing else, and you work out the protocol from the samples.

## Why `strings` fails, and why a blind demod fails
The file is float32 IQ, so there is no text to grep. And because none of the modulation
parameters are given (modulation type, symbol rate, deviation, center offset, sync
word), you cannot point a one-shot universal demodulator at it and get bytes. You have
to measure each parameter from the signal. That measuring step is the challenge.

## Solve
1. **Find the burst.** Smooth `|x|`; the burst is where the magnitude rises above the
   noise floor. Everything outside it is idle noise.
2. **Identify the modulation.** The spectrogram (inspectrum / URH) shows the burst
   alternating between two discrete tones. Two tones = 2-FSK. They sit near +35 kHz and
   +85 kHz, i.e. centered +60 kHz off DC (a normal SDR tune offset to avoid the DC
   spike).
3. **Discriminate to bits-per-sample.** Instantaneous frequency is
   `f[n] = angle(x[n] * conj(x[n-1])) * fs / (2*pi)`. The raw estimate is noisy, so
   low-pass it before thresholding at the midpoint between the two tone clusters.
4. **Recover the symbol rate.** The `0xAA` preamble alternates every symbol, so
   transition spacing is the symbol period (~100 samples -> 10 kBaud at 1 MHz). Fit it
   as a least-count average over all transition runs (each run is an integer number of
   symbols); a crude modal estimate drifts across the ~300-symbol burst and corrupts
   the tail.
5. **Frame sync.** Sample at symbol centers and slide the sampling phase until the
   `0x2DD4` sync word appears in the bitstream. That fixes byte alignment.
6. **Parse the frame.** After the sync: one length byte, then that many payload bytes,
   then CRC-16/CCITT. The CRC confirms a clean demod; the payload is the flag.

## Notes
- The capture is synthesized in numpy but is a genuine CPFSK signal with real AWGN
  (~19 dB SNR): it opens and demodulates in inspectrum, URH and GNU Radio exactly like
  a real capture. This is the "you don't need to own an SDR" point: the bench is
  virtual, the DSP skill is real.
- Anti-agent: no metadata + measure-from-signal + a CRC that rejects near-misses. The
  human insight is reading the two-tone structure off the spectrogram and turning it
  into demod parameters.
- Real basis: this is the standard URH / rtl_433 workflow for an unknown ISM device.

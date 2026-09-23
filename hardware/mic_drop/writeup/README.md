# Mic Drop: writeup

## The setup
A compromised smart conference-room AV device serves its live room audio as an HLS stream
(`/boardroom/index.m3u8`). The room feed sounds normal, but the implant is exfiltrating
data inside that same audio: a faint voice-band AFSK (modem) burst mixed under the
ambience. This mirrors real IoT/AV compromises where a device leaks over its own legitimate
media channel, and voice-band modems (fax, APRS, Bell 202) that are built to survive lossy
audio paths.

## Why `strings` / a file grep fails
There is no file with the flag in it. The flag is a modulated audio waveform, and it is
inside a lossy AAC/HLS stream. You have to pull the live stream, reconstruct the audio, and
treat it as a signal to demodulate. A voice-band modem is precisely what survives the lossy
codec, so the data is intact, but only recoverable through demodulation.

## Solve
1. **Pull the stream.** `ffmpeg -i http://<base>/boardroom/index.m3u8 -t 14 out.wav`, or
   open it in VLC/mpv, or fetch and concatenate the `.ts` segments. Grab ~10-15 s to get a
   full loop of the burst.
2. **Recognize the signal.** Under the room ambience the audio pulses between two fixed
   tones: an FSK signal in the voice band. A spectrogram shows the two tones clearly.
3. **Demodulate AFSK.** Parameters: mark 1200 Hz, space 2200 Hz, 300 baud, 8N1, LSB-first,
   with a mark-tone preamble. Per bit period, compare energy at 1200 vs 2200 Hz (Goertzel),
   recover the bits, and frame them into bytes. `minimodem -r 300 --mark 1200 --space 2200`
   does it out of the box; the reference solver ships its own Goertzel demodulator.
4. The decoded byte stream contains `H7CTF{...}`.

## Notes
- The audio is synthesized but is a genuine AFSK modem signal; it decodes in `minimodem`
  and in any standard FSK demod. This is the "you don't need the bugged device" point: the
  capture is virtual, the signal skill is real.
- Robustness: AFSK is voice-band by design, so it survives AAC 128k (validated 12/12 random
  flags through the codec, and end to end through the live HLS pipeline).
- Anti-agent: reconstructing a live streaming protocol and demodulating a modem out of the
  room audio is the human insight; a byte grep yields nothing.
- Weight: the stream is generated once at boot and looped (no live transcode), so the
  instance sits at ~4% CPU / ~30 MiB.

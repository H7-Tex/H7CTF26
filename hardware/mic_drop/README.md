# Mic Drop

`hardware` / `hard` / on-demand per-team instance (docker, HLS over HTTP), dynamic flag.

A compromised smart conference-room AV device streams its live room audio as HLS. The
implant hides an exfil channel *inside* that audio: a faint voice-band AFSK (modem) burst
mixed under the room ambience, carrying the flag. The player pulls the live HLS stream,
extracts the audio, notices the modem warble, and demodulates it (a voice-band 300-baud
AFSK, mark 1200 Hz / space 2200 Hz, 8N1) to recover the flag. Because it is a real
voice-band modem, it survives the lossy AAC/HLS codec intact.

## Delivery
Per-team live instance. On launch the container generates the room audio with `$FLAG`
encoded as the AFSK burst. The container pre-segments the audio once into a STATIC VOD HLS
stream at `/boardroom/index.m3u8` (served by a small threaded static HTTP server; no live
RTSP). Pull the stream, demodulate the audio offline, submit the flag.

## Files
- `challenge.yml` : definition (dynamic flag, on-demand docker, http:8080).
- `challenge/gen.py` : the audio synthesizer (room ambience + AFSK-encoded `$FLAG`).
- `challenge/serve.py` : threaded static HTTP server for the pre-segmented HLS.
- `challenge/entrypoint.sh` : generate audio, then run MediaMTX.
- `challenge/Dockerfile` : the instance image (`h7ctf26/mic-drop`, ffmpeg + MediaMTX + numpy).
- `solution/solve.py` : reference solver (pull HLS via ffmpeg, Goertzel AFSK demod).
- `writeup/README.md` : full explanation.

## Local test
```
python3 solution/solve.py http://<instance>/boardroom/index.m3u8   # pull live HLS -> flag
# or offline, without a stream:
FLAG='H7CTF{x}' python3 challenge/gen.py /tmp/md && python3 solution/solve.py /tmp/md/boardroom.wav
```
Validated end to end in the actual container: HLS ready ~3s, the reference solver pulls
the live stream and decodes the exact flag; steady-state ~4% CPU / ~30 MiB (the stream is
pre-generated once at boot and looped, so it is near-static weight). AFSK survives AAC
128k byte-exact (12/12 random flags through the codec).

## Deploy notes
- The image `apt install`s ffmpeg only (no MediaMTX/binary download). No GPU, no runtime
  external calls, no live RTSP. (v0.0.108: switched from live MediaMTX RTSP->HLS to static
  pre-segmented HLS - the live RTSP publish stalled intermittently under gVisor/CPU load.)
- Player-facing endpoint is HLS over HTTP (`/boardroom/index.m3u8`) so it rides the normal
  Traefik web path; no raw-TCP/RTSP transport is exposed publicly.

## Fairness / anti-agent notes
- Per-team dynamic flag; fresh audio each launch.
- Not `strings`-recoverable: the flag is a modulated audio waveform inside a lossy stream,
  not text anywhere.
- Requires real skill: pull and reconstruct a live HLS stream, recognize a modem signal in
  audio, and demodulate AFSK. A naive "download the file and grep" finds nothing; you have
  to treat it as a signal.
- Real basis: compromised IoT/AV devices exfiltrating over their own media channels, and
  voice-band data modems (fax/APRS/Bell 202) that survive lossy audio.

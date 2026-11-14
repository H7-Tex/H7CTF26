# Hear No Evil

**Category:** hardware  **Difficulty:** medium  **Author:** abu

> A pair of NoiseGate earbuds wakes up and starts gossiping with its phone app, and they are not the only ones chattering on the air. You were listening to all of it.
>
> Two things in that noise were meant to stay private. Take both.

Per-team instance over HTTP that serves `capture.pcap`, a BLE link-layer capture (linktype 251). Two dynamic flags, v1 and v2, with partial credit.

## Solution

Open it in Wireshark. A few things are advertising (Mi Band, JBL, Galaxy), so filter for ours:

```
btcommon.eir_ad.entry.device_name == "NoiseGate Buds"
```

The NoiseGate advert has manufacturer-specific data under company `0x0f39`: one type byte, then a 16-byte provisioning key. Hang on to that.

There's also a debug characteristic at handle `0x0041` that the devs left in. It spells out both schemes, so there's no guessing involved.

v1: after the connection, the config characteristic at `0x0021` is read over a Read Response and a few Read Blob Responses. Glue the values together in order and XOR with the provisioning key (repeated). That's flag v1.

v2: the earbuds notify a 16-byte nonce on `0x0031`, the app writes its auth response to `0x0032`, then the earbuds notify the vault on `0x0033`. The keystream is

```
sha256(provkey || nonce || byte(i))  for i = 0, 1, ...
```

concatenated to length. XOR it with the vault and you have v2.

The notifications on `0x0050` and `0x0051` are just noise.

```
python3 solution/solve.py <dir-with-capture.pcap>
```

Local test (needs scapy):

```
FLAG_V1='H7CTF{a}' FLAG_V2='H7CTF{b}' python3 challenge/gen.py /tmp/ng
python3 solution/solve.py /tmp/ng
```

Both flags are dynamic, per team.

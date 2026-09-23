# NoiseGate Earbuds

`hardware` / `medium` / on-demand per-team instance (docker, HTTP), two dynamic flags.

A BLE sniff of a pair of NoiseGate wireless earbuds and their companion app, delivered
as a standard BLE link-layer pcap (`capture.pcap`, linktype 251, opens in Wireshark).
The air has several advertisers (decoys); the player finds the earbuds, then recovers
two secrets:

- **v1 (leak, 200):** the earbuds' advertisement carries a 16-byte provisioning key in
  its manufacturer-specific data. A config characteristic (handle 0x0021) is read over
  several ATT read/blob responses; the reassembled value XOR the provisioning key is
  flag v1.
- **v2 (unlock, 300):** the earbuds notify a 16-byte nonce (handle 0x0031); the app
  authenticates (write to 0x0032); the earbuds then notify the encrypted "vault"
  (handle 0x0033). The keystream is `sha256(provkey || nonce || byte(i))` concatenated;
  ciphertext XOR keystream is flag v2. A debug characteristic (handle 0x0041) documents
  both schemes (developers left it in), so nothing has to be guessed.

## Delivery
Per-team live instance. On launch the container synthesizes a fresh capture with a
random provisioning key and nonce, framing `$FLAG_V1` and `$FLAG_V2` in as described,
and serves `capture.pcap` over HTTP. Named dynamic flags give partial credit.

## Files
- `challenge.yml` : definition (two named dynamic flags, on-demand docker, http:8080).
- `challenge/gen.py` : the capture synthesizer (advertising + GATT reads + auth + notifications, via scapy BTLE/ATT).
- `challenge/serve.py` : instance entrypoint (generate + serve `capture.pcap`).
- `challenge/Dockerfile` : the instance image (`h7ctf26/noisegate-earbuds`, scapy only).
- `solution/solve.py` : reference solver (parse the pcap, extract adv key, reassemble reads, decrypt both flags).
- `writeup/README.md` : full explanation.

## Local test (no Docker needed)
```
FLAG_V1='H7CTF{a}' FLAG_V2='H7CTF{b}' python3 challenge/gen.py /tmp/ng   # writes /tmp/ng/capture.pcap
python3 solution/solve.py /tmp/ng                                        # -> recovers both flags
```
Validated 20/20 across random flag pairs; the flags never appear in `strings` of the
pcap. Players use Wireshark's native btle/btatt dissectors (or scapy/pyshark); the
reference solver uses scapy.

## Fairness / anti-agent notes
- Two named dynamic flags, per-team, with partial credit; a fresh key/nonce each launch.
- Neither flag is `strings`-recoverable: v1 is XORed with the advertised key, v2 is
  XORed with a nonce-derived keystream.
- Requires real BLE-pcap dissection: pick the earbuds out of several advertisers, read
  the manufacturer data, reassemble a characteristic across multiple ATT read/blob
  responses (ignoring decoy notifications on other handles), and follow the
  nonce/auth/vault sequence. The debug characteristic keeps the crypto glue fair
  (documented, not guessed) so the work is the protocol dissection.
- Real basis: sniffing a BLE IoT device and its app, weak in-house "provisioning" and
  app-layer auth over GATT.

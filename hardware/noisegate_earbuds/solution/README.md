# NoiseGate Earbuds: intended solution

Launch the instance, download `capture.pcap`, then:
```
python3 solution/solve.py <dir-with-capture.pcap>
```
Parses the BLE capture, extracts the advertised key, reassembles the config read,
follows the auth exchange, and prints both flags.

## Path (what a player does)
1. Open `capture.pcap` in Wireshark. It is a BLE link-layer capture (btle). Several
   devices advertise; filter for the earbuds by name (`btcommon.eir_ad.entry.device_name
   == "NoiseGate Buds"`).
2. **v1 (leak).** The NoiseGate advertisement has manufacturer-specific data (company
   0x0f39): a type byte then a 16-byte provisioning key. After the connection, the
   config characteristic (handle 0x0021) is read across an ATT Read Response plus Read
   Blob Responses; reassemble those value bytes in order. Plaintext = value XOR provkey
   (provkey repeated). That is flag v1. (The debug characteristic at handle 0x0041 spells
   this out.)
3. **v2 (unlock).** The earbuds send a Handle Value Notification on handle 0x0031 (the
   16-byte nonce). The app writes to 0x0032 (the auth response). The earbuds then notify
   the vault on handle 0x0033 (ciphertext). Build the keystream
   `ks = sha256(provkey || nonce || byte(i))` for i = 0,1,.. concatenated to the needed
   length; plaintext = ciphertext XOR ks. That is flag v2.
4. Ignore the decoy notifications on handles 0x0050 / 0x0051 and the other advertisers.

## Why it is fair and not guessy
The debug characteristic (0x0041) documents both obfuscations, mirroring the diagnostic
strings real firmware/apps leave behind, so the crypto is glue, not a guessing game. The
actual work is dissecting the BLE capture correctly: identifying the right device and
handles among decoys, reassembling a multi-part read, and matching the nonce/auth/vault
sequence.

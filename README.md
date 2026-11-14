`H7CTF 2026`

- **ai**
  - [Argus](ai/argus), [Model Package Autopsy](ai/autopsy), [Adapter Cartel](ai/cartel), [Echo Chamber](ai/echo)
  - `ai/qwen` is just the script that ran the model backend
- **blockchain**
  - [Fee Swap](blockchain/feeswap), [Fool's Gold](blockchain/foolsgold), [Genesis](blockchain/genesis), [Perp Guard](blockchain/perpguard), [Hostile Takeover](blockchain/takeover), [Tidepool](blockchain/tidepool), [Trompe-l'œil](blockchain/trompeloeil)
  - `blockchain/harness` is the shared per-team anvil image
- **boot2root**
  - [Freightpipe](boot2root/freightpipe), [Rat Race](boot2root/ratrace)
- **cloud**
  - [Deputy](cloud/deputy), [Sealed](cloud/sealed)
- **crypto**
  - [Loose Lips](crypto/decryptostat), [The Ledger Never Sleeps](crypto/ledger), [Polynonce](crypto/polynonce), [Take Two](crypto/rollback), [Shared Blood](crypto/sharedblood), [Broken Telephone](crypto/telephone), [Vouchsafe](crypto/vouchsafe), [Owner's Draw](crypto/webhook)
- **devsecops**
  - [Trustfall CI](devsecops/trustfall) `Owatron`
- **forensics**
  - [Deep Freeze](forensics/deepfreeze), [Gone Not Forgotten](forensics/forgotten), [Frozen Assets](forensics/frozen), [Low and Slow](forensics/lowandslow), [The Patient Is Still Breathing](forensics/patient), [Ghost in the Timeline](forensics/timeline)
- **hardware**
  - [Afterglow](hardware/afterglow), [Ghost on the Bus](hardware/ghost), [GridWatch](hardware/gridwatch), [Hear No Evil](hardware/hearnoevil), [Kick the CAN](hardware/kickcan), [Mic Drop](hardware/micdrop), [Open Sesame](hardware/sesame), [Radio Silence](hardware/silence), [Trace Amounts](hardware/trace), [Dog Whistle](hardware/whistle)
- **misc**
  - [Assembly Line](misc/assembly), [Time Capsule](misc/capsule), [Overexposed](misc/overexposed), [Out of the Box](misc/sandboxed), [Tapeout](misc/tapeout), [The Ledger Opens](misc/welcome)
- **mobile**
  - [Help Yourself](mobile/deskline), [Signed, Sealed, Delivered](mobile/fleetlink), [Meridian Pay](mobile/meridian), [Onyx Locker](mobile/onyx)
- **osint**
  - [Public Domain](osint/publicdomain)
- **pwn**
  - [The Ladder (Aegis Gateway)](pwn/aegis) `graded`, [Papers Please](pwn/checkpoint), [Parcel Bomb](pwn/dispatch), [Frame of Reference](pwn/frame), [Hothouse](pwn/hothouse), [Keepalive](pwn/keepalive), [Loose Ends](pwn/ledger), [Manifest Destiny](pwn/manifest), [Sounding Line](pwn/sounding), [Safe Space](pwn/vault)
- **rev**
  - [Constraint Yourself](rev/cipherlock), [Countersign](rev/countersign), [Rust in Peace](rev/ferric), [Lockstep](rev/interlock), [Kintsugi](rev/kintsugi), [Twenty Questions](rev/questions), [Toll Story](rev/tollgate), [Modem Operandi](rev/warden)
- **web**
  - [Formwork](web/formwork), [Schrödinger Package](web/schrodinger), [Zombie Worker](web/zombie)

each challenge is `<category>/<slug>/`

remote ones have a `Dockerfile` or `docker-compose.yml` at the top, so spinning one up is just

```
cd web/formwork && docker build -t formwork . && docker run --rm -p 8080:8080 formwork
```

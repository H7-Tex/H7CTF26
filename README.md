# H7CTF'26 — Challenge Repository

Source for the H7CTF'26 qualifier challenges. Private during development; public after the event, so anyone can clone, rebuild, and learn from every challenge locally.

## Layout

Category-first. Each challenge is a directory `<category>/<name>/`:

```
<category>/<name>/
├── challenge.yml     metadata + deploy contract (see CONTRIBUTING.md)
├── README.md         public card: title, author, difficulty, description
├── challenge/        source + real flag (flag stays private until release)
├── handout/          what players download — never the real flag
├── solution/         reference solve (recovers the flag on a fresh instance)
└── writeup/          intended-solution writeup + screenshots
```

Categories: `crypto` `pwn` `web` `rev` `forensics` `misc` `osint` `blockchain` `hardware` `mobile` `cloud`.

## Standard

Every challenge ships a **working reference solve** and a **writeup** — no exceptions. See [CONTRIBUTING.md](CONTRIBUTING.md) for the `challenge.yml` schema, the flag/secrets rule, and the ship checklist. Metadata maps 1:1 to the Anvil platform importer.

## Index

Filled per category as challenges land.

## License

Code under [AGPL-3.0](LICENSE); writeups, descriptions, and assets under [CC BY-SA 4.0](LICENSE-CONTENT.md).

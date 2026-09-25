# Time Capsule - writeup

Git forensics. The lesson: `git add` writes the file's blob into `.git/objects` immediately, before
any commit. Unstaging (`git rm --cached`) or deleting the file removes it from the index and working
tree but **not** from the object store - the blob just becomes *dangling* (unreferenced). It stays
there until a `git gc` prunes it, which may never happen.

## Recon
`git log` / `git log -p --all` is clean - the credentials were never committed. `git reflog` is
empty too (the repo shipped without `.git/logs`). A naive "grep the history" turns up nothing. That's
the whole point: you have to look below the commit graph, at the raw objects.

## Recover
`git fsck` audits the object database and reports objects nothing points to:

```
$ git fsck --lost-found
dangling blob 698e3c6c553b697a80b4b44d7c29f1f345ceea21
dangling blob b5d4d544da9fb0f6a38caccf6c2d2aacb7ec9def
```

Dump each one:

```
$ git cat-file -p b5d4d544da9fb0f6a38caccf6c2d2aacb7ec9def
# production carrier credentials - DO NOT COMMIT
CARRIER_API_TOKEN=H7CTF{d4ngl1ng_bl0b_n3v3r_c0mm1tt3d}
CARRIER_API_SECRET=...
```

There are two dangling blobs: the real production secrets file (the one that also carries the API
secret) and a decoy "rotated" token. Read them, don't just submit the first `H7CTF{...}` you see.

`H7CTF{d4ngl1ng_bl0b_n3v3r_c0mm1tt3d}`

(`git fsck --lost-found` also writes the blobs to `.git/lost-found/other/<hash>` if you'd rather
open them as files.) `solution/solve.sh` walks it.

## Build
`FLAG=... bash challenge/build_repo.sh <outdir>` then zip the output dir (including `.git`) into
`time-capsule.zip`. The script stages the secret, unstages it before committing, adds a decoy
dangling blob, buries it under a later commit, and drops the reflogs.

## Teaching / realism
Secret-in-git leaks are one of the most common real-world exposures, and "I removed it, it's gone"
is a widespread misconception - `git add` alone is enough to persist a secret forever. The challenge
teaches object-store forensics (`fsck`, `cat-file`) rather than history reading, which is exactly
what incident responders do on a leaked repo.

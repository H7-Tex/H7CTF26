# Time Capsule

**Category:** misc  **Difficulty:** easy  **Author:** abu

> A Sparrow Freight developer swears the production token never made it into a commit, and the history is spotless. We pulled their repo before anyone could tidy it further.
>
> Never committed is not the same as never there.

Handout: `challenge/time-capsule.zip`, built with `FLAG=... bash challenge/build_repo.sh <outdir>` and zipped with `.git` included.

## Solution

`git log -p --all` is clean and `git reflog` is empty because the repo shipped without `.git/logs`. Grepping history gets you nothing.

The thing to know is that `git add` writes the blob into `.git/objects` right away, before any commit. Unstaging with `git rm --cached` or deleting the file doesn't remove that blob, it just leaves it dangling until a `git gc` prunes it. So look at the object store instead of the commit graph:

```
$ git fsck --lost-found
dangling blob 698e3c6c553b697a80b4b44d7c29f1f345ceea21
dangling blob c3d46ca9c0a373e94eae205cfad3e7ba7718e150
```

Dump both with `git cat-file -p <hash>`. One is a single line with a "rotated" token, `H7CTF{this_token_was_rotated_not_the_flag}`, which is the decoy. The other is the actual secrets file:

```
# production carrier credentials - DO NOT COMMIT
CARRIER_API_TOKEN=H7CTF{116f8522b35663cde2ce}
CARRIER_API_SECRET=...
```

`solution/solve.sh <repo-dir>` does the same walk.

Flag: `H7CTF{116f8522b35663cde2ce}`

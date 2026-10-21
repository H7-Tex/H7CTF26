# Notebook (template, not an event service)

Organizer notes. Copy this whole directory to `finals/services/<slug>/` and replace everything. The structure is the contract; the bugs are toys.

## Flag stores

| Store | Where the flag lives | Attack info | Intended path | Correct patch | Tempting wrong patch | Caught by |
|---|---|---|---|---|---|---|
| 0 | body of a private note | `{"note_id": ...}` | `GET /notes/<id>?preview=1` skips the owner check | owner check in the preview branch | disable preview | havoc previews its own private note |
| 1 | user bio | `{"user": ...}` | `GET /users/<name>?fields=bio` returns private fields to anyone | limit fields to public ones unless it's you | ignore `fields` | getflag reads its own bio via `fields`; havoc asks for `joined` |

## Unintended-bug notes

None known. Write yours here.

## Run it

```
cd service && docker compose up -d --build
python3 ../../tools/gate.py ..          # from finals/_template
```

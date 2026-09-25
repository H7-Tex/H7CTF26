# Sandboxed - writeup

A classic pyjail. `eval(expr, {"__builtins__": {}}, {})` with a substring denylist over the source.
The denylist kills the obvious stuff (`import`, `open`, `eval`, `exec`, `os`, `system`, `flag`,
backslash, `chr`, `getattr`, ...) and the empty builtins remove every convenient name. But two
things survive: the Python **type hierarchy** and **string concatenation**.

## The two ideas
1. **Reach a file object through the class tree.** Even with no builtins, `()` is an object, and
   `().__class__.__base__` is `object`. `object.__subclasses__()` lists every class loaded in the
   process - including the `io` classes. Walk to a file class:
   `_IOBase` -> `_RawIOBase` -> `FileIO`. `FileIO('/flag.txt').read()` returns the bytes. (The
   `__builtins__['open']` route via any module class's `__init__.__globals__` also works.)
2. **Beat the substring filter with concatenation.** The denylist matches literal substrings, so
   split the banned tokens across string literals: `'op'+'en'`, and `'flag'` in the path becomes
   `'/'+'fl'+'ag.txt'`. Those substrings never appear in the source, so the check passes.

## Payload
```
[c for c in [c for c in ().__class__.__base__.__subclasses__() if c.__name__=='_IOBase'][0].__subclasses__() if c.__name__=='_RawIOBase'][0].__subclasses__()[0]('/'+'fl'+'ag.txt').read()
```
`_RawIOBase.__subclasses__()[0]` is `FileIO`; instantiating it on the path and calling `.read()`
returns the flag, which the evaluator sends back as its result. `solution/solve.py` connects and
sends this.

## Deploy
Per-team on-demand docker instance. `entrypoint.sh` seals the platform-injected `$FLAG` into
`/flag.txt`, then `socat` serves `jail.py` (one python process per connection) on tcp/9999.
Dynamic flag -> nothing is shareable.

## Why it's fair
The jail source is a handout, so it's "beat this exact filter," not "guess what's blocked." The
intended technique (subclasses walk + string-splitting) is core pyjail knowledge; the denylist is
tuned so the trivial one-liners (`open`, `__import__`) are blocked but the standard escape paths
remain. An easy on-ramp for the misc category.

# Out of the Box

**Category:** misc  **Difficulty:** easy  **Author:** abu

> They stood up an expression evaluator, emptied the room it runs in, and put a bouncer on the door to turn away anything dangerous. The flag sits on the same box, just out of the room's reach.
>
> Read it anyway.

Handout: `challenge/sandboxed.zip` (`jail.py`). Per-team TCP instance on port 9999; `entrypoint.sh` writes `$FLAG` to `/flag.txt` and `socat` runs one jail per connection.

## Solution

The jail is a plain pyjail. Your line goes through a substring denylist (`import`, `open`, `eval`, `exec`, `os`, `sys`, `flag`, `chr`, `getattr`, backslash and friends, checked lowercased), then `eval(src, {"__builtins__": {}}, {})`. No builtins at all.

Two things survive that. First, the type hierarchy. `()` is still an object, `().__class__.__base__` is `object`, and `object.__subclasses__()` lists every class loaded in the process, including the `io` ones. Walk `_IOBase` -> `_RawIOBase` -> its first subclass, which is `FileIO`. `FileIO(path).read()` reads a file without ever touching `open`.

Second, the filter only matches literal substrings, so the path can be glued together: `'/'+'fl'+'ag.txt'` never contains `flag` in the source.

```
[c for c in [c for c in ().__class__.__base__.__subclasses__() if c.__name__=='_IOBase'][0].__subclasses__() if c.__name__=='_RawIOBase'][0].__subclasses__()[0]('/'+'fl'+'ag.txt').read()
```

The evaluator sends back the `repr` of the result, which is the flag bytes. Grabbing `open` out of some module's `__init__.__globals__['__builtins__']` with the same string-splitting trick works too.

```
python3 solution/solve.py <host> <port>
```

The flag is dynamic, one per team.

# Reference solution

The reference script builds a small wheel with two exact
`schrodinger_probe/__init__.py` members, uploads it, requests inspection, and
starts a Runtime session. Inspector records the first module member. With the
pinned Python 3.12.14 / pip 25.0.1 image, pip installs the last member. The
Portal confirms the package and inspection bindings, successful import,
repeated module path, and differing module digests before releasing the
configured flag.

Start the challenge from `challenge/`:

```sh
docker compose up --build --wait
```

Then run from the repository root:

```sh
python solution/solve.py --base-url http://127.0.0.1:8080
```

The transient flag is read from the immediate Runtime-session response. It is
not in the saved job output or Runtime logs. The script uses only Python's
standard library and targets a local challenge instance by default.

# Reference solver

Requires Python 3.11 or newer. The solver uses only the Python standard library;
it has no third-party dependencies.

Run it against a fresh instance using the public Portal URL:

```bash
python solution/solve.py https://<instance-host>
```

It recovers the instance's Anvil-issued `H7CTF{...}` value from the approved
protected-runtime deployment result. It does not access organizer APIs,
Qwen, or Kubernetes directly.

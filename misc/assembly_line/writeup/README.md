# Assembly Line - writeup

A classic misc scripting challenge: the server throws 250 small tasks at you, 2 seconds each, and only
hands over the flag if you clear the whole run. No handout - the "source" is the protocol you observe on
connect. The point is that a human can't do 250 rounds at 2s each; you write a client.

## The protocol
On connect the server prints a banner, then 250 lines of the form:
```
[<n>/250] <task>
```
where `<task>` is one of:
- `eval: <a> <op> <b>`  -> the integer result of `a op b` (op in `+ - *`)
- `reverse: <s>`        -> `s` reversed
- `sum: n1,n2,...`      -> the sum
- `b64: <base64>`       -> the decoded ASCII

You reply with one line per task. Any wrong or late (>2s) answer stops the line.

## The solver
Parse the prefix, compute, send the answer, repeat - trivial per task, the only trick is doing it in
code so you keep pace:
```python
if t.startswith("eval: "):    a,op,b = t[6:].split(); ans = eval(f"{a}{op}{b}")
elif t.startswith("reverse: "): ans = t[9:][::-1]
elif t.startswith("sum: "):     ans = sum(map(int, t[5:].split(",")))
elif t.startswith("b64: "):     ans = base64.b64decode(t[5:]).decode()
```
`solution/solve.py` runs the full loop; it clears 250/250 in well under the budget.

`H7CTF{sp33d_run_th3_4ss3mbly_l1n3_w1th_c0d3}` (per-team dynamic on the live instance).

## Deploy
Per-team on-demand docker; the Python server binds tcp/9999 directly and reads `$FLAG` from the env
(dynamic per-team). Long-lived interactive connection, so no Traefik half-close issue. Validated
end-to-end: the solver clears all 250 rounds and reads the flag over TCP against the container.

## Teaching
Socket automation and quick protocol parsing under a time budget - the everyday "you must script this"
misc reflex, and a gentle on-ramp to the interactive-service challenges (pyjail, pwn) elsewhere in the
set.

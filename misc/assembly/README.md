# Assembly Line

**Category:** misc  **Difficulty:** easy  **Author:** abu

> The Sparrow Freight sorting line never slows down: a long run of tiny jobs, each on a short clock, far more than any pair of hands can chase.
>
> Clear the whole shift and the line signs out the day's code.

No handout. Per-team TCP instance on port 9999.

## Solution

Connect and the server prints a banner, then starts throwing tasks at you one line at a time:

```
[1/250] eval: 812 * 37
[2/250] reverse: parcel
[3/250] sum: 4,19,88,2
[4/250] b64: c29ydGVk
```

Each one is trivial. The catch is that there are 250 of them and you get 2 seconds per answer. One wrong or late reply and the line stops. Nobody is doing that by hand, so write a client.

There are only four task types, so the parser is a few lines:

```python
if t.startswith("eval: "):      a, op, b = t[6:].split(); ans = eval(f"{a}{op}{b}")
elif t.startswith("reverse: "): ans = t[9:][::-1]
elif t.startswith("sum: "):     ans = sum(map(int, t[5:].split(",")))
elif t.startswith("b64: "):     ans = base64.b64decode(t[5:]).decode()
```

Loop over the lines, answer anything that matches `[n/250]`, and print whatever contains `H7CTF{` at the end.

```
python3 solution/solve.py <host> <port>
```

It clears all 250 rounds well inside the budget. The flag is dynamic, one per team.

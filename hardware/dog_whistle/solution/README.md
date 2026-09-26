# Reference solver

`solve.py` needs only numpy.

```
python3 solve.py <host> <port>
```

It synthesizes the two ultrasonic captures (leak, then overflow), recovers the
runtime address of `factory_diag` from the `CAL ECHO`, redirects the effect chain
by overflowing the calibration region, and prints the flag returned by
`factory_diag`.

Local bring-up:

```
make -C ../challenge OUT=/tmp/aria
cd /tmp && FLAG='H7CTF{test}' socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/tmp/aria
python3 solve.py 127.0.0.1 9999
```

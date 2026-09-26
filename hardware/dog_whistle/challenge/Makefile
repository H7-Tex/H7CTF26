CC ?= gcc
CFLAGS ?= -O2 -std=gnu11 -D_GNU_SOURCE -fno-omit-frame-pointer -ffp-contract=off -fstack-protector-strong -fPIE
LDFLAGS ?= -pie -Wl,-z,relro,-z,now
OUT ?= aria
SRC := src/main.c src/wav.c src/dsp.c src/codec.c

$(OUT): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(OUT) $(LDFLAGS) -lm

clean:
	rm -f $(OUT)

.PHONY: clean

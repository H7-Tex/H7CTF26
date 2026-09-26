NASM ?= nasm
FLAG ?= H7CTF{afterglow_local_test_0000}
SERVER_SECRET ?= afterglow-dev-secret
BUILD_DIR ?= build

panel.rom:
	BUILD_DIR=$(BUILD_DIR) OUT_ROM=panel.rom NASM=$(NASM) FLAG='$(FLAG)' SERVER_SECRET='$(SERVER_SECRET)' python3 bake.py

run: panel.rom
	qemu-system-i386 -drive format=raw,file=panel.rom

clean:
	rm -rf build panel.rom paneldata.bin boot.bin panel.bin

.PHONY: run clean

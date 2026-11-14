import random

FS = 1_000_000
N_PRESSES = 8
WINDOW = 64


def check(body44):
    s = 0
    for i in range(11):
        s += (body44 >> (4 * i)) & 0xF
    return s & 0xF


def pack(serial, counter, button):
    body = ((serial & 0xFFFFFF) << 20) | ((counter & 0xFFFF) << 4) | (button & 0xF)
    return (body << 4) | check(body)


def unpack(code48):
    crc = code48 & 0xF
    body = code48 >> 4
    serial = (body >> 20) & 0xFFFFFF
    counter = (body >> 4) & 0xFFFF
    button = body & 0xF
    return serial, counter, button, (check(body) == crc)


def make_device(seed):
    r = random.Random(seed)
    return {
        "serial": r.getrandbits(24),
        "base": r.getrandbits(12),
        "step": r.choice([1, 3, 5, 7]),
        "button": r.choice([1, 2, 4, 8]),
    }


def press_counter(dev, n):
    return (dev["base"] + n * dev["step"]) & 0xFFFF


def is_valid_next(dev, code48):
    serial, counter, button, ok = unpack(code48)
    if not ok or serial != dev["serial"] or button != dev["button"]:
        return False
    last = press_counter(dev, N_PRESSES - 1)
    return last < counter <= last + WINDOW

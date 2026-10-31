#!/usr/bin/env python3
import struct
import sys

KNOWN = [
    (0x58881688, "hisi/honor secure container A"),
    (0x58891689, "hisi/honor secure container B"),
    (0x27051956, "u-boot legacy image"),
    (0xD00DFEED, "flattened device tree"),
    (0x3AFF26ED, "android sparse"),
    (0xEDFE0DD0, "fdt (swapped)"),
    (0x016F2818, "u-boot fit/arm64 image"),
    (0x0A0D0A0D, "avb? no / dtbo?"),
    (0x51B0B5BA, "samsung? no"),
    (0x42504F4F, "POOB (boot)"),
    (0x4F4F4250, "BOOT"),
    (0x21444F52, "ROID! (ANDROID!)"),
    (0x544F4F42, "BOOT sw"),
    (0x00000000, "zeros"),
]


def dump(data, name):
    print("=" * 64)
    print(name, "size", len(data))
    for off in range(0, 0x60, 4):
        raw = data[off:off + 4]
        value = struct.unpack("<I", raw)[0]
        be = struct.unpack(">I", raw)[0]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in raw)
        print("%04x  le=%08x  be=%08x  ascii=%s" % (off, value, be, text))
    words = {}
    for magic, label in KNOWN:
        if magic and struct.unpack("<I", data[0:4])[0] == magic:
            words["first_word"] = label
    first = struct.unpack("<I", data[0:4])[0]
    print("first word 0x%08x -> %s" % (first, words.get("first_word", "unknown")))
    print("delta to 0x58881688: 0x%x" % (first - 0x58881688))
    for off in (0x8, 0x30, 0x200):
        seg = data[off:off + 16]
        print("off 0x%x: %s" % (off, " ".join("%02x" % b for b in seg)))
    run_ff = 0
    while 0x50 + run_ff < len(data) and data[0x50 + run_ff] == 0xFF:
        run_ff += 1
    print("0xff run from 0x50: %d bytes" % run_ff)


def main(argv):
    if len(argv) < 2:
        print("usage: header_scan.py <file> [file ...]")
        return 2
    for path in argv[1:]:
        dump(open(path, "rb").read(), path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
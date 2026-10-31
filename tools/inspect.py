#!/usr/bin/env python3
import bz2
import collections
import gzip
import hashlib
import json
import lzma
import math
import os
import struct
import sys
import zlib

MAGICS = [
    ("gzip", b"\x1f\x8b\x08"),
    ("zstd", b"\x28\xb5\x2f\xfd"),
    ("xz", b"\xfd7zXZ\x00"),
    ("lz4_frame", b"\x04\x22\x4d\x18"),
    ("lz4_legacy", b"\x02\x21\x4c\x18"),
    ("bzip2", b"BZh9"),
    ("lzop", b"\x89LZO\x00\r\n\x1a\n"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
    ("zip", b"PK\x03\x04"),
    ("rar", b"Rar!\x1a\x07"),
    ("elf", b"\x7fELF"),
    ("fdt", b"\xd0\x0d\xfe\xed"),
    ("android_boot", b"ANDROID!"),
    ("android_sparse", b"\x3a\xff\x26\xed"),
    ("avb0", b"AVB0"),
    ("cramfs", b"\x45\x3d\xcd\x28"),
    ("squashfs_le", b"hsqs"),
    ("squashfs_be", b"sqsh"),
    ("ext_super", b"\x53\xef\x01\x00"),
    ("cpio_newc", b"070701"),
    ("tar_ustar", b"ustar"),
    ("dex", b"dex\n"),
    ("pe", b"MZ\x90\x00"),
    ("hdr_a", bytes.fromhex("88168858")),
    ("hdr_b", bytes.fromhex("89168958")),
]


def entropy(buf):
    if not buf:
        return 0.0
    n = len(buf)
    counts = collections.Counter(buf)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def hexdump(data, offset, length):
    out = []
    end = min(len(data), offset + length)
    for i in range(offset, end, 16):
        chunk = data[i:i + 16]
        hexpart = " ".join("%02x" % b for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("%08x  %-47s  %s" % (i, hexpart, text))
    return out


def summary(path):
    data = open(path, "rb").read()
    total = len(data)
    last = total
    while last > 0 and data[last - 1] == 0:
        last -= 1
    info = {
        "file": os.path.basename(path),
        "size": total,
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "last_nonzero": last,
        "entropy_total": round(entropy(data[:last]), 4) if last else 0.0,
        "distinct_bytes": len(set(data[:last])),
        "zero_bytes": data.count(0),
        "ff_bytes": data.count(255),
    }
    pages = [i for i in range(0, total, 4096) if data[i:i + 4096].strip(b"\x00")]
    info["nonzero_pages"] = len(pages)
    info["first_pages"] = pages[:8]
    info["last_pages"] = pages[-8:]
    hits = {}
    for name, magic in MAGICS:
        pos = data.find(magic)
        if pos >= 0:
            hits[name] = pos
    info["magic_hits"] = hits
    chunks = []
    for i in range(0, last, 1 << 20):
        blk = data[i:i + (1 << 20)]
        chunks.append([hex(i), round(entropy(blk), 3)])
    info["entropy_1m"] = chunks
    blocks = [data[i:i + 16] for i in range(0, last - 15, 16)]
    info["blocks_16"] = len(blocks)
    info["blocks_16_uniq"] = len(set(blocks))
    return data, info


DECOMPRESSORS = [
    ("gzip", lambda d: gzip.decompress(d)),
    ("zlib", lambda d: zlib.decompress(d)),
    ("deflate_raw", lambda d: zlib.decompress(d, -15)),
    ("bz2", lambda d: bz2.decompress(d)),
    ("xz", lambda d: lzma.decompress(d)),
    ("lz4_frame", None),
    ("zstd", None),
]


def brute(path, data, last):
    results = []
    offsets = [0x0, 0x30, 0x38, 0x40, 0x100, 0x200, 0x400, 0x1000]
    for name, fn in DECOMPRESSORS:
        if fn is None:
            continue
        for off in offsets:
            if off >= last:
                continue
            try:
                out = fn(data[off:last])
            except Exception as exc:
                results.append({"algo": name, "offset": hex(off), "status": exc.__class__.__name__})
                continue
            results.append({"algo": name, "offset": hex(off), "status": "ok", "size": len(out)})
            open(path + "." + name + ".out", "wb").write(out)
            break
    return results


def main(argv):
    if len(argv) < 2:
        print("usage: inspect.py <file> [more files]")
        return 2
    lines = []
    for path in argv[1:]:
        data, info = summary(path)
        lines.append("## %s" % info["file"])
        lines.append("")
        lines.append("- size: %d" % info["size"])
        lines.append("- sha256: `%s`" % info["sha256"])
        lines.append("- md5: `%s`" % info["md5"])
        lines.append("- last nonzero byte: 0x%x" % info["last_nonzero"])
        lines.append("- entropy over nonzero region: %s" % info["entropy_total"])
        lines.append("- distinct byte values: %d" % info["distinct_bytes"])
        lines.append("- zero bytes: %d / 0xff bytes: %d" % (info["zero_bytes"], info["ff_bytes"]))
        lines.append("- nonzero 4K pages: %d" % info["nonzero_pages"])
        lines.append("- magic hits: %s" % (json.dumps(info["magic_hits"]) or "{}"))
        lines.append("- 16B blocks: %d of which unique %d" % (info["blocks_16"], info["blocks_16_uniq"]))
        lines.append("")
        lines.append("entropy per MiB: %s" % info["entropy_1m"])
        lines.append("")
        lines.append("```")
        lines.extend(hexdump(data, 0, 0x100))
        lines.append("```")
        lines.append("")
        lines.append("decompress attempts: %s" % json.dumps(brute(path, data, info["last_nonzero"])))
        lines.append("")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

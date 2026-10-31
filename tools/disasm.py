#!/usr/bin/env python3
import os
import subprocess
import sys

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, CS_ARCH_ARM, CS_MODE_THUMB

INTERESTING = ("svc", "hvc", "smc", "mrs", "msr", "eret", "brk", "pacibsp", "autibsp")


def elf_info(path):
    out = subprocess.run(["readelf", "-h", "-l", "-S", "-W", path],
                         capture_output=True, text=True)
    return out.stdout


def segments(path):
    out = subprocess.run(["readelf", "-l", "-W", path], capture_output=True, text=True).stdout
    result = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) > 5 and parts[0] == "LOAD":
            try:
                offset = int(parts[1], 16)
                vaddr = int(parts[2], 16)
                filesz = int(parts[4], 16)
                flags = parts[6] if len(parts) > 6 else ""
                result.append((offset, vaddr, filesz, flags))
            except ValueError:
                continue
    return result


def disasm(path, limit=4000):
    data = open(path, "rb").read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    lines = []
    hits = []
    for offset, vaddr, filesz, flags in segments(path):
        if "X" not in flags:
            continue
        code = data[offset:offset + filesz]
        for insn in md.disasm(code, vaddr):
            text = "%08x  %-10s %s" % (insn.address, insn.mnemonic, insn.op_str)
            if len(lines) < limit:
                lines.append(text)
            if insn.mnemonic in INTERESTING:
                hits.append(text)
    return lines, hits


def main(argv):
    if len(argv) < 2:
        print("usage: disasm.py <elf> [elf ...]")
        return 2
    for path in argv[1:]:
        print("=" * 60)
        print(path)
        print(elf_info(path))
        lines, hits = disasm(path)
        print("-- first %d instructions --" % len(lines))
        print("\n".join(lines))
        print("-- privileged / exception instructions --")
        print("\n".join(hits))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
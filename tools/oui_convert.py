#!/usr/bin/env python3
"""Convert IEEE OUI CSV to ouilist.bin for JANOS/CYM-NM28C5.

Usage:
    python oui_convert.py oui.csv ouilist.bin

Download IEEE OUI CSV (MA-L registry) from:
    https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries
    Select "MA-L" -> Export CSV

Binary format:
    4 bytes  : magic "OUI1"
    4 bytes  : entry count (uint32 little-endian)
    N x 32   : sorted entries
                 oui[3]   - 3 bytes big-endian (e.g. 0x70 0xC9 0x4E)
                 name[29] - null-terminated vendor string
"""

import csv
import struct
import sys

MAGIC      = b"OUI1"
NAME_LEN   = 29
ENTRY_SIZE = 32   # 3 + 29


def parse_oui(assignment):
    clean = assignment.replace(":", "").replace("-", "").strip()
    if len(clean) < 6:
        raise ValueError("Bad OUI: {!r}".format(assignment))
    return bytes.fromhex(clean[:6])


def convert(csv_path, bin_path):
    entries = []

    with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                assignment = (row.get("Assignment") or row.get("assignment") or "").strip()
                org = (row.get("Organization Name") or row.get("organization_name") or "").strip()
                if not assignment or not org:
                    continue
                oui = parse_oui(assignment)
                entries.append((oui, org))
            except Exception:
                continue

    entries.sort(key=lambda x: x[0])

    # Deduplicate (keep first occurrence after sort)
    seen = set()
    unique = []
    for oui, name in entries:
        if oui not in seen:
            seen.add(oui)
            unique.append((oui, name))

    with open(bin_path, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack("<I", len(unique)))
        for oui, name in unique:
            enc = name.encode("utf-8", errors="replace")[:NAME_LEN - 1]
            enc = enc + b"\x00" * (NAME_LEN - len(enc))
            f.write(oui + enc)

    print("Wrote {} OUI entries to {}".format(len(unique), bin_path))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("Usage: {} oui.csv ouilist.bin".format(sys.argv[0]))
    convert(sys.argv[1], sys.argv[2])

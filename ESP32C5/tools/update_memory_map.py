#!/usr/bin/env python3
"""
update_memory_map.py — Parse the CYM-NM28C5 linker map and rewrite the
auto-updated tables in ESP32C5/docs/memory-budget.md.

Called by CMake POST_BUILD:
    python3 <this_script> <map_file> <docs_dir> <version> <bin_size_bytes>
"""
import sys
import re
import os
import datetime

# ── Argument handling ───────────────────────────────────────────────────────
if len(sys.argv) < 5:
    print("usage: update_memory_map.py <map> <docs_dir> <version> <bin_size_bytes>")
    sys.exit(1)

MAP_PATH   = sys.argv[1]
DOCS_DIR   = sys.argv[2]
VERSION    = sys.argv[3]
_bin_arg   = sys.argv[4]
# Accept either a file path or a raw byte count
if os.path.exists(_bin_arg):
    BIN_BYTES = os.path.getsize(_bin_arg)
else:
    BIN_BYTES = int(_bin_arg)
DOC_PATH   = os.path.join(DOCS_DIR, "memory-budget.md")

# ── Parse map file ──────────────────────────────────────────────────────────
def parse_map(path):
    """Return (sections dict, bss_by_lib dict)."""
    sections = {}   # section_name -> total bytes
    bss_libs = {}   # library name -> bytes in .dram0.bss

    # A linker map section header looks like:
    #   .iram0.text     0x40800000    0x223ba
    # (no leading whitespace, dot-name, address, size — all hex)
    sec_re = re.compile(
        r'^(\.[a-z0-9_.]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)',
        re.IGNORECASE
    )
    # ESP-IDF map files use two forms for .bss.SYMBOL subsections inside .dram0.bss:
    #
    # Form 1 — inline (symbol name, addr, size, library all on one line):
    #   .bss.row.10    0x40828d7c      0x26c esp-idf/main/libmain.a(main.c.obj)
    #
    # Form 2 — split (symbol name alone, then addr+size+library on the next line):
    #   .bss.da_pan_copy.22
    #                  0x40829a88       0x38 esp-idf/main/libmain.a(main.c.obj)
    #
    # Both forms appear in the same map file. The old parser only handled form 1
    # and missed the majority of libmain's BSS.
    bss_inline_re = re.compile(
        r'^\s+\.bss\.\S+\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S+)',
        re.IGNORECASE
    )
    bss_name_re = re.compile(r'^\s+\.bss\.\S+\s*$')
    bss_cont_re = re.compile(
        r'^\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(\S+)',
        re.IGNORECASE
    )

    def _attr_lib(src, size):
        if size == 0:
            return
        lib_m = re.search(r'(lib\w+\.a)', src)
        lib = lib_m.group(1) if lib_m else src.split('(')[0].split('/')[-1][:40]
        bss_libs[lib] = bss_libs.get(lib, 0) + size

    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()

        i = 0
        while i < len(lines):
            line = lines[i]

            # Section header (no leading whitespace)
            m = sec_re.match(line)
            if m:
                name = m.group(1)
                size = int(m.group(3), 16)
                if size > sections.get(name, 0):
                    sections[name] = size
                i += 1
                continue

            # BSS form 1 — inline
            m = bss_inline_re.match(line)
            if m:
                _attr_lib(m.group(3), int(m.group(2), 16))
                i += 1
                continue

            # BSS form 2 — split: symbol name line, then continuation
            if bss_name_re.match(line):
                j = i + 1
                # Skip *fill* padding lines
                while j < len(lines) and lines[j].strip().startswith('*fill*'):
                    j += 1
                if j < len(lines):
                    mc = bss_cont_re.match(lines[j])
                    if mc:
                        _attr_lib(mc.group(3), int(mc.group(2), 16))
                        i = j + 1
                        continue

            i += 1

    except FileNotFoundError:
        print(f"[memory_map] WARNING: map file not found: {path}")

    return sections, bss_libs


sections, bss_libs = parse_map(MAP_PATH)

# ── Build replacement tables ────────────────────────────────────────────────
def fmt(n):
    """Format byte count as human-readable."""
    if n >= 1024:
        return f"{n:,} B ({n/1024:.1f} KB)"
    return f"{n:,} B"


build_date = datetime.date.today().isoformat()

iram   = sections.get('.iram0.text',  0)
ddata  = sections.get('.dram0.data',  0)
dbss   = sections.get('.dram0.bss',   0)
extbss = sections.get('.ext_ram.bss', 0)

metrics_table = f"""\
| Metric | Value |
|--------|-------|
| Version | {VERSION} |
| Build date | {build_date} |
| .iram0.text | {fmt(iram)} |
| .dram0.data | {fmt(ddata)} |
| .dram0.bss  (internal) | {fmt(dbss)} |
| .ext_ram.bss  (PSRAM) | {fmt(extbss)} |
| App binary size | {fmt(BIN_BYTES)} |"""

# Top 15 internal BSS consumers
top_libs = sorted(bss_libs.items(), key=lambda x: x[1], reverse=True)[:15]
if top_libs:
    bss_rows = "\n".join(
        f"| `{lib}` | {fmt(sz)} |"
        for lib, sz in top_libs
    )
    bss_table = f"| Library / object | Internal BSS |\n|-----------------|-------------|\n{bss_rows}"
else:
    bss_table = "| Library / object | Internal BSS |\n|-----------------|-------------|\n| (map parse found no entries) | — |"

# ── Rewrite the doc in-place ────────────────────────────────────────────────
def replace_section(content, start_marker, end_marker, new_body):
    pattern = re.compile(
        re.escape(start_marker) + r'.*?' + re.escape(end_marker),
        re.DOTALL
    )
    replacement = f"{start_marker}\n{new_body}\n{end_marker}"
    new_content, n = pattern.subn(replacement, content, count=1)
    if n == 0:
        print(f"[memory_map] WARNING: marker not found: {start_marker}")
    return new_content


try:
    with open(DOC_PATH, encoding='utf-8') as f:
        doc = f.read()

    doc = replace_section(
        doc,
        '<!-- MEMORY_METRICS_START -->',
        '<!-- MEMORY_METRICS_END -->',
        metrics_table
    )
    doc = replace_section(
        doc,
        '<!-- BSS_TABLE_START -->',
        '<!-- BSS_TABLE_END -->',
        bss_table
    )

    with open(DOC_PATH, 'w', encoding='utf-8') as f:
        f.write(doc)

    print(f"[memory_map] Updated {DOC_PATH}")
except FileNotFoundError:
    print(f"[memory_map] WARNING: doc not found: {DOC_PATH} — skipping update")

# ── Console summary (appears in build log) ──────────────────────────────────
print(f"[memory_map] ── Memory summary for {VERSION} ({build_date}) ──")
print(f"[memory_map]   .iram0.text  : {fmt(iram)}")
print(f"[memory_map]   .dram0.data  : {fmt(ddata)}")
print(f"[memory_map]   .dram0.bss   : {fmt(dbss)}  ← internal BSS")
print(f"[memory_map]   .ext_ram.bss : {fmt(extbss)}  ← PSRAM BSS")
print(f"[memory_map]   binary size  : {fmt(BIN_BYTES)}")
if top_libs:
    print(f"[memory_map]   Top internal BSS consumers:")
    for lib, sz in top_libs[:5]:
        print(f"[memory_map]     {lib:40s}  {sz:7,} B")

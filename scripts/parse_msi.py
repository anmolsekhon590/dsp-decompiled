#!/usr/bin/env python3
"""Minimal OLE2 (CFB) + MSI table parser for Archetype Plini X.msi.
Reads the _Tables stream list, then dumps key tables (Property, File, Directory,
Component, Shortcut, FeatureComponents) as TSV. Clean-room: no verbatim code."""
import struct, sys, os, io

MSI = "extracted_payload/Archetype Plini X.msi"
d = open(MSI, "rb").read()

# --- OLE2 header ---
assert d[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "not OLE"
sect_shift = struct.unpack_from("<H", d, 0x1e)[0]   # log2 sector size
sect_size = 1 << sect_shift
mini_shift = struct.unpack_from("<H", d, 0x32)[0]    # log2 mini sector size
mini_size = 1 << mini_shift
nfat = struct.unpack_from("<I", d, 0x2c)[0]
fat_start = struct.unpack_from("<I", d, 0x30)[0]
dir_start = struct.unpack_from("<I", d, 0x30 + 4)[0]
mini_cutoff = struct.unpack_from("<I", d, 0x38)[0]
mini_fat_start = struct.unpack_from("<I", d, 0x3c)[0]
mini_stream_start = struct.unpack_from("<I", d, 0x44)[0]  # first dir entry of mini stream root

def read_sector(idx):
    off = (idx + 1) * sect_size
    return d[off:off+sect_size]

# --- FAT chain ---
fat = b""
for i in range(nfat):
    s = read_sector(fat_start + i)
    fat += s
fat = struct.unpack("<%dI" % (len(fat)//4), fat)

def chain(start):
    out = []
    s = start
    seen = set()
    while s not in (0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF) and s not in seen:
        seen.add(s)
        out.append(s)
        s = fat[s] if s < len(fat) else 0xFFFFFFFE
    return out

def read_stream(start, size):
    if size == 0: return b""
    if size >= mini_cutoff:
        secs = chain(start)
        data = b"".join(read_sector(s) for s in secs)
        return data[:size]
    else:
        # mini stream
        secs = chain(mini_stream_start)
        mini = b"".join(read_sector(s) for s in secs)
        # mini fat
        mf = b""
        ms = mini_fat_start
        while ms not in (0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF):
            mf += read_sector(ms)
            ms = fat[ms] if ms < len(fat) else 0xFFFFFFFE
        mf = struct.unpack("<%dI" % (len(mf)//4), mf)
        msecs = []
        s = start
        seen = set()
        while s not in (0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF) and s not in seen:
            seen.add(s); msecs.append(s); s = mf[s] if s < len(mf) else 0xFFFFFFFE
        data = b"".join(mini[s*mini_size:(s+1)*mini_size] for s in msecs)
        return data[:size]

# --- Directory entries ---
def parse_dir():
    entries = []
    s = dir_start
    seen = set()
    while s not in (0xFFFFFFFE, 0xFFFFFFFD, 0xFFFFFFFF) and s not in seen:
        seen.add(s)
        sec = read_sector(s)
        for i in range(sect_size // 128):
            e = sec[i*128:(i+1)*128]
            if e[0:0x40].strip(b"\x00") == b"":  # empty entry (root often at 0)
                # still could be root; only skip if name len is 0
                pass
            name_len = struct.unpack_from("<H", e, 0x40)[0]
            if name_len == 0:
                continue
            name = e[0:name_len].decode("utf-16-le", "ignore").rstrip("\x00")
            etype = e[0x42]
            start = struct.unpack_from("<I", e, 0x74)[0]
            size = struct.unpack_from("<I", e, 0x78)[0] if etype != 1 else struct.unpack_from("<Q", e, 0x78)[0]
            entries.append((name, etype, start, size))
        s = fat[s] if s < len(fat) else 0xFFFFFFFE
    return entries

entries = parse_dir()
streams = {n: (st, sz) for (n, t, st, sz) in entries if t == 2}
print("=== OLE streams ===")
for n, t, st, sz in entries:
    print(f"  type={t} size={sz:>10}  {n!r}")

# --- MSI table decode: each table is a stream in the OLE root named after table.
# Column definitions live in the '_Columns' stream; rows in '<TableName>' stream.
# Decode: read '_Columns' to know per-table column types, then parse rows.

def read(name):
    if name not in streams: return b""
    return read_stream(*streams[name])

tables_stream = read("_Tables")
cols_stream = read("_Columns")

# _Tables: list of table names as null-terminated strings, each max 64 bytes? Actually
# _Tables is a 1-column table (Name, string). It's encoded as rows of fixed cat.
# Simpler: decode _Tables as UTF-16LE strings separated — but MSI uses a column cat system.
# Instead, rely on known stream names from the directory listing: any stream that isn't
# a reserved name is a table.
reserved = {"_Tables","_Columns","_Strings","_Validation"}
table_names = [n for n in streams if n not in reserved and not n.startswith("_")]
print("\n=== Tables found ===")
for t in sorted(table_names):
    print(" ", t)

# Decode _Strings (string pool): 2-byte lengths table + string data
def decode_strings():
    s = read("_Strings")
    if not s: return {}
    # Pool: array of (uint16 ref_count?) no — _Strings is just concatenated UTF-16LE strings
    # separated by null. Actually MSI _Strings: list of null-terminated UTF-16LE strings.
    parts = s.decode("utf-16-le","ignore").split("\x00")
    return [p for p in parts if p]
strpool = decode_strings()

# Decode _Columns: rows define (Table, Number, Name, Type). Type low byte: 0=string,1=int,2=binary? Actually
# cat: 1 bit is key. Type values: 0=long string, 1=short int?, 2=long int, etc. We'll be pragmatic.
# Column record (each 8 bytes? no, variable). Let's just print raw _Columns hex head.
print("\n=== _Columns head ===")
print(cols_stream[:64].hex())

# For our purposes, dump the raw bytes of key tables and try to extract printable strings.
def dump_table(name):
    raw = read(name)
    print(f"\n=== {name} ({len(raw)} bytes) ===")
    # MSI rows are not trivially delimited; print hex+ascii head and any UTF16/ascii strings.
    if len(raw) > 0:
        print("head:", raw[:80].hex())
        # extract ascii and utf16 substrings
        import re
        asc = re.findall(rb"[\x20-\x7e]{3,}", raw)
        print("ascii tokens:", [t.decode() for t in asc[:30]])
        u16 = re.findall(rb"(?:[\x20-\x7e]\x00){3,}", raw)
        print("utf16 tokens:", [t.decode('utf-16-le','ignore') for t in u16[:30]])

for t in ["Property","Directory","Component","File","Shortcut","Feature","FeatureComponents","Registry","CustomAction"]:
    if t in streams:
        dump_table(t)

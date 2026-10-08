#!/usr/bin/env python3
"""Locate the LZMA stream in the AI SFX overlay and attempt decompression."""
import mmap, lzma, struct, os

FILE = "Archetype Plini X v1.0.2.exe"
f = open(FILE, 'rb')
mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

# Scan windowed entropy to find where true compressed (entropy ~8.0, no structure) data starts.
def ent(b):
    import math, collections
    c = collections.Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

print("=== Entropy profile across overlay (1MB windows) ===")
prev = None
for off in range(0x356600, 0x1398c000, 0x100000):
    e = ent(mm[off:off+0x100000])
    tag = ""
    print(f"{off:08x}  ent={e:.3f}")

# Find LZMA-alone header: byte0 in [0..225], then 4-byte dict size (power of 2 ish),
# then 8-byte uncompressed size (often 0xffffffffffffffff or a real value).
# Brute scan candidate starts across the high-entropy region.
def try_alone(start, feed=0x40000):
    try:
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        out = dec.decompress(mm[start:start+feed])
        return len(out), out[:48]
    except Exception as e:
        return None

print("\n=== Brute scan for LZMA-alone stream (0x356600..0x500000 & around cab) ===")
found = []
for s in range(0x356600, 0x500000, 0x200):
    if mm[s] > 0xE1:  # props byte validity: lc<=8,lp<=4,pb<=4 => max 8+4*9+5*9*5=... actually <=0xE1 (225)
        continue
    r = try_alone(s, 0x4000)
    if r and r[0] > 200:
        found.append((s, r[0]))
        print(f"  LZMA-alone @ {hex(s)} -> {r[0]} bytes; head={r[1].hex()}")
        if len(found) > 10:
            break

# Also scan the CAB-claimed region
print("\n=== Scan around 0x1347a8dc ===")
for s in list(range(0x1347a000, 0x1347b000, 0x40)) + list(range(0x4e4000, 0x4e5000, 0x10)):
    if mm[s] > 0xE1: continue
    r = try_alone(s, 0x4000)
    if r and r[0] > 200:
        print(f"  LZMA-alone @ {hex(s)} -> {r[0]} bytes; head={r[1][:32].hex()}")

f.close()

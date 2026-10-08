#!/usr/bin/env python3
"""Extract the 3 embedded PE files from the overlay, validate, and report their internals."""
import pefile, os, struct

FILE = "Archetype Plini X v1.0.2.exe"
OUT = "decompiled/embedded"
os.makedirs(OUT, exist_ok=True)

# Known PE offsets in overlay and their estimated sizes from section table scan
pes = [
    (0x38a200, "embedded_pe1_at_0x38a200"),
    (0x423400, "embedded_pe2_at_0x423400"),
    (0x42fe00, "embedded_pe3_at_0x42fe00"),
]

# First, get accurate sizes: parse each PE's sections to compute its true raw extent
def pe_extent_at(fpath, base_off):
    with open(fpath,'rb') as f:
        data = f.read()  # whole file mmap is too big; we read by offset below
    return None

f = open(FILE, 'rb')

def read(off, n):
    f.seek(off); return f.read(n)

for off, name in pes:
    f.seek(off)
    head = f.read(0x400)
    e_lfanew = int.from_bytes(head[0x3c:0x40],'little')
    pe_off = off + e_lfanew
    f.seek(pe_off)
    pehdr = f.read(0x18+224)
    machine = int.from_bytes(pehdr[4:6],'little')
    nsec = int.from_bytes(pehdr[6:8],'little')
    opt_sz = int.from_bytes(pehdr[0x14:0x16],'little')
    magic = int.from_bytes(pehdr[0x18:0x1a],'little')
    sec_tbl_off = pe_off + 0x18 + opt_sz
    end = 0
    secs = []
    for i in range(nsec):
        f.seek(sec_tbl_off + i*40)
        s = f.read(40)
        vsize = int.from_bytes(s[8:12],'little')
        vaddr = int.from_bytes(s[12:16],'little')
        rawsize = int.from_bytes(s[16:20],'little')
        rawoff = int.from_bytes(s[20:24],'little')
        nm = s[0:8].rstrip(b'\x00').decode('latin1')
        e = rawoff + rawsize
        if e > end: end = e
        secs.append((nm, rawoff, rawsize, vaddr, vsize))
    print(f"\n=== PE @ {hex(off)}  machine={hex(machine)} nsec={nsec} raw_extent={end} ===")
    for nm,ro,rs,va,vs in secs:
        print(f"   {nm:10} rawoff={hex(ro):10} rawsize={hex(rs):10} vaddr={hex(va):10} vsize={hex(vs):10}")

    # Extract the bytes
    f.seek(off)
    data = f.read(end)
    out = os.path.join(OUT, name + ".exe")
    with open(out,'wb') as g:
        g.write(data)
    print(f"   -> wrote {len(data)} bytes to {out}")

    # Also: extract anything that might follow up to next PE marker as 'padding'
f.close()

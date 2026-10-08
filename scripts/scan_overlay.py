#!/usr/bin/env python3
"""Scan the overlay region of the installer for all embedded PE files and archives."""
import os, mmap

FILE = "Archetype Plini X v1.0.2.exe"
OVERLAY_START = 0x356600
SIG_START = 0x1398c518  # Authenticode signature

f = open(FILE, 'rb')
mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
fsize = len(mm)

print(f"Overlay region: {hex(OVERLAY_START)} .. {hex(SIG_START)} (size {SIG_START-OVERLAY_START:,} bytes)")

# Find all MZ headers in overlay
mz_positions = []
pos = OVERLAY_START
while True:
    idx = mm.find(b'MZ', pos)
    if idx == -1 or idx >= SIG_START:
        break
    mz_positions.append(idx)
    pos = idx + 1

print(f"\nFound {len(mz_positions)} 'MZ' occurrences in overlay.")
# Validate each as a real PE (has PE\0\0 at e_lfanew offset)
print("\n=== Valid PE files in overlay ===")
pes = []
for mz in mz_positions:
    if mz + 0x40 > len(mm):
        continue
    e_lfanew = int.from_bytes(mm[mz+0x3c:mz+0x40], 'little')
    if e_lfanew == 0 or e_lfanew > 0x1000:
        continue
    pe_off = mz + e_lfanew
    if pe_off + 4 > len(mm):
        continue
    if mm[pe_off:pe_off+4] == b'PE\x00\x00':
        # Read machine + num sections + opt header size
        machine = int.from_bytes(mm[pe_off+4:pe_off+6], 'little')
        nsec = int.from_bytes(mm[pe_off+6:pe_off+8], 'little')
        opt_sz = int.from_bytes(mm[pe_off+0x14:pe_off+0x16], 'little')
        magic = int.from_bytes(mm[pe_off+0x18:pe_off+0x1a], 'little')
        # estimate size by summing sections' raw data end
        sec_tbl = pe_off + 0x18 + opt_sz
        end = 0
        for i in range(nsec):
            so = sec_tbl + i*40
            if so+40 > len(mm): break
            rawsize = int.from_bytes(mm[so+16:so+20], 'little')
            rawoff = int.from_bytes(mm[so+20:so+24], 'little')
            e = rawoff + rawsize
            if e > end: end = e
        arch = {0x14c:'i386',0x8664:'amd64',0x1c0:'ARM',0xaa64:'ARM64'}.get(machine, hex(machine))
        sub = int.from_bytes(mm[pe_off+0x5c:pe_off+0x5e],'little') if opt_sz>=0x44 else 0
        print(f"  PE @ {hex(mz):10}  machine={arch:6} nsec={nsec} optmagic={hex(magic)} subsystem={sub} est_size={end}")
        pes.append((mz, end, arch, nsec))

# 7z archive scan
print("\n=== Archive markers in overlay ===")
for m, name in [(b'7z\xbc\xaf\x27\x1c','7z'),(b'MSCF\x00\x00\x00\x00','CAB(new)')]:
    pos = OVERLAY_START
    while True:
        idx = mm.find(m, pos)
        if idx == -1 or idx >= SIG_START: break
        print(f"  {name} @ {hex(idx)}")
        pos = idx + 1

# CAB old signature: 'MSCF'
pos = OVERLAY_START
while True:
    idx = mm.find(b'MSCF', pos)
    if idx == -1 or idx >= SIG_START: break
    # CAB header: 4 'MSCF', 4 reserved0, 4 cbCabinet, 4 reserved2, 1 verMajor,1 verMinor,2 cFolders,2 cFiles,2 flags,2 setID,2 iCabinet
    if idx + 36 <= len(mm):
        cbCabinet = int.from_bytes(mm[idx+8:idx+12],'little')
        cFolders = int.from_bytes(mm[idx+26:idx+28],'little')
        cFiles = int.from_bytes(mm[idx+28:idx+30],'little')
        flags = int.from_bytes(mm[idx+30:idx+32],'little')
        print(f"  CAB(MSCF) @ {hex(idx)} cbCabinet={cbCabinet} cFolders={cFolders} cFiles={cFiles} flags={hex(flags)}")
    pos = idx + 1

f.close()

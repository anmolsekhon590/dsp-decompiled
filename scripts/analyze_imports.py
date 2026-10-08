#!/usr/bin/env python3
"""Analyze imports, delay imports, and resources of the PE."""
import pefile

FILE = "Archetype Plini X v1.0.2.exe"
pe = pefile.PE(FILE)

print("=== IMPORT DIRECTORY ===")
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode('latin1', 'replace')
        print(f"\n--- {dll}  ({len(entry.imports)} funcs) ---")
        for imp in entry.imports:
            n = imp.name.decode() if imp.name else f"ord_{imp.ordinal}"
            print(f"  {hex(imp.address):12} {n}")
else:
    print("No standard imports")

print("\n\n=== DELAY IMPORT DIRECTORY ===")
if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
    for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
        dll = entry.dll.decode('latin1', 'replace') if entry.dll else "?"
        print(f"--- {dll} ---")
else:
    print("No delay imports")

print("\n\n=== RESOURCE TREE ===")
if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
    for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        tname = pefile.RESOURCE_TYPE.get(rtype.struct.Id, rtype.struct.Id)
        if rtype.name:
            tname = str(rtype.name)
        print(f"\nType: {tname} (id={rtype.struct.Id})  entries={len(rtype.directory.entries)}")
        for sub in rtype.directory.entries:
            if sub.name:
                subname = str(sub.name)
            else:
                subname = f"id_{sub.struct.Id}"
            for lang in sub.directory.entries:
                data_rva = lang.data.struct.OffsetToData
                size = lang.data.struct.Size
                # offset to data in file
                offset = pe.get_offset_from_rva(data_rva)
                print(f"    {subname:20} lang={lang.struct.Id:5} fileoff={hex(offset):12} size={size:8}")
else:
    print("No resources")

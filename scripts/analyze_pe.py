#!/usr/bin/env python3
"""Comprehensive PE analysis of Archetype Plini X v1.0.2.exe"""
import pefile
import os

FILE = "Archetype Plini X v1.0.2.exe"
pe = pefile.PE(FILE, fast_load=True)

print("=== DOS / FILE HEADER ===")
print(f"e_lfanew: {hex(pe.DOS_HEADER.e_lfanew)}")
print(f"Machine: {hex(pe.FILE_HEADER.Machine)} (0x14c=i386)")
print(f"NumberOfSections: {pe.FILE_HEADER.NumberOfSections}")
print(f"TimeDateStamp: {hex(pe.FILE_HEADER.TimeDateStamp)}")
print(f"Characteristics: {hex(pe.FILE_HEADER.Characteristics)}")
print(f"SizeOfOptionalHeader: {pe.FILE_HEADER.SizeOfOptionalHeader}")

print("\n=== OPTIONAL HEADER ===")
oh = pe.OPTIONAL_HEADER
print(f"Magic: {hex(oh.Magic)} (0x10b=PE32)")
print(f"AddressOfEntryPoint: {hex(oh.AddressOfEntryPoint)}")
print(f"ImageBase: {hex(oh.ImageBase)}")
print(f"SizeOfImage: {hex(oh.SizeOfImage)} ({oh.SizeOfImage:,})")
print(f"SizeOfHeaders: {hex(oh.SizeOfHeaders)}")
print(f"Subsystem: {oh.Subsystem} (2=GUI)")
print(f"EntryPoint RVA: {hex(oh.AddressOfEntryPoint)}")
print(f"SectionAlignment: {hex(oh.SectionAlignment)}")
print(f"FileAlignment: {hex(oh.FileAlignment)}")

print("\n=== SECTIONS ===")
print(f"{'Name':10} {'VAddr':10} {'VSize':10} {'RawOff':10} {'RawSize':10} {'Entropy':>8} {'Flags':>10}")
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('latin1')
    ent = s.get_entropy()
    flags = hex(s.Characteristics)
    print(f"{name:10} {hex(s.VirtualAddress):10} {hex(s.Misc_VirtualSize):10} "
          f"{hex(s.PointerToRawData):10} {hex(s.SizeOfRawData):10} {ent:8.3f} {flags:>10}")

print("\n=== DIRECTORY ENTRIES ===")
for idx, d in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
    names = ["EXPORT","IMPORT","RESOURCE","EXCEPTION","SECURITY","BASERELOC",
             "DEBUG","ARCHITECTURE","GLOBALPTR","TLS","LOAD_CONFIG","BOUND_IMPORT",
             "IAT","DELAY_IMPORT","COM_DESCRIPTOR","RESERVED"]
    if d.VirtualAddress or d.Size:
        print(f"[{idx}] {names[idx]:16} VA={hex(d.VirtualAddress):12} Size={d.Size:>10} ({hex(d.Size)})")

print(f"\nFile size on disk: {os.path.getsize(FILE):,}")

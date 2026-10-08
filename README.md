# Archetype: Plini X v1.0.2 — Reverse-Engineering Analysis

Clean-room reverse-engineering study of Neural DSP's **Archetype: Plini X**
guitar amp/pedal modelling plugin installer (`Archetype Plini X v1.0.2.exe`,
314 MiB). All findings below were derived from structural inspection, MSI
table export, and decompilation of the **installer shell only**. No Neural DSP
proprietary DSP code or model weights are reproduced here; the protected
plugin binaries are characterised at a high level only.

> ⚖️ **Legal notice**: This analysis is for interoperability, security
> research, and educational purposes. The plugin itself is commercial
> software protected by PACE/iLok DRM and copyright (© 2024 Neural DSP).
> Do not use any of this to circumvent licensing. See `../LICENSE`.

---

## TL;DR

| Question | Answer |
|----------|--------|
| Is it a .NET app? | **No.** Zero managed metadata anywhere (stub, helpers, plugins all native C++). |
| What is the 314 MiB EXE? | An **Advanced Installer 20.9.1 SFX bootstrapper** (Caphyon) wrapping an LZMA-compressed MSI + CAB. |
| How do I extract it? | `wine "Archetype Plini X v1.0.2.exe" /extract` dumps `Archetype Plini X.msi` + `Archetype Plini X1.cab`. |
| What's inside? | 4 plugin binaries (standalone/VST2/VST3/AAX, x64, ~91 MiB each) + 189 preset XMLs + manual PDF. |
| What framework? | **JUCE** + **Intel IPP** + **GRU neural nets** (RTNeural-style) for amp/cab modelling. |
| DRM? | **PACE Anti-Piracy iLok** (InterLok). Model weights are encrypted, decrypted in memory at runtime. |
| Compiler | MSVC 14.36 (stub) / MSVC (plugins), x86-64 for the plugins. |

---

## Repository layout

```
neural-dsp-rev/
├── README.md                        # ← this file (main project doc)
├── LICENSE                          # analysis license (analysis artefacts only)
├── .gitignore
├── scripts/                         # analysis scripts (Python)
│   ├── analyze_pe.py                # PE section/header analyser
│   ├── analyze_imports.py           # PE import-table dumper
│   ├── extract_embedded_pe.py       # carves the 3 embedded helper DLLs
│   ├── scan_overlay.py              # overlay entropy / structure scanner
│   ├── find_lzma.py                 # LZMA stream locator (entropy + brute decode)
│   └── parse_msi.py                  # raw OLE2/MSI table parser (fallback)
├── decompiled/
│   ├── README.md                    # index of decompiled/ subdirectories
│   ├── PROGRESS.md                   # chronological findings log
│   ├── analysis/                    # Ghidra headless decompile-export script
│   │   └── DecompExport.py
│   ├── embedded/                    # 3 Caphyon helper DLLs carved from the stub
│   │   ├── embedded_pe1_at_0x38a200.exe   # AICustAct.dll (73 MSI custom actions)
│   │   ├── embedded_pe2_at_0x423400.exe   # lzmaextractor.dll (LZMA extract)
│   │   └── embedded_pe3_at_0x42fe00.exe   # Prereq.dll (prerequisite installer)
│   ├── pe_resources/                # 7z-extracted PE sections + .rsrc/
│   │   ├── .text .rdata .data .reloc
│   │   └── .rsrc/{BITMAP,ICON,DIALOG,HTML(=XAML),MANIFEST,version.txt,…}
│   ├── csharp/                      # EMPTY — no .NET exists (see PROGRESS §3)
│   ├── native/                      # native-analysis notes (stub/helpers)
│   └── resources/                   # resource notes
└── extracted_payload/               # MSI + CAB + unpacked contents (gitignored)
    ├── README.md                    # what's inside & how it was extracted
    └── cab_contents/               # 195 unpacked files (353.7 MiB)
        ├── ArchetypePlini.exe       # standalone (x64)
        ├── ArchetypePlini.dll       # VST2 (x64)
        ├── ArchetypePliniX.vst3     # VST3 (x64)
        ├── ArchetypePliniX.aaxplugin# AAX (x64)
        ├── ArchetypePliniXv1.0.0.pdf
        ├── Plugin.ico
        └── *.xml                    # 189 presets
```

> The original installer (`Archetype Plini X v1.0.2.exe`, 314 MiB) and the
> extracted binaries/presets are **not committed** — see `.gitignore` and
> `LICENSE`. A Wine prefix was used to run `/extract`; it is also gitignored.

---

## The installer shell (stub)

`Archetype Plini X v1.0.2.exe` is a **PE32 i386** Advanced Installer SFX
bootstrapper (Caphyon LTD, Advanced Installer 20.9.1 build 6620d1e2):

- ~3.5 MiB native stub (MSVC 14.36), GDI+/WPF-themed UI.
- 310 MiB overlay = LZMA-compressed `Archetype Plini X.msi` + `…X1.cab`,
  terminated by an `ADVINSTSFX` trailer + Authenticode signature (DigiCert).
- 3 embedded Caphyon helper DLLs in the overlay's index region:
  `AICustAct.dll`, `lzmaextractor.dll`, `Prereq.dll` — generic Advanced
  Installer runtime, **not** Neural DSP code, and **not .NET**.
- SFX flags: `/extract`, `/extractlzma`, `/groupsextract`, `/selinst`,
  `/help`, plus MSI pass-through (`/quiet`, `/qb!`, …).

### Reproducing the extraction
```bash
# 1. carve the 3 embedded helper DLLs from the stub overlay
python3 scripts/extract_embedded_pe.py

# 2. extract PE resources/sections with 7z
7z x -odecompiled/pe_resources "Archetype Plini X v1.0.2.exe" ".rsrc" ".text" ".rdata" ".data" ".reloc"

# 3. dump the SFX payload via the bootstrapper's own /extract (Wine)
WINEPREFIX=./wine_prefix WINEDEBUG=-all DISPLAY= \
  wine "Archetype Plini X v1.0.2.exe" /extractlzma /extract
# → %APPDATA%/Neural DSP/Archetype Plini X 1.0.2/install/{*.msi,*.cab}

# 4. unpack the CAB
7z x -oextracted_payload/cab_contents extracted_payload/"Archetype Plini X1.cab"

# 5. inspect the MSI (msitools)
msiinfo tables    extracted_payload/"Archetype Plini X.msi"
msiinfo export    extracted_payload/"Archetype Plini X.msi" File
```

## The plugin

The four plugin binaries are **native PE32+ x86-64** JUCE-based C++ with:

- **Intel IPP** static-linked (`IPPCODE`/`IPPDATA` sections) for vectorised DSP.
- **GRU recurrent neural networks** for amp & cabinet modelling
  (3 amps: clean/crunch/lead; cab sim; 3 EQs; pedals: compressor/drive/
  octaver/preDelay; FX: chorus/delay/reverb; tuner + metronome).
- **PACE/iLok** DRM: the `.proxy` section embeds the PACE license-proxy PE;
  the `.guard` section holds obfuscated/anti-tamper code; model weights live
  in an 80 MB virtual `.mfrt` region that is **decrypted at runtime** by the
  iLok license. The weights are therefore not recoverable from the static
  binary without a licensed, running instance.

### Preset format
`.xml` presets are a **custom flat key-value serialization** (not standard
XML), e.g.:
```
plini-X version 1.0.1 name Vestiges - Default Rhythm isFavorite false appModel …
subModels … ampParameters … leadAmp … leadAmpGain 0.513372 leadAmpBright true …
```
Parameters are normalised floats (0..1) or booleans, organised into the same
`subModels` hierarchy as the internal `archetypeAppModel.xml`.

## What is NOT here / scope limits

- **No .NET decompilation** — there is no managed code in this product.
- **No DSP source / model weights** — these are PACE-encrypted and
  runtime-only; reproducing them would require circumventing the DRM, which
  is out of scope and not provided here.
- The native stub and Caphyon helpers are **generic third-party toolchain**,
  decompiling them yields no Neural DSP IP; Ghidra notes are included for
  completeness but are low-value.

See `decompiled/PROGRESS.md` for the full chronological findings log.

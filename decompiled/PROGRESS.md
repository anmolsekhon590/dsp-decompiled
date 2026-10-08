# Reverse-Engineering Progress Log — Archetype Plini X v1.0.2.exe

> Clean-room analysis. No verbatim code copying. Findings are derived from
> structural/metadata inspection, MSI table export, and decompilation.

## 0. Artifact identity

- **File**: `Archetype Plini X v1.0.2.exe` (328,789,592 bytes ≈ 314 MiB)
- **Publisher version-info**:
  - CompanyName: `Neural DSP`
  - FileDescription: `Archetype Plini X Installer`
  - InternalName: `Archetype Plini X v1.0.2 RC1`
  - ProductName: `Archetype Plini X`
  - ProductVersion / FileVersion: `1.0.2`
  - LegalCopyright: `Copyright (C) 2024 Neural DSP`
- **Authenticode**: Signed by Neural DSP, timestamped via DigiCert Trusted G4
  Code Signing RSA4096 SHA384 2021 CA (sig at file offset `0x1398c518`, 10,560 B).

## 1. PE layout (the stub, ~3.5 MiB)

PE32 (i386), 5 sections, ImageBase 0x400000, Subsystem = Windows GUI.

| Section | VAddr    | VSize    | RawOff   | RawSize  | Entropy |
|---------|----------|----------|----------|----------|---------|
| .text   | 0x1000   | 0x26acb6 | 0x400    | 0x26ae00 | 6.453   |
| .rdata  | 0x26c000 | 0x8f55a  | 0x26b200 | 0x8f600  | 4.603   |
| .data   | 0x2fc000 | 0xd240   | 0x2fa800 | 0x3c00   | 4.767   |
| .rsrc   | 0x30a000 | 0x2f46c | 0x2fe400 | 0x2f600  | 5.557   |
| .reloc  | 0x33a000 | 0x28bf0 | 0x32da00 | 0x28c00  | 6.513   |

Last section ends at `0x356600` → **overlay** spans `0x356600 .. 0x1398c518`
(325,279,512 B ≈ 310 MiB), followed by the Authenticode signature.

### Imports
- **Standard import**: only `KERNEL32.dll` (186 functions) — the SFX stub is
  self-contained C/C++.
- **Delay imports**: msi.dll, gdiplus.dll, Cabinet.dll, USER32, GDI32,
  ADVAPI32, SHELL32, ole32, OLEAUT32, SHLWAPI, COMCTL32, UxTheme, MSIMG32,
  dbghelp, VERSION, WININET, dwmapi, MPR, NETAPI32.
- GDI+ usage confirms GDI+/WPF-rendered UI.

### .rsrc resources (extracted to `decompiled/pe_resources/.rsrc/`)
- RT_BITMAP ×6, RT_ICON ×5, RT_DIALOG ×5, RT_STRING ×15,
  RT_GROUP_ICON ×1, RT_VERSION ×1, **RT_HTML ×9** (actually WPF XAML:
  ControlTemplate / Style / Button / ComboBox — the installer theme), RT_MANIFEST ×1.
- A real **CAB** at file offset `0x29bc00` (MSCF, 902 B) inside `.rdata`
  containing `stopexecseq.mst` (MSI transform / stop-exec sequence).

## 2. The 310 MiB overlay = Advanced Installer SFX payload

### Build toolchain (from embedded strings, offset ~0x35dc00)
- `Advanced Installer 20.9.1 build 6620d1e2` (Caphyon LTD)
- Markers: `AI_BOOTSTRAPPERORIGINAL_ALLANG`, `AI_EMBEDDED_FILES_LOCATION`,
  `AI_YEAR2024AI_PACKAGING_TOOL`, `AI_BUILD_NAMEDefaultBuild`.
- Trailer magic `ADVINSTSFX` at `0x1398c50a`.

### SFX file table (trailer @ `0x1398c3e0 .. 0x1398c518`)
Length-prefixed UTF-16 entries describing embedded files:
- `Archetype Plini X.msi`           (offset table ref `0x356600`)
- `Archetype Plini X1.cab`          (offset `0x1347a8dc`)
- `Archetype Plini X v1.0.2 RC1.ini`

### SFX command-line interface (from stub strings)
The stub recognises these flags (found in `.rdata`, wide strings):
- `/extract`        — extract embedded files to the extraction folder
- `/extractlzma`    — extract the LZMA-compressed payload
- `/groupsextract`  — extract file groups
- `/selinst`        — selective install
- `/help`           — usage
- `/quiet /qb! /qb+ /qn+` etc. — MSI pass-through UI levels

### Extraction method (reproduced, clean-room)
Running the bootstrapper under **Wine 11.18** with `/extract` extracted the
embedded payload verbatim to
`%APPDATA%\Neural DSP\Archetype Plini X 1.0.2\install\`:
- `Archetype Plini X.msi`   (1,815,040 B = 0x1bb200 — matches trailer)
- `Archetype Plini X1.cab`  (323,463,388 B ≈ 309 MiB)
These are copied to `extracted_payload/` and the CAB unpacked to
`extracted_payload/cab_contents/` (195 files, 353.7 MiB uncompressed).

### Embedded native helper DLLs (Caphyon custom actions, NOT .NET)
Extracted to `decompiled/embedded/`:

| Offset    | Raw size  | OriginalFile         | Exports | Purpose |
|-----------|-----------|----------------------|---------|---------|
| 0x38a200  | 586,752   | `AICustAct.dll`      | 73      | "Various custom actions" (msi/shell/network/crypto) |
| 0x423400  | 7,168     | `lzmaextractor.dll`  | 5       | "Custom action that extracts a LZMA archive" |
| 0x42fe00  | 738,304   | `Prereq.dll`         | 12      | "installs feature-based prerequisites" |

All three are PE32 i386 DLLs, **CLR/COM descriptor = 0** (pure native C++).

## 3. .NET claim — DEBUNKED

The original analysis brief asserted ".NET metadata streams (#~, #-) present"
and listed decompiling .NET DLLs as a task. This is a **false positive**:

- PE COM/CLR descriptor (DataDirectory[14]) = `VA=0 size=0` — no CLR header.
- `BSJB` (.NET metadata root signature): **0 occurrences** in the entire file.
- The `#~`, `#-`, `#US` byte patterns binwalk/strings matched are coincidental
  `23 7e 00` byte triples inside the high-entropy LZMA-compressed payload.
- `ilspycmd` rejects all three embedded DLLs and all four plugin binaries with
  `PE file does not contain any managed metadata`.

**Conclusion: there are no .NET assemblies anywhere in this product.** The
installer shell and helper DLLs are plain C/C++ (MSVC 14.36); the plugin
binaries are native x86-64 C++ (JUCE-based, MSVC). `decompiled/csharp/` is
empty by design.

## 4. The actual product: plugin binaries + presets (from CAB)

`Archetype Plini X1.cab` (MSZip, 1 block) contains 195 files (353.7 MiB):

| File                          | Size (B)  | Format | Role |
|-------------------------------|-----------|--------|------|
| `ArchetypePlini.exe`          | 91,211,592 | PE32+ x64 GUI | Standalone application |
| `ArchetypePlini.dll`          | 91,809,608 | PE32+ x64 DLL | VST2 plugin |
| `ArchetypePliniX.vst3`        | 92,102,472 | PE32+ x64 DLL | VST3 plugin |
| `ArchetypePliniX.aaxplugin`   | 91,975,496 | PE32+ x64 DLL | AAX plugin (Pro Tools) |
| `ArchetypePliniXv1.0.0.pdf`   |  3,037,771 | PDF          | User manual |
| `Plugin.ico`                  |     30,838 | ICO          | Plugin icon |
| 189 × `*.xml`                 | ~3,600 ea  | Custom XML   | Factory/artist presets |

### Plugin binary architecture (ArchetypePlini.exe, 17 sections)
PE32+ x86-64, ImageBase 0x140000000, MSVC. Notable sections:
- `.text` (35 MB) — main code
- **`IPPCODE`** / **`IPPDATA`** — Intel Integrated Performance Primitives
  (DSP acceleration; static-linked IPP code + data). Confirms heavy DSP.
- **`.mfrt`** — virtual size 0x4fce000 (~80 MB) but only 0x800 raw →
  memory-mapped / runtime-populated model region.
- **`.proxy`** (0x154000 raw) — embeds a full x86-64 PE (6 std sections);
  the **PACE/iLok license proxy**.
- **`.guard`** (0x760800 raw ≈ 7.5 MB) — PACE anti-tamper / obfuscated code.
- `.text001`/`.rdata01`/...`01` — a second linked binary (the PACE wrapper).

### Licensing / DRM: PACE Anti-Piracy iLok
Strings confirm **PACE InterLok / iLok** (NOT Themida):
- `PaceException@pace` (boost-mangled C++ class)
- `algorithmIdIlok1`, `algorithmIdIlok2`, `accountIlokActivations`
- "Access to the iLok License Server requires a valid password"
- "A PACE code signing certificate was found on your iLok …"
- AES-128 license blob crypto (`aes128`).
The plugin requires an iLok USB dongle or machine license; the `.proxy`
section is the PACE-wrapped license mediator that decrypts the runtime model
data.

### DSP / ML framework (from strings)
- **JUCE** framework (Steinberg ASIO/VST3/AAX integration strings).
- **Intel IPP** (IPPCODE/IPPDATA sections) — vectorised DSP.
- **GRU neural networks** — string `GRU` + model-path XML referencing
  amp/cab models; architecture is RTNeural-style recurrent nets for
  amp/cabinet emulation. Model weights are encrypted by PACE and only
  decrypted in-memory at runtime (hence the 80 MB virtual `.mfrt`).
- Internal parameter model (from `archetypeAppModel.xml`):
  - `ampParameters`: cleanAmp / crunchAmp / leadAmp (3 amp models)
  - `cabParameters`: cabinet simulation
  - `eqParameters`: cleanEQ / crunchEQ / leadEQ (9-band each)
  - `pedalParameters`: compressor / drive / octaver / preDelay
  - `fxParameters`: chorus / delay / reverb
  - tunerParameters / metronomeParameters

### Preset XML format (custom, not standard XML)
Presets are a **flat key-value serialization** (space-separated, not
angle-bracket XML despite the `.xml` extension). Header:
`plini-X version 1.0.1 name <PresetName> isFavorite <bool> appModel`
followed by nested `subModels` blocks with normalised float parameters
(0..1) and named controls (e.g. `leadAmpGain 0.513372`, `leadAmpBright true`,
`cleanEQLpf 20000`, `gateThreshold -56.0025`).

## 5. MSI install manifest (msitools export)

- **ProductCode**   = `{CCD20C13-43D6-47A4-9164-21D010D6E885}`
- **UpgradeCode**    = `{271A5832-EEFD-46E5-9258-166ED97F25D3}`
- **ProductVersion** = `1.0.2`, ProductLanguage `1033` (en-US)
- **Manufacturer**   = `Neural DSP`, ProductName `Archetype Plini X`

### Features (installable groups)
| Feature     | Title      | Install dir | Components |
|-------------|------------|-------------|------------|
| MainFeature | Standalone | APPDIR      | exe, shortcut, ProductInfo |
| AAX         | AAX        | AAXDIR      | aaxplugin |
| VST         | VST        | VSTDIR      | VST2 dll |
| VST3        | VST3       | VST3DIR     | vst3 |
| PRESETS     | PRESETS    | PREDIR      | 189 preset XMLs + User dir |
| MANUAL      | MANUAL     | APPDIR      | PDF |

### Install directories (Directory table)
- `APPDIR`   → `[ProgramFiles]…\Archetype Plini X`
- `VSTDIR`   → `C:\Program Files\Common Files\VST`  (VST2)
- `VST3DIR`  → `C:\Program Files\Common Files\VST3`
- `AAXDIR`   → `C:\Program Files\Common Files\Avid\Audio\Plug-Ins`
- `PREDIR`   → `C:\ProgramData\Neural DSP\Archetype Plini X` (factory presets)
  with `Artists\` subfolders (Mike Dawes, Jack Gardiner, Rabea Massaad, …)
  and `Plini\`, `User\`, `Neural DSP\` (Factory) subdirs.

### Custom actions (driving the SFX extraction)
- `AI_ExtractLzma` → `lzmaextractor.dll!ExtractLZMAFiles` (type 1025 = DLL+CA)
- `AI_FindExeLzma` → `lzmaextractor.dll!FindEXE`
- `AI_ExtractFiles` → `Prereq.dll!ExtractSourceFiles`
- `AI_DeleteLzma` / `AI_DeleteRLzma` → cleanup
- `AI_DpiContentScale`, `AI_Detect_MODERNWIN`, `AI_PREPARE_UPGRADE`, etc.
  → `AICustAct.dll` various

### Launch conditions
- Requires Windows NT ≥ 6.x (rejects 9x/NT4/2000/XP/2003).
- `SETUPEXEDIR OR (REMOVE="ALL")` — "This package can only be run from a
  bootstrapper" (the MSI is not directly runnable).

## 5b. Neural model weight extraction — NOT POSSIBLE from static binary

The user asked whether the GRU model weights can be extracted from the
plugin binary directly. **They cannot.** Proven by section analysis:

| Section | Raw size | Entropy | Float-density | Verdict |
|---------|----------|---------|---------------|---------|
| `.mfrt` | 0x800 | **0.073** | n/a (zeros) | 16-byte header + 2KB zeros; 80 MB is **virtual reservation only** — weights loaded at runtime |
| `.guard` | 0x760800 | 7.090 | 0% | Embeds a **PACE PE** (MZ+DOS stub at +8); encrypted anti-tamper code |
| `.data` | 0xcc000 | 7.997 | 0% | PACE-encrypted runtime data |
| `IPPCODE` | 0x9b800 | 7.997 | 0% | Packed/encrypted IPP code |
| `.rdata` | 0x298e000 | 3.078 | 1.8% | Plaintext: processor registry, model XML defs, strings — **architecture only** |

The 3 GRU model IDs (`Plini_{Clean,Crunch,Lead}EnergyNormNoBias_Poweramp_Processor_GRU`)
at file offsets `0x49b1a30`/`0x49b18a8`/etc sit inside a **C++ type-registry
string table** (adjacent to `Fixed Tube Processor`, `gain_processor`,
`TST01 Processor`) — they are RTTI/registration names, **not** weight blobs.

**Architecture IS recoverable** (plaintext in `.rdata`):
- 3 GRU poweramp models (EnergyNormNoBias topology — see topology notes below)
- 3 preamp processors (clean/crunch/lead) + `fixed_tube_processor`
- Cab sim (IR-based), pedals (comp/dist/mod/stomp_delay), FX (Chorus 2290, Reverb, FDN)
- Full MVC model XML hierarchy (`archetypeAppModel.xml` → `*ParametersModel.xml`)

**Inferred GRU topology** (from the `Plini_*EnergyNormNoBias_Poweramp_Processor_GRU`
registry names — a naming convention, not weight data):
- **GRU** = gated recurrent unit (3 gates: reset/update/candidate, vs an LSTM's 4).
- **EnergyNorm** = input is normalised by its energy before the recurrent core, a
  known technique to make a recurrent amp model gain-independent / output-stable
  across input levels. Equivalent function to NAM's per-file `metadata.loudness` /
  `input_level_dbu`, but applied *inside* the network rather than as file metadata.
- **NoBias** = the bias terms on the GRU gates are dropped, reducing parameters and
  regularising the model.

The internal weight layout is therefore almost certainly the standard recurrent
-model pattern — a flat `float32` array consumed in order as
`[W_gru (3 gates × (in+hidden)), initial_hidden, head_W, (head_b)]`, with the bias
slot omitted per the `NoBias` suffix. (We document the *shape* only; the actual
values are not recovered — see below.)

**Weights are NOT recoverable** — they are PACE/iLok-encrypted in `.guard`/`.data`,
decrypted at runtime into the virtual `.mfrt` region. Extraction would require
memory-dumping a licensed running instance (out of scope).

## 6. Status / next steps
- [x] PE structure mapped
- [x] Overlay / SFX identified and extracted (Wine /extract)
- [x] .NET claim debunked
- [x] Embedded helper DLLs extracted & identified (Caphyon AI runtime)
- [x] MSI + CAB extracted; 195 files unpacked
- [x] Plugin binaries characterised (JUCE + IPP + PACE/iLok + GRU models)
- [x] MSI install manifest exported (msitools)
- [ ] Native decompilation of the stub (Ghidra, pending PyGhidra) — low value;
      the stub is generic Caphyon AI bootstrapper, not Neural DSP IP.
- [ ] Deeper native analysis of `ArchetypePlini.exe` DSP — blocked by PACE
      obfuscation of model weights; code is reachable but weights are
      runtime-decrypted. Would require a licensed, running instance.

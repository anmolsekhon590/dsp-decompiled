# Extracted payload

Contents of the Advanced Installer SFX overlay, recovered by running the
bootstrapper's own `/extract` flag under Wine:

```
wine "Archetype Plini X v1.0.2.exe" /extractlzma /extract
```

→ `%APPDATA%\Neural DSP\Archetype Plini X 1.0.2\install\`

## Files (do not commit the binaries/presets — see ../LICENSE)

- `Archetype Plini X.msi`  (1,815,040 B)  — Windows Installer package (OLE2)
- `Archetype Plini X1.cab` (323,463,388 B) — MSZip cabinet, 195 files, 353.7 MiB unpacked
- `cab_contents/` — unpacked CAB (the actual plugin + presets)

### cab_contents/

| File | Size | Type |
|------|------|------|
| `ArchetypePlini.exe`        | 91,211,592 | PE32+ x64 GUI  — standalone app |
| `ArchetypePlini.dll`        | 91,809,608 | PE32+ x64 DLL  — VST2 |
| `ArchetypePliniX.vst3`      | 92,102,472 | PE32+ x64 DLL  — VST3 |
| `ArchetypePliniX.aaxplugin` | 91,975,496 | PE32+ x64 DLL  — AAX (Pro Tools) |
| `ArchetypePliniXv1.0.0.pdf` |  3,037,771 | PDF — user manual |
| `Plugin.ico`                |     30,838 | ICO |
| 189 × `*.xml`               | ~3,600 ea  | custom preset format |

All four plugin binaries are **native x86-64 C++** (JUCE + Intel IPP), with
**PACE/iLok** DRM (`.proxy`/`.guard` sections) and **GRU** neural amp/cab
models (weights runtime-decrypted into the 80 MB virtual `.mfrt` region).

The MSI install manifest (ProductCode `{CCD20C13-43D6-47A4-9164-21D010D6E885}`,
UpgradeCode `{271A5832-EEFD-46E5-9258-166ED97F25D3}`, version 1.0.2) installs
into `Program Files\Archetype Plini X` + `Common Files\{VST,VST3,Avid\…}`
+ `ProgramData\Neural DSP\Archetype Plini X` (presets). See
`../decompiled/PROGRESS.md` §5 for the full table export.

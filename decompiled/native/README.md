# Native analysis (stub + helper DLLs)

The installer stub (`Archetype Plini X v1.0.2.exe`, PE32 i386) and the three
embedded helper DLLs are **generic Advanced Installer (Caphyon) v20.9.1
runtime** — not Neural DSP proprietary code. They are plain C++ (MSVC 14.36),
native, with no .NET metadata.

## Carved helper DLLs (in `../embedded/`)
- `AICustAct.dll`     — 73 exported MSI custom actions (DetectModernWindows,
  UpdateInstallMode, LaunchLogFile, EnableDebugLog, DpiContentScale, …).
- `lzmaextractor.dll` — 5 exports (ExtractLZMAFiles, DeleteLZMAFiles, FindEXE,
  ExpandExtractionPath, DeleteExtractionPath). Decodes the SFX's custom-framed
  LZMA payload.
- `Prereq.dll`        — 12 exports (InstallPrereq, DownloadPrereq, …) for
  feature-based prerequisite installation.

## Ghidra
`analysis/DecompExport.py` is a PyGhidra headless post-script that decompiles
named exports. The bundled Ghidra 26.03 dropped bundled Jython; run with
`pyghidraRun` or install the PyGhidra extension (`pip install --user
pyghidra`, then set `GHIDRA_INSTALL_DIR=/opt/ghidra`).

Because these DLLs are Caphyon's off-the-shelf runtime rather than Neural DSP
IP, native decompilation here is low-value and not pursued further.

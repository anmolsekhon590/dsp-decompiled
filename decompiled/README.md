# decompiled/ — reverse-engineering artefacts

This directory holds the analysis output for the installer shell and embedded
helpers. The main project documentation lives in the [top-level `README.md`](../README.md);
the chronological findings log is [`PROGRESS.md`](PROGRESS.md).

## Subdirectories

| Path | Contents |
|------|----------|
| `embedded/` | The 3 Caphyon Advanced Installer helper DLLs carved from the SFX overlay (`AICustAct.dll`, `lzmaextractor.dll`, `Prereq.dll`) + export lists. |
| `analysis/` | Ghidra headless decompile-export script (`DecompExport.py`, PyGhidra). |
| `pe_resources/` | 7z-extracted PE sections + `.rsrc/` tree (bitmaps, icons, dialogs, XAML theme, manifest, version info) from the stub. |
| `native/` | Notes on the native stub + helper DLLs (generic Caphyon runtime, not Neural DSP IP). |
| `csharp/` | **Empty by design** — there is no .NET anywhere in this product (see PROGRESS §3). |
| `resources/` | Notes on the PE `.rsrc` resources. |

## Key takeaways

- The stub is a **PE32 i386 Advanced Installer 20.9.1 SFX bootstrapper** (Caphyon),
  not Neural DSP code, and not .NET.
- The 3 embedded DLLs are Caphyon's generic installer runtime (custom actions,
  LZMA extraction, prerequisite install).
- The actual plugin (JUCE + Intel IPP + GRU neural amps, PACE/iLok DRM) lives in
  `../extracted_payload/cab_contents/` — see that dir's README and PROGRESS §4–5b.

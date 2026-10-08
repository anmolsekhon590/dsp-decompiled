# C# / .NET decompilation — NONE

This directory is intentionally **empty**.

The original analysis brief hypothesised embedded .NET assemblies
("metadata streams #~, #- present"). That was a false positive: the `23 7e 00`
byte patterns binwalk/strings matched are coincidental bytes inside the
high-entropy LZMA-compressed overlay, not real .NET metadata streams.

Evidence that there is **no .NET anywhere** in this product:
- PE CLR/COM descriptor (DataDirectory[14]) = 0 in the stub and all 4 plugins.
- `BSJB` (.NET metadata root signature): 0 occurrences in the whole file.
- `ilspycmd` rejects all 5 native PEs with "PE file does not contain any
  managed metadata".

The installer shell, the 3 Caphyon helper DLLs, and all 4 Neural DSP plugin
binaries are **native C/C++** (stub/helpers: x86 MSVC; plugins: x86-64 JUCE+IPP).

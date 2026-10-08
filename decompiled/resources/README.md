# Resources (PE .rsrc) — extracted to ../pe_resources/.rsrc/

7z cleanly extracted every RT_* resource from the stub's `.rsrc` section.
Catalogue:

| RT type       | Count | Contents |
|---------------|-------|----------|
| RT_BITMAP     | 6     | installer UI bitmaps |
| RT_ICON       | 5     | app icon set (multiple sizes) |
| RT_DIALOG     | 5     | installer dialogs (201/216/225/2000/10123) |
| RT_STRING     | 15    | string tables (button text, prompts) |
| RT_GROUP_ICON | 1     | icon group (128) |
| RT_VERSION    | 1     | version info |
| RT_HTML       | 9     | **WPF XAML** templates (ControlTemplate/Style/Button/ComboBox) — the Advanced Installer theme |
| RT_MANIFEST   | 1     | Common Controls v6 manifest |

Also in `.rdata`: a small `stopexecseq.mst` CAB at file offset `0x29bc00`
(902 B, MSZip) — the MSI stop-execution-sequence transform.

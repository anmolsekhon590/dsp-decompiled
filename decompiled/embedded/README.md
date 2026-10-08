# Embedded helper DLLs (carved from the SFX overlay)

Three PE32 i386 DLLs are embedded in the stub's overlay and extracted to this
directory by `../../extract_embedded_pe.py`. They are **Caphyon Advanced
Installer v20.9.1 runtime** (not Neural DSP code, not .NET).

| Carved file                       | Original name      | Offset   | Size     | Exports |
|-----------------------------------|--------------------|----------|----------|---------|
| embedded_pe1_at_0x38a200.exe      | AICustAct.dll      | 0x38a200 | 586,752  | 73      |
| embedded_pe2_at_0x423400.exe      | lzmaextractor.dll  | 0x423400 | 7,168    | 5       |
| embedded_pe3_at_0x42fe00.exe       | Prereq.dll         | 0x42fe00 | 738,304  | 12      |

## Export lists

### AICustAct.dll (73)
AI_AuthorSinglePackage, AI_ResolveKnownFolders, AI_SearchOfficeAddins,
AddCaspolSecurityPolicy, BrowseForFile, CheckFreeTCPPort, CheckIfUserExists,
ChooseTextStyles, CloseApplication, CollectFeaturesWithoutCab,
ComputeReplaceProductsList, ConfigureNonAdminServiceStart,
ConfigureServFailActions, CopyFileFolder, CreateExeProcess,
DeleteEmptyDirectory, DeleteFromCheckList, DeleteFromComboBox,
DeleteFromListBox, DeleteFromListView, DeleteShortcuts, DetectModernWindows,
DetectProcess, DetectService, DetectWindowsTheme, DisableFeatures, DoEvents,
DpiContentScale, EnableDebugLog, EnumStartedServices, ExtractCheckListData,
ExtractComboBoxData, ExtractListBoxData, ExtractListViewData, GetArpIconPath,
GetFreeTCPPort, GetLocalizedCredentials, GetPathFreeSpace,
InstanceMajorUpgrade, JoinFiles, LaunchApp, LaunchLogFile, LoadShortcutDirs,
LogOnAsAService, MixedAllUsersInstallLocation, MsgBox, MsmTrialMessage,
PerformRegistryEntryTypeChange, PlayAudioFile, PopulateCheckList,
PopulateComboBox, PopulateListBox, PopulateListView,
PrepareRegistryEntryTypeChange, PrepareUpgrade, PreserveInstallType,
PreventInstancesUpgrade, PrintRTF, ProcessFailActions, RegisterAdvinstCom,
RemoveCaspolSecurityPolicy, ResolveFormattedProperty, ResolveKnownFolder,
ResolveServiceProperties, RestartElevated, RestoreLocation, RunAllExitActions,
RunFinishActions, SendPropertyToUI, SetLatestVersionPath, StartWinService,
StopProcess, StopWinService, TrialMessage, UninstallPreviousVersions,
UnregisterAdvinstCom, UpdateFeatureStates, UpdateInstallMode,
UpdateMsiEditControls, ValidateInstallFolder, ViewReadMe, WarningMessageBox.

### lzmaextractor.dll (5)
DeleteExtractionPath, DeleteLZMAFiles, ExpandExtractionPath, ExtractLZMAFiles,
FindEXE.

### Prereq.dll (12)
CleanPrereq, ConfigurePrereqLauncher, DoAppSearchEx, DownloadPrereq,
ExtractPrereq, ExtractSourceFiles, InstallPostPrereq, InstallPrePrereq,
InstallPrereq, RollbackPrePrereq, RollbackPrereq, VerifyPrePrereq,
VerifyPrereq.

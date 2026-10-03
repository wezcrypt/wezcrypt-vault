; Inno Setup 6 script for WezCrypt Vault.
;
; Built by scripts\build_release.ps1, which passes the version from wezcrypt_vault/version.py:
;   ISCC.exe /DAppVersion=1.1.0 /DSourceExe=..\dist\WezCryptVault.exe /DOutputDir=..\dist packaging\WezCryptVault.iss
; Optional Authenticode signing (no certificate is ever bundled):
;   ISCC.exe ... /DSignEnabled "/Swezsign=signtool.exe sign /fd sha256 /tr <timestamp-url> /td sha256 ... $f"
;
; Program files go to C:\Program Files\WezCrypt Vault (per-machine; the user may choose a per-user install).
; Mutable user data lives in %LOCALAPPDATA%\WezCryptVault and is NEVER written or replaced by the
; installer, so upgrades preserve the database, settings, trusted SSH fingerprints and logs.
; Credential Manager entries (master key, SSH secrets) are never touched by install, upgrade or uninstall.

#ifndef AppVersion
  #error AppVersion is required: ISCC /DAppVersion=x.y.z
#endif
#ifndef SourceExe
  #define SourceExe "..\dist\WezCryptVault.exe"
#endif
#ifndef OutputDir
  #define OutputDir "..\dist"
#endif

#define AppName "WezCrypt Vault"
#define AppPublisher "wezcrypt"
#define AppURL "https://wezcrypt.com"
#define AppRepo "https://github.com/wezcrypt/wezcrypt-vault"
#define AppExe "WezCryptVault.exe"
#define AppDescription "Secure Client-Side Encrypted File Storage"
#define UserDataDir "WezCryptVault"

[Setup]
; Fixed AppId: every version upgrades the same installation in place.
AppId={{5B1F7C2E-8E4A-4D1B-9C61-2F0A6E9B3D47}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppRepo}
AppUpdatesURL={#AppRepo}/releases
AppCopyright=Copyright (C) 2026 {#AppPublisher}
AppComments={#AppDescription}
VersionInfoVersion={#AppVersion}.0
VersionInfoProductVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} Setup
VersionInfoCompany={#AppPublisher}
VersionInfoCopyright=Copyright (C) 2026 {#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
DisableDirPage=auto
UsePreviousAppDir=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir={#OutputDir}
OutputBaseFilename=WezCryptVault-Setup-{#AppVersion}
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
CloseApplicationsFilter={#AppExe}
RestartApplications=no
ShowLanguageDialog=no
#ifdef SignEnabled
SignTool=wezsign
SignedUninstaller=yes
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create Desktop Shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#SourceExe}"; DestDir: "{app}"; DestName: "{#AppExe}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\SECURITY.md"; DestDir: "{app}"; Flags: ignoreversion
; Intentionally NO user data, databases, config.toml, keys or credentials are packaged.

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; Comment: "{#AppDescription}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Comment: "{#AppDescription}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Only files the installer itself may have created inside {app}. User data is handled in [Code].
Type: filesandordirs; Name: "{app}\__pycache__"

[Code]
function UserDataPath(): String;
begin
  Result := ExpandConstant('{localappdata}\{#UserDataDir}');
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Path: String;
begin
  if CurUninstallStep <> usPostUninstall then
    exit;
  Path := UserDataPath();
  { Silent uninstalls (e.g. upgrades driven by tools) never remove user data. }
  if UninstallSilent() or (not DirExists(Path)) then
    exit;
  if MsgBox('WezCrypt Vault has been removed.' + #13#10#13#10 +
            'Do you ALSO want to remove your local application data?' + #13#10 +
            Path + #13#10#13#10 +
            'This deletes the local file registry (original filenames and File IDs), settings, ' +
            'trusted SSH fingerprints and logs. Encrypted files on your server are not affected. ' +
            'Master key and SSH secrets in Windows Credential Manager are NOT removed.' + #13#10#13#10 +
            'Choose No to keep your data for a future reinstall (recommended).',
            mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
  begin
    if MsgBox('Are you sure? Without the local registry you will need the File IDs to download ' +
              'your files again.', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DelTree(Path, True, True, True);
  end;
end;

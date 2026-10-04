; Inno Setup script for the OffsecHub Windows installer.
;
;   iscc /DAppVersion=0.2.0 packaging\windows\offsechub.iss
;
; Packs the PyInstaller bundle (dist\OffsecHub, from packaging\build.ps1) into
; dist\offsechub-setup-<version>.exe. If build\MicrosoftEdgeWebview2Setup.exe
; exists it is embedded and run when the WebView2 Runtime is missing.
;
; Installs per user (no administrator rights) by default; choosing "all users"
; installs into Program Files. Uninstalling never touches vaults or settings.
;
; Signed builds: iscc /DSign "/Ssigntool=<signtool command> $f" ... signs
; Setup.exe and the uninstaller (packaging\build.ps1 does this).

#ifndef AppVersion
  #error Pass the version: iscc /DAppVersion=x.y.z offsechub.iss
#endif
#define AppName "OffsecHub"
#define AppExe "offsechub.exe"
#define Root AddBackslash(SourcePath) + "..\.."
#define Bundle Root + "\dist\OffsecHub"
#define WebView2Setup Root + "\build\MicrosoftEdgeWebview2Setup.exe"

[Setup]
AppId={{8B5F1C2E-4A7D-4E59-9C3B-2F6D1E8A7C41}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppName}
AppPublisherURL=https://github.com/ajfan6T/offsechub
AppSupportURL=https://github.com/ajfan6T/offsechub/issues
AppUpdatesURL=https://github.com/ajfan6T/offsechub/releases
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} setup
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Windows 10 1809 or later (WebView2 and the TLS/crypto the bundle expects).
MinVersion=10.0.17763
OutputDir={#Root}\dist
OutputBaseFilename=offsechub-setup-{#AppVersion}
SetupIconFile={#Root}\packaging\icons\offsechub.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
ChangesEnvironment=yes
#ifdef Sign
; build.ps1 passes the "signtool" command (/Ssigntool=...) when signing is set up.
SignTool=signtool
SignedUninstaller=yes
#endif
; Closes a running OffsecHub through the Restart Manager: the window gets a
; normal close, so the vault is saved and locked first.
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addtopath"; Description: "Add offsechub-cli to PATH, for imports from a terminal"; GroupDescription: "Command line:"; Flags: unchecked

[Files]
Source: "{#Bundle}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
#if FileExists(WebView2Setup)
Source: "{#WebView2Setup}"; DestDir: "{tmp}"; Flags: deleteafterinstall; Check: NeedsWebView2
#endif

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"; Comment: "Encrypted workspace for penetration testing engagements"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
#if FileExists(WebView2Setup)
Filename: "{tmp}\MicrosoftEdgeWebview2Setup.exe"; Parameters: "/silent /install"; StatusMsg: "Installing the Microsoft Edge WebView2 Runtime..."; Check: NeedsWebView2; Flags: waituntilterminated
#endif
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[Code]
const
  WebView2Key = 'Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}';
  UserEnvKey = 'Environment';
  MachineEnvKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

{ The WebView2 Runtime registers its version ("pv") per machine or per user. }
function HasWebView2(Root: Integer; Key: String): Boolean;
var
  Version: String;
begin
  Result := RegQueryStringValue(Root, Key, 'pv', Version) and (Version <> '') and (Version <> '0.0.0.0');
end;

function NeedsWebView2(): Boolean;
begin
  Result := not (HasWebView2(HKLM, 'SOFTWARE\WOW6432Node\' + WebView2Key)
    or HasWebView2(HKLM, 'SOFTWARE\' + WebView2Key)
    or HasWebView2(HKCU, 'Software\' + WebView2Key));
end;

function EnvRoot(): Integer;
begin
  if IsAdminInstallMode then Result := HKLM else Result := HKCU;
end;

function EnvKey(): String;
begin
  if IsAdminInstallMode then Result := MachineEnvKey else Result := UserEnvKey;
end;

{ PATH without Dir (compared case-insensitively), entries otherwise unchanged. }
function PathWithout(Paths, Dir: String): String;
var
  Item: String;
  I: Integer;
begin
  Result := '';
  Paths := Paths + ';';
  while Paths <> '' do
  begin
    I := Pos(';', Paths);
    Item := Copy(Paths, 1, I - 1);
    Delete(Paths, 1, I);
    if (Item <> '') and (CompareText(RemoveBackslashUnlessRoot(Item), RemoveBackslashUnlessRoot(Dir)) <> 0) then
    begin
      if Result <> '' then Result := Result + ';';
      Result := Result + Item;
    end;
  end;
end;

procedure AddToPath(Dir: String);
var
  Paths: String;
begin
  if not RegQueryStringValue(EnvRoot, EnvKey, 'Path', Paths) then Paths := '';
  Paths := PathWithout(Paths, Dir);
  if Paths <> '' then Paths := Paths + ';';
  RegWriteExpandStringValue(EnvRoot, EnvKey, 'Path', Paths + Dir);
end;

procedure RemoveFromPath(Dir: String);
var
  Paths: String;
begin
  if RegQueryStringValue(EnvRoot, EnvKey, 'Path', Paths) then
    RegWriteExpandStringValue(EnvRoot, EnvKey, 'Path', PathWithout(Paths, Dir));
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('addtopath') then
    AddToPath(ExpandConstant('{app}'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}'));
end;

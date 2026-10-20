; Inno Setup script for RV HashInv (Python build; built by .github/workflows/release.yml).
; Installs the Nuitka standalone folder dist\rv-hashinv. Per-user install: no administrator rights needed.
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\.."
#endif

[Setup]
AppId={{9A41C2D7-3E58-4F0B-8C6A-5D2E7B1F4A93}
AppName=RV HashInv
AppVersion={#AppVersion}
AppPublisher=Rakvor
AppPublisherURL=https://github.com/rakvor/rv-hashinv
DefaultDirName={localappdata}\Programs\Rakvor\RV HashInv
DefaultGroupName=Rakvor
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
LicenseFile={#SourceDir}\LICENSE
OutputBaseFilename=rv-hashinv-{#AppVersion}-windows-x64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ChangesEnvironment=yes
UninstallDisplayIcon={app}\rv-hashinv-gui.exe

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "fr"; MessagesFile: "compiler:Languages\French.isl"

[Tasks]
Name: "addtopath"; Description: "Add the rv-hashinv command to PATH"; Flags: checkedonce
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; Flags: unchecked

[Files]
; The whole standalone folder: both executables, the shared Python runtime, Qt DLLs (LGPL, replaceable), docs, examples.
Source: "{#SourceDir}\dist\rv-hashinv\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\RV HashInv"; Filename: "{app}\rv-hashinv-gui.exe"
Name: "{group}\RV HashInv documentation"; Filename: "{app}\docs"
Name: "{autodesktop}\RV HashInv"; Filename: "{app}\rv-hashinv-gui.exe"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsAddPath(ExpandConstant('{app}'))

[Run]
Filename: "{app}\rv-hashinv-gui.exe"; Description: "Start RV HashInv"; Flags: nowait postinstall skipifsilent

[Code]
function NeedsAddPath(Dir: string): Boolean;
var
  Paths: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, 'Environment', 'Path', Paths) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Paths) + ';') = 0;
end;

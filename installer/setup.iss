; SecureVault - Script Inno Setup
; Copie l'exe dans Program Files, enregistre le menu contextuel Windows et
; l'association .securevault à l'installation, nettoie le registre avant
; désinstallation.

#define MyAppName "SecureVault"
#define MyAppVersion "1.0.3"
#define MyAppPublisher "SecureVault"
#define MyAppExeName "securevault.exe"

[Setup]
AppId={{B3B6B6C0-9F1E-4A3D-8C2E-2F6E7B1B7A10}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=Output
OutputBaseFilename=SecureVault_Setup
ArchitecturesInstallIn64BitMode=x64compatible
WizardStyle=modern
DisableProgramGroupPage=yes
LicenseFile=license.txt
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma
SolidCompression=yes

; Note : seul l'anglais est référencé ci-dessous car c'est la seule langue
; garantie présente avec une installation par défaut d'Inno Setup (French.isl
; est un composant optionnel séparé). Pour ajouter le français, installe ce
; composant depuis Inno Setup puis ajoute une section [Languages] avec
; `Name: "french"; MessagesFile: "compiler:Languages\French.isl"`.
[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel2=Ceci va installer [name/ver] sur cet ordinateur.%n%nSecureVault ajoute au menu contextuel de l'Explorateur Windows deux modes de protection pour vos fichiers et dossiers : un verrouillage rapide (permissions NTFS) et un chiffrement fort (AES-256-GCM).%n%nIl est recommandé de fermer les autres applications avant de continuer.

[Files]
Source: "..\target\release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\docs\guide.html"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Désinstaller {#MyAppName}"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "install"; Flags: runascurrentuser; StatusMsg: "Enregistrement du menu contextuel..."

[UninstallRun]
; Les entrées [UninstallRun] s'exécutent avant la suppression des fichiers,
; donc {#MyAppExeName} existe encore ici.
Filename: "{app}\{#MyAppExeName}"; Parameters: "uninstall"; Flags: runascurrentuser; RunOnceId: "SecureVaultUninstall"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

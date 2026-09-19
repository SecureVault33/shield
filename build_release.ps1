# Compile SecureVault en mode release, PUIS génère l'installeur Inno Setup
# (comme SecureVault_Setup_0.1.0.exe) et l'archive sous versions\ avec le
# numéro de version.
#
# Pourquoi l'installeur et pas juste le binaire brut : double-cliquer sur
# securevault.exe seul ne fait rien d'utile (c'est un outil en ligne de
# commande, sans argument il n'y a rien à exécuter) et n'enregistre ni le
# menu contextuel de l'Explorateur ni l'association .securevault. Seul
# l'installeur fait une "installe propre" (copie dans Program Files +
# `securevault.exe install` lancé automatiquement).
#
# Prérequis : Inno Setup installé (https://jrsoftware.org/isdl.php) — voir
# installer/BUILD.md.
#
# Usage : .\build_release.ps1

$ErrorActionPreference = "Stop"

# Compile en release
cargo build --release
if ($LASTEXITCODE -ne 0) {
    Write-Error "cargo build --release a échoué (code $LASTEXITCODE)."
    exit $LASTEXITCODE
}

# Localise le compilateur Inno Setup (ISCC.exe) : d'abord sur le PATH, sinon
# dans les emplacements d'installation standards.
$isccCommand = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue
if ($isccCommand) {
    $isccPath = $isccCommand.Source
} else {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
    )
    $isccPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $isccPath) {
        Write-Error "ISCC.exe introuvable. Installe Inno Setup (https://jrsoftware.org/isdl.php) puis relance ce script."
        exit 1
    }
}

# Compile l'installeur (produit installer\Output\SecureVault_Setup.exe)
& $isccPath "installer\setup.iss"
if ($LASTEXITCODE -ne 0) {
    Write-Error "La compilation Inno Setup a échoué (code $LASTEXITCODE)."
    exit $LASTEXITCODE
}

# Numéro de version, lu depuis Cargo.toml (ex: "0.1.0")
$cargoToml = Get-Content "Cargo.toml" -Raw
$version = "unknown"
if ($cargoToml -match '(?m)^\s*version\s*=\s*"([^"]+)"') {
    $version = $Matches[1]
}

# Crée le dossier versions s'il n'existe pas
New-Item -ItemType Directory -Force -Path "versions" | Out-Null

# Copie l'installeur généré, nommé avec le numéro de version
$dest = "versions\SecureVault_Setup_$version.exe"
Copy-Item "installer\Output\SecureVault_Setup.exe" $dest -Force

Write-Host "Installeur copié dans : $dest"

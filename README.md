# SecureVault — version gratuite (code source)

Outil léger pour Windows 10/11 qui protège fichiers et dossiers depuis le menu
contextuel de l'Explorateur (clic droit), avec un Centre d'administration pour
tout piloter.

Ce dépôt contient le code source **open source** de la **version gratuite** de
SecureVault, publié sous licence [MIT](LICENSE). L'activation de SecureVault
Pro n'en fait pas partie.

## Deux modes de protection

- **Accès Rapide** (`src/acl/`) : permissions NTFS restrictives (DACL
  protégée) ; l'élément reste visible dans l'Explorateur mais ne s'ouvre plus.
  La DACL d'origine est sauvegardée chiffrée dans un flux alternatif (ADS).
- **Chiffrement Fort** (`src/crypto/`) : AES-256-GCM, clé dérivée du mot de
  passe par Argon2id (m = 64 Mio, t = 3, p = 4). Format `.vault` à double
  enveloppe : une clé de fichier aléatoire, chiffrée à la fois par le mot de
  passe et par une recovery key, chacun des deux suffisant pour déchiffrer.

## Version gratuite

- 20 verrouillages et 3 chiffrements.
- Déverrouiller, déchiffrer, exporter ses recovery keys et forcer le
  déverrouillage restent **toujours gratuits et illimités**.

## Compiler

Prérequis : [Rust](https://rustup.rs/) (cible `x86_64-pc-windows-msvc`).

```
cargo build --release
cargo test --release -- --test-threads=1
```

Les tests doivent tourner sur un seul thread : certains partagent des
fichiers sous `%LOCALAPPDATA%\SecureVault` (sauvegardés puis restaurés).

L'installeur (Inno Setup 6) se génère avec `.\build_release.ps1` — voir
[installer/BUILD.md](installer/BUILD.md).

## Structure

- `src/acl/` — mode Accès Rapide (DACL, ADS, fichier compagnon `.securevault`)
- `src/crypto/` — mode Chiffrement Fort (AES-256-GCM, Argon2id, recovery key)
- `src/dashboard/` — Centre d'administration, registre des éléments protégés,
  Master Password, déverrouillage forcé
- `src/ui/` — popups Win32/GDI (thème sombre)
- `src/registry/` — menu contextuel Windows et icônes
- `src/license/` — compteurs de la version gratuite
- `docs/guide.html` — guide utilisateur

## Licence

[MIT](LICENSE) — © 2026 SecureVault33.

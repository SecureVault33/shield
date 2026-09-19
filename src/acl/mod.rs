mod permissions;

use crate::errors::{Result, SecureVaultError};
use std::path::Path;

pub use permissions::is_locked;

/// Vérifie un mot de passe candidat pour une cible verrouillée SANS la
/// déverrouiller réellement. Utilisée par la popup de saisie pour un nouvel
/// essai sur place (voir `ui::show_password_prompt` et
/// `permissions::verify_password` pour le détail).
pub fn verify_password(target: &Path, password: &str) -> Result<bool> {
    permissions::verify_password(target, password)
}

/// Verrouille un fichier/dossier via modification des permissions NTFS (ACL).
/// Vérifie d'abord l'état (déjà verrouillé ?).
///
/// Pas d'élévation UAC : le propriétaire d'un fichier peut toujours modifier
/// sa propre DACL (droit `WRITE_DAC` implicite au propriétaire, indépendant
/// du niveau d'élévation du process), donc le process courant — avec le
/// jeton de l'utilisateur qui l'a lancé — suffit. Si la cible appartient à un
/// autre utilisateur ou nécessite réellement des droits administrateur
/// (fichier système, etc.), l'appel Win32 sous-jacent échoue et l'erreur
/// remonte clairement (voir `permissions::check_win32`) plutôt que de
/// déclencher une invite UAC automatique.
pub fn lock(target: &Path, password: &str) -> Result<()> {
    if is_locked(target) {
        return Err(SecureVaultError::Acl("la cible est déjà verrouillée".into()));
    }
    permissions::lock_path(target, password)
}

/// Déverrouille un fichier/dossier en restaurant les ACE d'origine depuis
/// l'ADS. Vérifie d'abord l'état (bien verrouillé ?). Pas d'élévation UAC —
/// voir `lock`.
pub fn unlock(target: &Path, password: &str) -> Result<()> {
    if !is_locked(target) {
        return Err(SecureVaultError::Acl("la cible n'est pas verrouillée".into()));
    }
    permissions::unlock_path(target, password)
}

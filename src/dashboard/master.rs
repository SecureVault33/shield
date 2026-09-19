//! Master Password : un second mot de passe, indépendant de ceux posés par
//! fichier/dossier, qui permet le déverrouillage forcé en cas d'urgence
//! (voir `dashboard::force_unlock`). Stocké en hash Argon2id — jamais en
//! clair — au même format que `kdf::hash_password`.

use crate::crypto::kdf;
use crate::errors::{Result, SecureVaultError};
use std::fs;
use std::path::PathBuf;

fn master_key_path() -> Result<PathBuf> {
    let local_app_data = std::env::var("LOCALAPPDATA")
        .map_err(|_| SecureVaultError::Registry("variable LOCALAPPDATA introuvable".into()))?;
    let dir = PathBuf::from(local_app_data).join("SecureVault");
    fs::create_dir_all(&dir)?;
    Ok(dir.join("master.key"))
}

/// Vérifie si un Master Password a déjà été configuré sur cette machine.
pub fn is_master_password_set() -> bool {
    master_key_path().map(|p| p.exists()).unwrap_or(false)
}

/// Configure le Master Password (hash Argon2id). Échoue si un Master
/// Password existe déjà — utiliser `change_master_password` pour le changer.
pub fn setup_master_password(password: &str) -> Result<()> {
    let path = master_key_path()?;
    if path.exists() {
        return Err(SecureVaultError::Crypto("Master password déjà configuré".into()));
    }
    let (hash, _salt) = kdf::hash_password(password)?;
    fs::write(&path, hash)?;
    Ok(())
}

/// Vérifie un mot de passe candidat contre le Master Password stocké.
pub fn verify_master_password(password: &str) -> Result<bool> {
    let path = master_key_path()?;
    if !path.exists() {
        return Err(SecureVaultError::Crypto("Master password non configuré".into()));
    }
    let hash = fs::read_to_string(&path)?;
    kdf::verify_password(password, hash.trim())
}

/// Change le Master Password : vérifie l'ancien avant de le remplacer.
pub fn change_master_password(old_password: &str, new_password: &str) -> Result<()> {
    if !verify_master_password(old_password)? {
        return Err(SecureVaultError::InvalidPassword);
    }
    let path = master_key_path()?;
    let (hash, _salt) = kdf::hash_password(new_password)?;
    fs::write(&path, hash)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // `master_key_path` pointe vers un fichier fixe sous `%LOCALAPPDATA%`,
    // partagé par tout le process : ces tests s'exécutent verrouillés entre
    // eux (voir aussi `dashboard::registry::tests`, même principe) et avec
    // `cargo test -- --test-threads=1` pour ne pas se marcher dessus.
    static MASTER_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn with_clean_master<F: FnOnce()>(f: F) {
        // Garde récupérée même après un panic d'un test précédent : sinon le
        // mutex empoisonné ferait échouer tous les suivants SANS restaurer le
        // master.key réel de l'utilisateur.
        let _guard = MASTER_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = master_key_path().unwrap();
        let original = fs::read_to_string(&path).ok();

        crate::dashboard::remove_until_gone(&path);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

        // Restauration AVANT la propagation du panic : un `assert!` raté ne
        // doit jamais laisser l'utilisateur sans son Master Password.
        match original {
            Some(content) => fs::write(&path, content).unwrap(),
            None => {
                let _ = fs::remove_file(&path);
            }
        }

        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }

    #[test]
    fn setup_verify_and_change() {
        with_clean_master(|| {
            assert!(!is_master_password_set());

            setup_master_password("master-correct").unwrap();
            assert!(is_master_password_set());

            // Un second setup doit échouer (déjà configuré).
            assert!(setup_master_password("autre").is_err());

            assert_eq!(verify_master_password("master-correct").unwrap(), true);
            assert_eq!(verify_master_password("mauvais").unwrap(), false);

            change_master_password("master-correct", "nouveau-master").unwrap();
            assert_eq!(verify_master_password("master-correct").unwrap(), false);
            assert_eq!(verify_master_password("nouveau-master").unwrap(), true);

            // Changer avec un mauvais ancien mot de passe doit échouer et ne
            // rien modifier.
            assert!(change_master_password("faux-ancien", "autre").is_err());
            assert_eq!(verify_master_password("nouveau-master").unwrap(), true);
        });
    }
}

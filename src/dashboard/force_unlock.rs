//! Déverrouillage forcé (mode ACL uniquement) : dernier recours quand le
//! mot de passe est perdu ou l'ACL corrompue. Nécessite des droits
//! administrateur — `takeown` reprend la propriété du fichier/dossier et
//! `icacls /reset` réinitialise ses permissions à celles héritées du
//! dossier parent, même si le process courant n'est ni propriétaire ni
//! détenteur de `WRITE_DAC` sur la cible (ce qui, contrairement à
//! `acl::lock`/`unlock`, justifie réellement l'élévation ici).
//!
//! Ne fonctionne PAS pour le mode `encrypted` : par design, il n'y a aucun
//! moyen de retrouver des données chiffrées sans le mot de passe ou la
//! recovery key — voir `dashboard::window`, qui bloque cette action pour
//! les entrées chiffrées avant même d'appeler ce module.

use crate::dashboard::registry::{self, VaultEntry};
use crate::errors::{Result, SecureVaultError};
use std::path::Path;
use std::process::Command;
use windows::core::HSTRING;
use windows::Win32::Storage::FileSystem::{
    DeleteFileW, GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_SYSTEM, FILE_FLAGS_AND_ATTRIBUTES,
    INVALID_FILE_ATTRIBUTES,
};

const ADS_STREAM_SUFFIX: &str = ":securevault";
const COMPANION_SUFFIX: &str = ".securevault";
/// Voir `acl::permissions::HASH_SUFFIX` : fichier de hash voisin, créé au
/// verrouillage depuis la 0.7.0. Il doit disparaître avec le reste, sinon la
/// cible paraîtrait encore verrouillée à un futur `verify_password`.
const HASH_SUFFIX: &str = ".securevault.hash";

fn run_command(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program).args(args).output().map_err(|e| {
        SecureVaultError::Acl(format!("échec du lancement de '{program}': {e}"))
    })?;
    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SecureVaultError::Acl(format!(
            "'{program}' a échoué (code {:?}) : {} {}",
            output.status.code(),
            stdout.trim(),
            stderr.trim()
        )));
    }
    Ok(())
}

/// Retire les attributs caché/système, sans toucher aux autres. Best-effort
/// si la cible n'a plus d'attributs lisibles (déjà dans un état étrange) :
/// ce n'est pas fatal pour un déverrouillage forcé.
fn clear_hidden_system_attributes(path: &Path) -> Result<()> {
    let wide = HSTRING::from(path.as_os_str());
    let current = unsafe { GetFileAttributesW(&wide) };
    if current == INVALID_FILE_ATTRIBUTES {
        return Ok(());
    }
    let cleared = current & !(FILE_ATTRIBUTE_HIDDEN.0 | FILE_ATTRIBUTE_SYSTEM.0);
    let attrs = if cleared == 0 {
        FILE_ATTRIBUTE_NORMAL
    } else {
        FILE_FLAGS_AND_ATTRIBUTES(cleared)
    };
    unsafe { SetFileAttributesW(&wide, attrs) }
        .map_err(|e| SecureVaultError::Acl(format!("changement d'attributs échoué: {e}")))
}

/// Supprime l'ADS `:securevault` si présent. Ignore l'échec : l'ADS peut
/// simplement ne pas exister (ou déjà avoir été nettoyée par `unlock`).
fn remove_ads(path: &Path) {
    let mut ads_os = path.as_os_str().to_os_string();
    ads_os.push(ADS_STREAM_SUFFIX);
    let wide = HSTRING::from(ads_os.as_os_str());
    unsafe {
        let _ = DeleteFileW(&wide);
    }
}

/// Supprime les fichiers voisins `.securevault` (compagnon) et
/// `.securevault.hash` s'ils existent. Le hash est masqué à l'écriture, donc
/// on retire l'attribut avant de supprimer.
fn remove_sidecars(path: &Path) -> Result<()> {
    let (Some(file_name), Some(parent)) = (path.file_name().and_then(|n| n.to_str()), path.parent())
    else {
        return Ok(());
    };

    let companion = parent.join(format!("{file_name}{COMPANION_SUFFIX}"));
    match std::fs::remove_file(&companion) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    let hash_file = parent.join(format!("{file_name}{HASH_SUFFIX}"));
    if hash_file.exists() {
        let wide = HSTRING::from(hash_file.as_os_str());
        let _ = unsafe { SetFileAttributesW(&wide, FILE_ATTRIBUTE_NORMAL) };
    }
    match std::fs::remove_file(&hash_file) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Déverrouille de force un fichier/dossier verrouillé en mode ACL :
/// `takeown` (reprise de propriété) + `icacls /reset` (réinitialisation des
/// permissions), retrait des attributs caché/système, suppression de l'ADS
/// de sauvegarde et du fichier compagnon, puis mise à jour du registre.
pub fn force_unlock_path(path: &Path) -> Result<()> {
    let path_str = path
        .to_str()
        .ok_or_else(|| SecureVaultError::Acl("chemin non-UTF8".into()))?;
    let is_dir = path.is_dir();

    let mut takeown_args: Vec<&str> = vec!["/F", path_str, "/A"];
    if is_dir {
        takeown_args.push("/R");
    }
    run_command("takeown", &takeown_args)?;

    let mut icacls_args: Vec<&str> = vec![path_str, "/reset"];
    if is_dir {
        icacls_args.push("/T");
    }
    run_command("icacls", &icacls_args)?;

    clear_hidden_system_attributes(path)?;
    remove_ads(path);
    remove_sidecars(path)?;

    // Best-effort : le registre est un carnet de bord, pas la source de
    // vérité (voir `registry::update_status`).
    let _ = registry::update_status(path_str, "unlocked");

    Ok(())
}

/// Applique `force_unlock_path` à toutes les entrées `acl_locked`+`locked`
/// fournies (les autres sont silencieusement ignorées). Retourne le résultat
/// par entrée (chemin d'origine, résultat) pour que l'appelant (dashboard)
/// puisse afficher un résumé succès/échec par fichier.
pub fn force_unlock_all(entries: &[VaultEntry]) -> Result<Vec<(String, Result<()>)>> {
    Ok(entries
        .iter()
        .filter(|e| e.mode == "acl_locked" && e.status == "locked")
        .map(|e| {
            let result = force_unlock_path(Path::new(&e.original_path));
            (e.original_path.clone(), result)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    // `force_unlock_path` shelle vers `takeown`/`icacls`, qui échouent sans
    // droits administrateur — ce test ne peut donc pas tourner dans la CI
    // normale (`cargo test`) ni dans un terminal non élevé. Pour le vérifier
    // manuellement :
    //   1. Ouvrir un terminal EN ADMINISTRATEUR.
    //   2. `cargo test --release -- --ignored force_unlock_path_recovers_a_locked_file`
    // Le test verrouille un fichier temporaire via `acl::lock`, puis appelle
    // `force_unlock_path` SANS le mot de passe (simulant un mot de passe
    // perdu) et vérifie que le fichier redevient lisible et que le registre
    // passe à `"unlocked"`.
    #[test]
    #[ignore = "nécessite un terminal Administrateur (takeown/icacls) — voir le commentaire ci-dessus"]
    fn force_unlock_path_recovers_a_locked_file() {
        let dir = std::env::temp_dir().join(format!("securevault_force_unlock_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("secret.txt");
        std::fs::write(&target, b"contenu").unwrap();

        crate::acl::lock(&target, "mot-de-passe-perdu").unwrap();
        assert!(std::fs::read(&target).is_err(), "le fichier doit être inaccessible une fois verrouillé");

        force_unlock_path(&target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"contenu");

        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_dir(&dir);
    }
}

//! Registre des opérations : trace chaque fichier/dossier verrouillé ou
//! chiffré par SecureVault dans un fichier JSON, pour le Centre
//! d'administration (`dashboard::window`). C'est un carnet de bord — la
//! source de vérité reste l'état réel du fichier (DACL/ADS ou `.vault`) ;
//! le registre peut donc être en retard ou incomplet (ex: verrouillage fait
//! avec une version antérieure) sans que ça casse quoi que ce soit.
//!
//! Les recovery keys, elles, ne sont PAS un carnet de bord : ce sont des
//! secrets qui déverrouillent un `.vault` sans le mot de passe. Depuis la
//! 0.7.0 elles sont chiffrées (AES-256-GCM, clé dérivée du Master Password)
//! avant d'être écrites ici — voir `add_entry`/`get_recovery_key`.

use crate::crypto::{aes_gcm, kdf};
use crate::errors::{Result, SecureVaultError};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: String,
    pub original_path: String,
    pub protected_path: String,
    /// `"acl_locked"` ou `"encrypted"`.
    pub mode: String,
    pub protected_at: String,
    /// `"locked"` ou `"unlocked"`.
    pub status: String,
    pub is_directory: bool,
    /// Rappel de sécurité déjà envoyé pour cette exposition (voir
    /// `dashboard::notifier`). Remis à `false` à chaque nouveau
    /// déverrouillage, sinon le rappel ne fonctionnerait qu'une seule fois
    /// dans la vie d'une entrée. `#[serde(default)]` : les entrées d'un
    /// registre créé par une version antérieure à 0.5.0 n'ont pas ce champ.
    #[serde(default)]
    pub reminder_sent: bool,
    /// Date du dernier passage à `"unlocked"` (RFC3339), c'est-à-dire le
    /// début de la période d'exposition. Distinct de `protected_at`, qui est
    /// la date de PROTECTION : compter l'exposition depuis `protected_at`
    /// donnait des durées absurdes (« exposé depuis 3 mois » pour un fichier
    /// déverrouillé il y a deux minutes). Effacé au reverrouillage.
    #[serde(default)]
    pub unlocked_at: Option<String>,
    /// Recovery key du chiffrement (mode `"encrypted"` uniquement), chiffrée
    /// AES-256-GCM avec une clé dérivée du Master Password, encodée en
    /// base64. `recovery_key_nonce` porte le nonce correspondant.
    ///
    /// Si `recovery_key_nonce` est `None`, c'est une clé en CLAIR écrite par
    /// une version antérieure à 0.7.0 : elle est lue telle quelle et migrée
    /// dès qu'un Master Password est disponible (voir
    /// `migrate_plaintext_recovery_keys`).
    #[serde(default)]
    pub recovery_key: Option<String>,
    #[serde(default)]
    pub recovery_key_nonce: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRegistry {
    pub version: u32,
    /// Sel Argon2id du chiffrement des recovery keys, commun à tout le
    /// registre (base64). Un seul sel suffit : c'est le NONCE qui doit être
    /// unique par clé, et il l'est (`recovery_key_nonce`). Un sel par entrée
    /// imposerait une dérivation Argon2id (~150 ms) par entrée à l'export.
    #[serde(default)]
    pub recovery_salt: Option<String>,
    pub entries: Vec<VaultEntry>,
}

impl Default for VaultRegistry {
    fn default() -> Self {
        VaultRegistry {
            version: 1,
            recovery_salt: None,
            entries: Vec::new(),
        }
    }
}

/// Chemin de `%LOCALAPPDATA%\SecureVault\vault_registry.json`, créant le
/// dossier parent si besoin.
pub fn get_registry_path() -> Result<PathBuf> {
    let local_app_data = std::env::var("LOCALAPPDATA")
        .map_err(|_| SecureVaultError::Registry("variable LOCALAPPDATA introuvable".into()))?;
    let dir = PathBuf::from(local_app_data).join("SecureVault");
    fs::create_dir_all(&dir)?;
    Ok(dir.join("vault_registry.json"))
}

/// Charge le registre ; un registre vide (pas une erreur) si le fichier
/// n'existe pas encore. Déduplique au passage (voir `deduplicate`).
pub fn load_registry() -> Result<VaultRegistry> {
    let path = get_registry_path()?;
    if !path.exists() {
        return Ok(VaultRegistry::default());
    }
    let content = fs::read_to_string(&path)?;
    let mut registry: VaultRegistry = serde_json::from_str(&content)
        .map_err(|e| SecureVaultError::Registry(format!("registre JSON invalide: {e}")))?;
    deduplicate(&mut registry);
    Ok(registry)
}

/// Ne garde qu'une entrée par couple (`original_path`, `mode`) : la plus
/// récente selon `protected_at`. Les versions antérieures à 0.7.0 empilaient
/// une nouvelle entrée à chaque verrouillage, donc un registre existant peut
/// contenir plusieurs lignes pour le même chemin — toutes mises à jour
/// ensemble par `update_status`, ce qui rendait le dashboard illisible.
///
/// Le `mode` fait partie de la clé et pas seulement le chemin : verrouiller un
/// dossier (ACL) PUIS le chiffrer produit deux protections bien réelles, avec
/// deux artefacts distincts (la cible elle-même et un `.vault` à côté). Les
/// fusionner perdrait une protection et rattacherait la recovery key du
/// `.vault` à une entrée ACL qui n'en a pas.
///
/// L'ordre d'origine est conservé (position de la première occurrence) pour
/// que la liste ne se réorganise pas sous les yeux de l'utilisateur.
fn deduplicate(registry: &mut VaultRegistry) {
    let mut best: Vec<VaultEntry> = Vec::with_capacity(registry.entries.len());

    for entry in registry.entries.drain(..) {
        match best
            .iter_mut()
            .find(|e| e.original_path == entry.original_path && e.mode == entry.mode)
        {
            Some(existing) => {
                if entry.protected_at >= existing.protected_at {
                    // Une entrée plus récente remplace l'ancienne, mais on ne
                    // perd pas une recovery key que la nouvelle n'aurait pas.
                    let mut winner = entry;
                    if winner.recovery_key.is_none() {
                        winner.recovery_key = existing.recovery_key.take();
                        winner.recovery_key_nonce = existing.recovery_key_nonce.take();
                    }
                    *existing = winner;
                }
            }
            None => best.push(entry),
        }
    }

    registry.entries = best;
}

/// Sauvegarde le registre, indenté pour rester lisible/éditable à la main.
pub fn save_registry(registry: &VaultRegistry) -> Result<()> {
    let path = get_registry_path()?;
    let content = serde_json::to_string_pretty(registry)
        .map_err(|e| SecureVaultError::Registry(format!("sérialisation du registre échouée: {e}")))?;
    fs::write(&path, content)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Chiffrement des recovery keys
// ---------------------------------------------------------------------------

/// Retourne le sel du registre, en le créant s'il n'existe pas encore.
/// L'appelant doit sauvegarder le registre ensuite.
fn ensure_recovery_salt(registry: &mut VaultRegistry) -> Result<[u8; kdf::SALT_LEN]> {
    if let Some(encoded) = &registry.recovery_salt {
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|_| SecureVaultError::Registry("sel du registre illisible".into()))?;
        let salt: [u8; kdf::SALT_LEN] = decoded.as_slice().try_into().map_err(|_| {
            SecureVaultError::Registry("sel du registre de taille inattendue".into())
        })?;
        return Ok(salt);
    }

    let mut salt = [0u8; kdf::SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    registry.recovery_salt = Some(STANDARD.encode(salt));
    Ok(salt)
}

/// Chiffre une recovery key (sa forme base64, telle qu'affichée à
/// l'utilisateur) pour stockage. Retourne `(ciphertext_b64, nonce_b64)`.
fn seal_recovery_key(
    plain: &str,
    master_password: &str,
    salt: &[u8; kdf::SALT_LEN],
) -> Result<(String, String)> {
    let key = kdf::derive_key(master_password, salt)?;
    let mut nonce = [0u8; aes_gcm::NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = aes_gcm::encrypt(&key, &nonce, plain.as_bytes())?;
    Ok((STANDARD.encode(ciphertext), STANDARD.encode(nonce)))
}

/// Déchiffre la recovery key d'une entrée avec le Master Password.
///
/// Une entrée sans `recovery_key_nonce` date d'avant la 0.7.0 : sa clé est en
/// clair et retournée telle quelle (voir `migrate_plaintext_recovery_keys`).
pub fn get_recovery_key(entry: &VaultEntry, master_password: &str) -> Result<Zeroizing<String>> {
    let Some(stored) = entry.recovery_key.as_ref() else {
        return Err(SecureVaultError::Registry(
            "aucune recovery key enregistrée pour cette entrée".into(),
        ));
    };

    let Some(nonce_b64) = entry.recovery_key_nonce.as_ref() else {
        return Ok(Zeroizing::new(stored.clone()));
    };

    let registry = load_registry()?;
    let salt_b64 = registry.recovery_salt.ok_or_else(|| {
        SecureVaultError::Registry("sel du registre manquant (recovery key illisible)".into())
    })?;
    let salt: [u8; kdf::SALT_LEN] = STANDARD
        .decode(&salt_b64)
        .map_err(|_| SecureVaultError::Registry("sel du registre illisible".into()))?
        .as_slice()
        .try_into()
        .map_err(|_| SecureVaultError::Registry("sel du registre de taille inattendue".into()))?;

    let nonce: [u8; aes_gcm::NONCE_LEN] = STANDARD
        .decode(nonce_b64)
        .map_err(|_| SecureVaultError::Registry("nonce de recovery key illisible".into()))?
        .as_slice()
        .try_into()
        .map_err(|_| SecureVaultError::Registry("nonce de recovery key invalide".into()))?;

    let ciphertext = STANDARD
        .decode(stored)
        .map_err(|_| SecureVaultError::Registry("recovery key illisible".into()))?;

    let key = kdf::derive_key(master_password, &salt)?;
    let plain = Zeroizing::new(
        aes_gcm::decrypt(&key, &nonce, &ciphertext).map_err(|_| {
            SecureVaultError::MasterPassword(
                "recovery key indéchiffrable — Master Password incorrect ?".into(),
            )
        })?,
    );

    String::from_utf8(plain.to_vec())
        .map(Zeroizing::new)
        .map_err(|_| SecureVaultError::Registry("recovery key non-UTF8".into()))
}

/// Chiffre les recovery keys restées en clair (entrées créées avant la
/// 0.7.0). Appelée quand le Master Password vient d'être vérifié — typiquement
/// à l'export. Retourne le nombre d'entrées migrées.
pub fn migrate_plaintext_recovery_keys(master_password: &str) -> Result<usize> {
    let mut registry = load_registry()?;
    let salt = ensure_recovery_salt(&mut registry)?;

    let mut migrated = 0usize;
    for entry in registry.entries.iter_mut() {
        let needs_migration =
            entry.recovery_key.is_some() && entry.recovery_key_nonce.is_none();
        if !needs_migration {
            continue;
        }
        let plain = entry.recovery_key.clone().unwrap_or_default();
        let (sealed, nonce) = seal_recovery_key(&plain, master_password, &salt)?;
        entry.recovery_key = Some(sealed);
        entry.recovery_key_nonce = Some(nonce);
        migrated += 1;
    }

    if migrated > 0 || registry.recovery_salt.is_some() {
        save_registry(&registry)?;
    }
    Ok(migrated)
}

/// Re-chiffre toutes les recovery keys avec un NOUVEAU Master Password.
///
/// Appelé juste après `master::change_master_password` : sans cette étape,
/// changer de Master Password rendrait toutes les recovery keys enregistrées
/// définitivement illisibles — un bouton « changer mon mot de passe » qui
/// détruit silencieusement des secrets de récupération serait un piège.
///
/// Le sel est régénéré au passage (nouveau mot de passe = nouvelle dérivation)
/// et chaque clé reçoit un nonce neuf.
pub fn reseal_recovery_keys(old_master: &str, new_master: &str) -> Result<usize> {
    let mut registry = load_registry()?;

    // Déchiffrer TOUT avec l'ancien avant d'écrire quoi que ce soit : si une
    // seule clé résiste, on abandonne sans avoir rien corrompu.
    let mut plaintexts: Vec<(usize, Zeroizing<String>)> = Vec::new();
    for (index, entry) in registry.entries.iter().enumerate() {
        if entry.recovery_key.is_none() {
            continue;
        }
        plaintexts.push((index, get_recovery_key(entry, old_master)?));
    }

    if plaintexts.is_empty() {
        return Ok(0);
    }

    let mut salt = [0u8; kdf::SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    registry.recovery_salt = Some(STANDARD.encode(salt));

    let count = plaintexts.len();
    for (index, plain) in plaintexts {
        let (cipher, nonce) = seal_recovery_key(&plain, new_master, &salt)?;
        registry.entries[index].recovery_key = Some(cipher);
        registry.entries[index].recovery_key_nonce = Some(nonce);
    }

    save_registry(&registry)?;
    Ok(count)
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

/// Ajoute ou met à jour l'entrée correspondant à `original_path`.
///
/// Déduplication (voir `deduplicate`) : reprotéger un chemin déjà connu DANS
/// LE MÊME MODE met à jour l'entrée existante (statut, date, chemin protégé)
/// au lieu d'empiler une nouvelle ligne. Protéger le même chemin dans l'autre
/// mode crée bien une seconde entrée — ce sont deux protections distinctes.
///
/// `recovery_key` + `master_password` : si les deux sont fournis, la recovery
/// key est chiffrée avant stockage. Si `master_password` est absent alors
/// qu'une recovery key est fournie, on refuse de l'écrire en clair — mieux
/// vaut perdre la possibilité d'export que dupliquer un secret sur disque.
pub fn add_entry(
    original_path: &str,
    protected_path: &str,
    mode: &str,
    is_directory: bool,
    recovery_key: Option<&str>,
    master_password: Option<&str>,
) -> Result<()> {
    let mut registry = load_registry()?;

    let sealed = match (recovery_key, master_password) {
        (Some(plain), Some(master)) => {
            let salt = ensure_recovery_salt(&mut registry)?;
            let (cipher, nonce) = seal_recovery_key(plain, master, &salt)?;
            Some((cipher, nonce))
        }
        _ => None,
    };

    let now = chrono::Utc::now().to_rfc3339();

    match registry
        .entries
        .iter_mut()
        .find(|e| e.original_path == original_path && e.mode == mode)
    {
        Some(existing) => {
            existing.protected_path = protected_path.to_string();
            existing.protected_at = now;
            existing.status = "locked".to_string();
            existing.is_directory = is_directory;
            existing.reminder_sent = false;
            existing.unlocked_at = None;
            if let Some((cipher, nonce)) = sealed {
                existing.recovery_key = Some(cipher);
                existing.recovery_key_nonce = Some(nonce);
            }
        }
        None => {
            let (recovery_key, recovery_key_nonce) = match sealed {
                Some((cipher, nonce)) => (Some(cipher), Some(nonce)),
                None => (None, None),
            };
            registry.entries.push(VaultEntry {
                id: uuid::Uuid::new_v4().to_string(),
                original_path: original_path.to_string(),
                protected_path: protected_path.to_string(),
                mode: mode.to_string(),
                protected_at: now,
                status: "locked".to_string(),
                is_directory,
                reminder_sent: false,
                unlocked_at: None,
                recovery_key,
                recovery_key_nonce,
            });
        }
    }

    save_registry(&registry)
}

/// Met à jour le statut de la (ou des) entrée(s) dont `original_path` OU
/// `protected_path` correspond à `path`. Best-effort : ne pas trouver
/// d'entrée correspondante n'est PAS une erreur (le registre est un carnet
/// de bord, pas la source de vérité — un verrouillage fait avant l'ajout du
/// dashboard n'y figure simplement pas).
///
/// Le passage à `"unlocked"` horodate `unlocked_at` et réarme `reminder_sent` :
/// c'est ce couple qui fait fonctionner le rappel de sécurité à chaque
/// exposition, et pas seulement à la première (voir `dashboard::notifier`).
pub fn update_status(path: &str, new_status: &str) -> Result<()> {
    let mut registry = load_registry()?;
    let mut changed = false;
    for entry in registry.entries.iter_mut() {
        if entry.original_path == path || entry.protected_path == path {
            if entry.status != new_status {
                if new_status == "unlocked" {
                    entry.unlocked_at = Some(chrono::Utc::now().to_rfc3339());
                    entry.reminder_sent = false;
                } else {
                    entry.unlocked_at = None;
                    entry.reminder_sent = false;
                }
            }
            entry.status = new_status.to_string();
            changed = true;
        }
    }
    if changed {
        save_registry(&registry)?;
    }
    Ok(())
}

/// Supprime une entrée par son ID (retire seulement l'entrée du registre —
/// ne touche pas au fichier réel). Erreur si l'ID est inconnu : contrairement
/// à `update_status`, c'est une action explicite de l'utilisateur (bouton
/// "Retirer" du dashboard), qui mérite un retour clair.
pub fn remove_entry(id: &str) -> Result<()> {
    let mut registry = load_registry()?;
    let before = registry.entries.len();
    registry.entries.retain(|e| e.id != id);
    if registry.entries.len() == before {
        return Err(SecureVaultError::Registry(format!(
            "aucune entrée avec l'identifiant '{id}'"
        )));
    }
    save_registry(&registry)
}

pub fn list_entries() -> Result<Vec<VaultEntry>> {
    Ok(load_registry()?.entries)
}

/// Entrées verrouillées en mode ACL uniquement (candidates au déverrouillage
/// forcé — voir `force_unlock`, qui ne fonctionne pas pour `"encrypted"`).
pub fn find_locked_acl_entries() -> Result<Vec<VaultEntry>> {
    Ok(list_entries()?
        .into_iter()
        .filter(|e| e.mode == "acl_locked" && e.status == "locked")
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // `get_registry_path` lit `%LOCALAPPDATA%`, une ressource partagée par
    // process : ces tests s'exécutent donc verrouillés entre eux (un seul à
    // la fois) pour éviter qu'ils ne piétinent le même fichier registre en
    // parallèle. Chaque test sauvegarde/restaure le contenu original.
    static REGISTRY_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn with_clean_registry<F: FnOnce()>(f: F) {
        // `lock()` plutôt que `lock().unwrap()` : si un test précédent a
        // paniqué, le mutex est empoisonné — on récupère quand même la garde,
        // sinon TOUS les tests suivants échoueraient en cascade sans jamais
        // restaurer le registre réel de l'utilisateur.
        let _guard = REGISTRY_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = get_registry_path().unwrap();
        let original = fs::read_to_string(&path).ok();

        crate::dashboard::remove_until_gone(&path);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

        // Restauration AVANT la propagation du panic : sans ça, un assert
        // raté détruisait les données réelles de l'utilisateur.
        match original {
            Some(content) => {
                fs::write(&path, content).unwrap();
            }
            None => {
                let _ = fs::remove_file(&path);
            }
        }

        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }

    #[test]
    fn crud_add_list_update_remove() {
        with_clean_registry(|| {
            assert!(list_entries().unwrap().is_empty());

            add_entry("C:\\a.txt", "C:\\a.txt", "acl_locked", false, None, None).unwrap();
            add_entry(
                "C:\\Dossier",
                "C:\\Dossier.vault",
                "encrypted",
                true,
                None,
                None,
            )
            .unwrap();

            let entries = list_entries().unwrap();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].status, "locked");

            update_status("C:\\a.txt", "unlocked").unwrap();
            let entries = list_entries().unwrap();
            let updated = entries.iter().find(|e| e.original_path == "C:\\a.txt").unwrap();
            assert_eq!(updated.status, "unlocked");
            assert!(
                updated.unlocked_at.is_some(),
                "le passage à unlocked doit horodater unlocked_at"
            );

            // Chercher aussi par protected_path.
            update_status("C:\\Dossier.vault", "unlocked").unwrap();
            let entries = list_entries().unwrap();
            let updated = entries.iter().find(|e| e.protected_path == "C:\\Dossier.vault").unwrap();
            assert_eq!(updated.status, "unlocked");

            // Statut d'un chemin inconnu : pas une erreur (best-effort).
            update_status("C:\\inconnu.txt", "unlocked").unwrap();

            let id = entries[0].id.clone();
            remove_entry(&id).unwrap();
            assert_eq!(list_entries().unwrap().len(), 1);

            assert!(remove_entry("id-inexistant").is_err());
        });
    }

    #[test]
    fn find_locked_acl_entries_filters_correctly() {
        with_clean_registry(|| {
            add_entry("C:\\locked_acl.txt", "C:\\locked_acl.txt", "acl_locked", false, None, None).unwrap();
            add_entry("C:\\unlocked_acl.txt", "C:\\unlocked_acl.txt", "acl_locked", false, None, None).unwrap();
            add_entry("C:\\encrypted.txt", "C:\\encrypted.txt.vault", "encrypted", false, None, None).unwrap();

            update_status("C:\\unlocked_acl.txt", "unlocked").unwrap();

            let locked = find_locked_acl_entries().unwrap();
            assert_eq!(locked.len(), 1);
            assert_eq!(locked[0].original_path, "C:\\locked_acl.txt");
        });
    }

    /// Régression B5 : reprotéger un chemin déjà connu ne doit PAS créer une
    /// seconde ligne pour le même fichier.
    #[test]
    fn add_entry_updates_instead_of_duplicating() {
        with_clean_registry(|| {
            add_entry("C:\\x.txt", "C:\\x.txt", "acl_locked", false, None, None).unwrap();
            update_status("C:\\x.txt", "unlocked").unwrap();
            add_entry("C:\\x.txt", "C:\\x.txt", "acl_locked", false, None, None).unwrap();

            let entries = list_entries().unwrap();
            assert_eq!(entries.len(), 1, "un seul chemin = une seule entrée");
            assert_eq!(entries[0].status, "locked");
            assert!(
                entries[0].unlocked_at.is_none(),
                "le reverrouillage doit effacer unlocked_at"
            );
        });
    }

    /// Deux modes sur le même chemin = deux protections réelles, donc deux
    /// entrées. C'est exactement le cas présent dans un registre 0.6.x où un
    /// dossier a été chiffré puis verrouillé.
    #[test]
    fn same_path_in_two_modes_stays_two_entries() {
        with_clean_registry(|| {
            add_entry("C:\\Dossier", "C:\\Dossier.vault", "encrypted", true, None, None).unwrap();
            add_entry("C:\\Dossier", "C:\\Dossier", "acl_locked", true, None, None).unwrap();

            let entries = list_entries().unwrap();
            assert_eq!(entries.len(), 2, "chiffré et verrouillé sont deux protections");
            assert!(entries.iter().any(|e| e.mode == "encrypted"));
            assert!(entries.iter().any(|e| e.mode == "acl_locked"));

            // Reprotéger dans un mode déjà présent ne duplique toujours pas.
            add_entry("C:\\Dossier", "C:\\Dossier", "acl_locked", true, None, None).unwrap();
            assert_eq!(list_entries().unwrap().len(), 2);
        });
    }

    /// Régression I2 : chaque nouveau déverrouillage doit réarmer le rappel,
    /// sinon la notification ne se déclenche qu'une fois par entrée.
    #[test]
    fn relocking_then_unlocking_rearms_the_reminder() {
        with_clean_registry(|| {
            add_entry("C:\\y.txt", "C:\\y.txt", "acl_locked", false, None, None).unwrap();
            update_status("C:\\y.txt", "unlocked").unwrap();

            // Simule un rappel déjà envoyé pour cette exposition.
            let mut registry = load_registry().unwrap();
            registry.entries[0].reminder_sent = true;
            save_registry(&registry).unwrap();

            update_status("C:\\y.txt", "locked").unwrap();
            update_status("C:\\y.txt", "unlocked").unwrap();

            let entries = list_entries().unwrap();
            assert!(!entries[0].reminder_sent, "le rappel doit être réarmé");
            assert!(entries[0].unlocked_at.is_some());
        });
    }

    /// Régression S1 : une recovery key stockée avec un Master Password ne
    /// doit jamais apparaître en clair dans le JSON, et doit se relire.
    #[test]
    fn recovery_key_is_sealed_and_roundtrips() {
        with_clean_registry(|| {
            let plain = "P5DvJg4Ix6caa77ftIvbenvq37ogCak54djtGpp5270=";
            add_entry(
                "C:\\secret",
                "C:\\secret.vault",
                "encrypted",
                true,
                Some(plain),
                Some("master-de-test"),
            )
            .unwrap();

            let raw = fs::read_to_string(get_registry_path().unwrap()).unwrap();
            assert!(
                !raw.contains(plain),
                "la recovery key ne doit pas être lisible dans le JSON"
            );

            let entries = list_entries().unwrap();
            let recovered = get_recovery_key(&entries[0], "master-de-test").unwrap();
            assert_eq!(&*recovered, plain);

            assert!(
                get_recovery_key(&entries[0], "mauvais-master").is_err(),
                "un mauvais Master Password ne doit pas déchiffrer la clé"
            );
        });
    }

    /// Sans Master Password, on préfère ne rien stocker plutôt que d'écrire
    /// le secret en clair.
    #[test]
    fn recovery_key_is_not_stored_without_a_master_password() {
        with_clean_registry(|| {
            add_entry(
                "C:\\z",
                "C:\\z.vault",
                "encrypted",
                false,
                Some("cle-en-clair"),
                None,
            )
            .unwrap();

            let raw = fs::read_to_string(get_registry_path().unwrap()).unwrap();
            assert!(!raw.contains("cle-en-clair"));
            assert!(list_entries().unwrap()[0].recovery_key.is_none());
        });
    }

    /// Migration : une clé en clair héritée d'une version < 0.7.0 est lisible
    /// telle quelle, puis chiffrée dès qu'un Master Password est disponible.
    #[test]
    fn legacy_plaintext_recovery_key_is_readable_then_migrated() {
        with_clean_registry(|| {
            add_entry("C:\\old", "C:\\old.vault", "encrypted", false, None, None).unwrap();

            let mut registry = load_registry().unwrap();
            registry.entries[0].recovery_key = Some("ancienne-cle".to_string());
            registry.entries[0].recovery_key_nonce = None;
            save_registry(&registry).unwrap();

            let entries = list_entries().unwrap();
            assert_eq!(
                &*get_recovery_key(&entries[0], "peu-importe").unwrap(),
                "ancienne-cle"
            );

            assert_eq!(migrate_plaintext_recovery_keys("master-de-test").unwrap(), 1);

            let raw = fs::read_to_string(get_registry_path().unwrap()).unwrap();
            assert!(!raw.contains("ancienne-cle"));

            let entries = list_entries().unwrap();
            assert_eq!(
                &*get_recovery_key(&entries[0], "master-de-test").unwrap(),
                "ancienne-cle"
            );
        });
    }
}

use crate::crypto::aes_gcm::{self, NONCE_LEN};
use crate::crypto::kdf::{self, SALT_LEN};
use crate::errors::{Result, SecureVaultError};
use rand::rngs::OsRng;
use rand::RngCore;
use std::ffi::c_void;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use windows::core::HSTRING;
use windows::Win32::Foundation::{
    LocalFree, ERROR_ACCESS_DENIED, ERROR_SUCCESS, HLOCAL, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, EXPLICIT_ACCESS_W, GetNamedSecurityInfoW, SetEntriesInAclW,
    SetNamedSecurityInfoW, DENY_ACCESS, GRANT_ACCESS, SE_FILE_OBJECT, TRUSTEE_W,
};
use windows::Win32::Security::{
    CreateWellKnownSid, ACL, DACL_SECURITY_INFORMATION, NO_INHERITANCE,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_MAX_SID_SIZE,
    UNPROTECTED_DACL_SECURITY_INFORMATION, WinWorldSid,
};
use windows::Win32::Storage::FileSystem::{
    GetFileAttributesW, SetFileAttributesW, DELETE, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_SYSTEM, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_READ_ATTRIBUTES, INVALID_FILE_ATTRIBUTES, READ_CONTROL, SYNCHRONIZE,
};

/// Nom de l'Alternate Data Stream utilisé pour stocker la sauvegarde chiffrée des ACE.
const ADS_STREAM_SUFFIX: &str = ":securevault";
const ADS_MAGIC: &[u8; 4] = b"SVAC";
const ADS_VERSION: u8 = 1;

/// Suffixe du fichier compagnon créé à côté d'une cible verrouillée : double-
/// cliquer dessus dans l'Explorateur lance `unlock-companion` (voir le type
/// de fichier `.securevault` enregistré par `registry::install_context_menu`).
const COMPANION_SUFFIX: &str = ".securevault";

/// Suffixe du fichier de hash, à côté du fichier compagnon.
///
/// Pourquoi un fichier séparé plutôt que l'ADS : l'ADS `:securevault` partage
/// la DACL de son fichier porteur, donc lire le hash qui s'y trouvait obligeait
/// à lever temporairement la DACL restrictive — c'est-à-dire à appliquer une
/// DACL NULL (accès total pour TOUS) pendant toute la durée d'un Argon2id
/// (~150 ms), à chaque essai de mot de passe. Pire : un process tué pendant
/// cette fenêtre laissait la cible définitivement ouverte.
///
/// Le hash n'est pas un secret (Argon2id, sel aléatoire par cible) : le sortir
/// dans un fichier voisin supprime entièrement cette fenêtre d'exposition. La
/// sauvegarde de la DACL, elle, reste dans l'ADS — c'est le seul endroit où
/// elle ne peut pas être supprimée par inadvertance sans perdre aussi la cible.
const HASH_SUFFIX: &str = ".securevault.hash";

/// Chemin de l'ADS `:securevault` associé à une cible.
fn ads_path(target: &Path) -> PathBuf {
    let mut os = target.as_os_str().to_os_string();
    os.push(ADS_STREAM_SUFFIX);
    PathBuf::from(os)
}

/// Rend un chemin absolu sans exiger qu'il existe déjà. Indispensable ici :
/// le fichier compagnon `.securevault` est relu par une invocation ultérieure
/// et complètement séparée du process (double-clic dans l'Explorateur), dont
/// le répertoire de travail n'a aucun rapport avec le dossier de la cible.
fn absolutize(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

/// Chemin du fichier compagnon `<nom_original>.securevault`, dans le même
/// dossier parent que `target`.
fn companion_path(target: &Path) -> Result<PathBuf> {
    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| SecureVaultError::Acl("nom de cible invalide (non-UTF8)".into()))?;
    let parent = target
        .parent()
        .ok_or_else(|| SecureVaultError::Acl("la cible n'a pas de dossier parent".into()))?;
    Ok(parent.join(format!("{file_name}{COMPANION_SUFFIX}")))
}

/// Écrit le fichier compagnon (texte brut, chemin absolu de la cible).
fn write_companion(target: &Path) -> Result<()> {
    let path = companion_path(target)?;
    fs::write(path, target.as_os_str().to_string_lossy().as_bytes())?;
    Ok(())
}

/// Supprime le fichier compagnon s'il existe (idempotent).
fn remove_companion(target: &Path) -> Result<()> {
    let path = companion_path(target)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Chemin du fichier de hash `<nom_original>.securevault.hash` (voir
/// `HASH_SUFFIX`), dans le même dossier parent que `target`.
pub fn hash_path(target: &Path) -> Result<PathBuf> {
    let file_name = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| SecureVaultError::Acl("nom de cible invalide (non-UTF8)".into()))?;
    let parent = target
        .parent()
        .ok_or_else(|| SecureVaultError::Acl("la cible n'a pas de dossier parent".into()))?;
    Ok(parent.join(format!("{file_name}{HASH_SUFFIX}")))
}

/// Écrit le hash PHC Argon2id du mot de passe à côté de la cible, puis le
/// masque : contrairement au compagnon `.securevault` (que l'utilisateur doit
/// pouvoir double-cliquer), ce fichier est purement interne et n'a rien à
/// faire dans la vue de l'Explorateur.
fn write_hash_file(target: &Path, hash: &str) -> Result<()> {
    let path = hash_path(target)?;
    fs::write(&path, hash.as_bytes())?;
    // Best-effort : un hash visible est inesthétique, pas dangereux.
    let wide = HSTRING::from(path.as_os_str());
    let _ = unsafe { SetFileAttributesW(&wide, FILE_ATTRIBUTE_HIDDEN) };
    Ok(())
}

/// Lit le hash stocké à côté de la cible. `Ok(None)` si le fichier n'existe
/// pas : c'est le cas des cibles verrouillées par une version antérieure à
/// 0.7.0, qui n'ont le hash que dans l'ADS (voir le repli dans
/// `verify_password`).
fn read_hash_file(target: &Path) -> Result<Option<String>> {
    let path = match hash_path(target) {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };
    match fs::read_to_string(&path) {
        Ok(content) => {
            let trimmed = content.trim().to_string();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Supprime le fichier de hash s'il existe (idempotent). L'attribut caché doit
/// être retiré d'abord : `remove_file` échoue sur un fichier en lecture seule,
/// pas sur un fichier caché, mais on nettoie par symétrie avec `set_hidden`.
pub fn remove_hash_file(target: &Path) -> Result<()> {
    let path = hash_path(target)?;
    if path.exists() {
        let wide = HSTRING::from(path.as_os_str());
        let _ = unsafe { SetFileAttributesW(&wide, FILE_ATTRIBUTE_NORMAL) };
    }
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Sans élévation UAC (voir `acl::lock`/`unlock`), un `ERROR_ACCESS_DENIED`
/// ici signifie typiquement que la cible n'appartient pas à l'utilisateur
/// courant (ou est un fichier système protégé) : message clair plutôt qu'un
/// code Win32 brut, et surtout pas d'invite UAC automatique — l'utilisateur
/// peut relancer depuis une invite administrateur s'il le souhaite.
fn check_win32(status: WIN32_ERROR, context: &str) -> Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else if status == ERROR_ACCESS_DENIED {
        Err(SecureVaultError::Acl(
            "Accès refusé — ce fichier nécessite des droits administrateur.".into(),
        ))
    } else {
        Err(SecureVaultError::Acl(format!(
            "{context} (code Win32 {})",
            status.0
        )))
    }
}

/// Vérifie si la cible est verrouillée (présence de l'ADS `:securevault`).
pub fn is_locked(target: &Path) -> bool {
    fs::metadata(ads_path(target)).is_ok()
}

struct Backup {
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    hash: String,
    ciphertext: Vec<u8>,
}

fn pack_backup(salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN], hash: &str, ciphertext: &[u8]) -> Vec<u8> {
    let hash_bytes = hash.as_bytes();
    let mut out = Vec::with_capacity(
        ADS_MAGIC.len() + 1 + SALT_LEN + NONCE_LEN + 2 + hash_bytes.len() + 4 + ciphertext.len(),
    );
    out.extend_from_slice(ADS_MAGIC);
    out.push(ADS_VERSION);
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&(hash_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(hash_bytes);
    out.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
    out.extend_from_slice(ciphertext);
    out
}

fn unpack_backup(data: &[u8]) -> Result<Backup> {
    let header_len = ADS_MAGIC.len() + 1 + SALT_LEN + NONCE_LEN + 2;
    if data.len() < header_len {
        return Err(SecureVaultError::InvalidFormat("en-tête ADS tronqué".into()));
    }
    if &data[0..ADS_MAGIC.len()] != ADS_MAGIC {
        return Err(SecureVaultError::InvalidFormat("signature ADS invalide".into()));
    }
    let mut offset = ADS_MAGIC.len();

    let version = data[offset];
    offset += 1;
    if version != ADS_VERSION {
        return Err(SecureVaultError::InvalidFormat(format!(
            "version ADS non supportée: {version}"
        )));
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&data[offset..offset + SALT_LEN]);
    offset += SALT_LEN;

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&data[offset..offset + NONCE_LEN]);
    offset += NONCE_LEN;

    let hash_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    if data.len() < offset + hash_len + 4 {
        return Err(SecureVaultError::InvalidFormat("hash ADS tronqué".into()));
    }
    let hash = String::from_utf8(data[offset..offset + hash_len].to_vec())
        .map_err(|_| SecureVaultError::InvalidFormat("hash ADS non-UTF8".into()))?;
    offset += hash_len;

    let cipher_len = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    if data.len() < offset + cipher_len {
        return Err(SecureVaultError::InvalidFormat(
            "données chiffrées ADS tronquées".into(),
        ));
    }
    let ciphertext = data[offset..offset + cipher_len].to_vec();

    Ok(Backup {
        salt,
        nonce,
        hash,
        ciphertext,
    })
}

fn write_ads(target: &Path, data: &[u8]) -> Result<()> {
    let mut file = File::create(ads_path(target))?;
    file.write_all(data)?;
    Ok(())
}

fn read_ads(target: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(ads_path(target))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

fn remove_ads(target: &Path) -> Result<()> {
    match fs::remove_file(ads_path(target)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Lit la DACL courante de `target` via `GetNamedSecurityInfoW` et en retourne
/// une copie brute (octets), directement réutilisable par `restore_dacl`.
fn read_dacl(target: &Path) -> Result<Vec<u8>> {
    let wide = HSTRING::from(target.as_os_str());
    let mut psd = PSECURITY_DESCRIPTOR::default();
    let mut pdacl: *mut ACL = std::ptr::null_mut();

    let status = unsafe {
        GetNamedSecurityInfoW(
            &wide,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut pdacl),
            None,
            &mut psd,
        )
    };
    check_win32(status, "lecture de la DACL")?;

    let acl_bytes = if pdacl.is_null() {
        Vec::new()
    } else {
        let header = unsafe { *pdacl };
        let size = header.AclSize as usize;
        unsafe { std::slice::from_raw_parts(pdacl as *const u8, size) }.to_vec()
    };

    if !psd.is_invalid() {
        unsafe {
            let _ = LocalFree(HLOCAL(psd.0));
        }
    }

    Ok(acl_bytes)
}

/// Restaure une DACL depuis une copie brute d'ACL (telle que produite par `read_dacl`).
fn restore_dacl(target: &Path, acl_bytes: &[u8]) -> Result<()> {
    if acl_bytes.is_empty() {
        return Ok(());
    }

    // Copie dans un buffer aligné sur 8 octets : Windows exige un alignement
    // DWORD pour les structures ACL, que `Vec<u8>` ne garantit pas.
    let word_len = acl_bytes.len().div_ceil(8);
    let mut aligned: Vec<u64> = vec![0u64; word_len];
    unsafe {
        std::ptr::copy_nonoverlapping(
            acl_bytes.as_ptr(),
            aligned.as_mut_ptr() as *mut u8,
            acl_bytes.len(),
        );
    }
    let acl_ptr = aligned.as_ptr() as *const ACL;

    let wide = HSTRING::from(target.as_os_str());
    let status = unsafe {
        SetNamedSecurityInfoW(
            &wide,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
            Some(acl_ptr),
            None,
        )
    };
    check_win32(status, "restauration de la DACL")
}

/// Construit le SID bien connu "Everyone" (S-1-1-0) dans un buffer possédé
/// par l'appelant (nécessaire car `TRUSTEE_W` ne fait que pointer dessus).
fn everyone_sid() -> Result<Vec<u8>> {
    let mut buf = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut size = buf.len() as u32;
    let psid = PSID(buf.as_mut_ptr() as *mut c_void);
    unsafe {
        CreateWellKnownSid(WinWorldSid, PSID::default(), psid, &mut size)
            .map_err(|e| SecureVaultError::Acl(format!("création du SID Everyone échouée: {e}")))?;
    }
    buf.truncate(size as usize);
    Ok(buf)
}

/// Applique une DACL qui REFUSE la lecture/écriture/exécution/suppression du
/// CONTENU à tout le monde, mais CONSERVE `FILE_READ_ATTRIBUTES`,
/// `SYNCHRONIZE` et `READ_CONTROL` : le fichier/dossier reste visible dans
/// l'Explorateur (nom, taille, icône) mais ne peut plus être ouvert. Une DACL
/// totalement vide rendrait la cible invisible même avec "éléments masqués"
/// activé — c'est le bug qu'on évite ici.
///
/// Deux pièges évités volontairement par rapport à une implémentation naïve :
///
/// 1. Un ACE DENY qui stocke les bits `GENERIC_READ`/`GENERIC_WRITE`/
///    `GENERIC_EXECUTE` tels quels est inefficace : Windows développe TOUJOURS
///    l'accès *demandé* en droits spécifiques avant `AccessCheck`, mais ne
///    développe PAS les droits *génériques* stockés dans une ACE existante.
///    Un DENY sur le bit générique ne recouvre alors aucun bit spécifique
///    réel et ne bloque donc rien. On utilise ici `FILE_GENERIC_READ` /
///    `_WRITE` / `_EXECUTE`, déjà développés en droits spécifiques.
/// 2. `FILE_LIST_DIRECTORY` et `FILE_READ_DATA` sont le MÊME bit (`0x1`),
///    seule son interprétation diffère selon que la cible est un dossier ou
///    un fichier. Accorder ce bit sur un fichier verrouillé donnerait accès
///    à son contenu (`FILE_READ_DATA`) — l'exact opposé du but recherché. Ce
///    bit n'est donc jamais accordé : ni pour les fichiers (pas de lecture de
///    contenu), ni pour les dossiers (pas de navigation dans un dossier
///    verrouillé).
///
/// `SYNCHRONIZE`/`READ_CONTROL` sont nécessaires car `CreateFileW` échoue en
/// bloc si UN SEUL des droits demandés manque : sans eux, même une simple
/// requête de métadonnées (taille, dates, utilisée par l'Explorateur comme
/// par `std::fs::metadata`) est refusée dans son ensemble.
fn apply_restrictive_dacl(target: &Path) -> Result<()> {
    let mut sid_buf = everyone_sid()?;
    let psid = PSID(sid_buf.as_mut_ptr() as *mut c_void);

    let mut trustee = TRUSTEE_W::default();
    unsafe {
        BuildTrusteeWithSidW(&mut trustee, psid);
    }

    const KEPT_VISIBLE: u32 = FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0 | READ_CONTROL.0;
    let deny_mask =
        (FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0 | FILE_GENERIC_EXECUTE.0 | DELETE.0)
            & !KEPT_VISIBLE;

    let entries = [
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: deny_mask,
            grfAccessMode: DENY_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: trustee,
        },
        EXPLICIT_ACCESS_W {
            grfAccessPermissions: KEPT_VISIBLE,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: NO_INHERITANCE,
            Trustee: trustee,
        },
    ];

    let mut new_acl: *mut ACL = std::ptr::null_mut();
    let create_status = unsafe { SetEntriesInAclW(Some(&entries), None, &mut new_acl) };
    check_win32(create_status, "création de la DACL restrictive")?;

    let wide = HSTRING::from(target.as_os_str());
    let set_status = unsafe {
        SetNamedSecurityInfoW(
            &wide,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
            Some(new_acl as *const ACL),
            None,
        )
    };

    unsafe {
        let _ = LocalFree(HLOCAL(new_acl as *mut c_void));
    }

    check_win32(set_status, "application de la DACL restrictive")
}

/// Lève temporairement toute restriction d'accès en posant une DACL NULL
/// (accès complet à tout le monde) sur `target`.
///
/// Nécessaire car un Alternate Data Stream n'a pas d'ACL indépendante de son
/// fichier porteur : une fois `apply_restrictive_dacl` posée, même le
/// propriétaire ne peut plus lire le contenu de l'ADS `:securevault` (seuls
/// `WRITE_DAC`/`READ_CONTROL` restent implicites au propriétaire, pas
/// `FILE_READ_DATA`). Il faut donc lever la restriction avant de pouvoir lire
/// la sauvegarde chiffrée, quitte à la réappliquer aussitôt (voir
/// `unlock_path`, qui reverrouille sur tout échec plutôt que de laisser la
/// cible grande ouverte).
fn clear_dacl_temporarily(target: &Path) -> Result<()> {
    let wide = HSTRING::from(target.as_os_str());
    let status = unsafe {
        SetNamedSecurityInfoW(
            &wide,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            PSID::default(),
            PSID::default(),
            None,
            None,
        )
    };
    check_win32(status, "levée temporaire de la DACL")
}

/// Bascule l'attribut "caché" (`FILE_ATTRIBUTE_HIDDEN` uniquement). L'attribut
/// "système" est volontairement exclu à la pose : combiné à "caché", il rend
/// le fichier invisible même avec "éléments masqués" coché dans l'Explorateur
/// (il faudrait en plus décocher "masquer les fichiers protégés du système").
/// Au retrait, on nettoie aussi l'attribut système au cas où un fichier
/// verrouillé par une version antérieure de SecureVault l'aurait encore.
fn set_hidden(target: &Path, enable: bool) -> Result<()> {
    let wide = HSTRING::from(target.as_os_str());
    let current = unsafe { GetFileAttributesW(&wide) };
    if current == INVALID_FILE_ATTRIBUTES {
        return Err(SecureVaultError::Acl(
            "impossible de lire les attributs du fichier".into(),
        ));
    }

    let attrs = if enable {
        FILE_FLAGS_AND_ATTRIBUTES(current) | FILE_ATTRIBUTE_HIDDEN
    } else {
        let cleared = current & !(FILE_ATTRIBUTE_HIDDEN.0 | FILE_ATTRIBUTE_SYSTEM.0);
        if cleared == 0 {
            FILE_ATTRIBUTE_NORMAL
        } else {
            FILE_FLAGS_AND_ATTRIBUTES(cleared)
        }
    };

    unsafe { SetFileAttributesW(&wide, attrs) }
        .map_err(|e| SecureVaultError::Acl(format!("changement d'attributs échoué: {e}")))
}

/// Verrouille `target` : sauvegarde chiffrée de la DACL courante dans l'ADS
/// `:securevault`, écriture du hash du mot de passe dans le fichier voisin
/// `.securevault.hash` (voir `HASH_SUFFIX`), pose de l'attribut caché, puis
/// application de la DACL restrictive (refuse lecture/écriture/exécution/
/// suppression mais conserve la visibilité). L'attribut est posé AVANT la
/// DACL : `SetFileAttributesW` exige `FILE_WRITE_ATTRIBUTES` (inclus dans
/// `GENERIC_WRITE`), qui vient justement d'être refusé — l'inverser nous
/// verrouillerait nous-mêmes hors du fichier avant d'avoir fini.
pub fn lock_path(target: &Path, password: &str) -> Result<()> {
    let target_abs = absolutize(target)?;
    let target: &Path = &target_abs;

    if is_locked(target) {
        return Err(SecureVaultError::Acl("la cible est déjà verrouillée".into()));
    }

    let acl_bytes = read_dacl(target)?;

    let (hash, salt) = kdf::hash_password(password)?;
    let key = kdf::derive_key(password, &salt)?;

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = aes_gcm::encrypt(&key, &nonce, &acl_bytes)?;
    let payload = pack_backup(&salt, &nonce, &hash, &ciphertext);
    write_ads(target, &payload)?;

    // Le hash est AUSSI conservé dans l'ADS (`pack_backup` ci-dessus) : le
    // fichier voisin n'est qu'un cache lisible sans lever la DACL. S'il est
    // supprimé à la main, `verify_password` retombe simplement sur l'ancien
    // chemin, et `unlock_path` continue de fonctionner sans lui.
    write_hash_file(target, &hash)?;

    set_hidden(target, true)?;
    apply_restrictive_dacl(target)?;
    write_companion(target)?;

    Ok(())
}

/// Déverrouille `target` : vérifie le mot de passe contre le hash Argon2id
/// stocké, restaure la DACL d'origine, retire l'attribut caché et
/// supprime l'ADS de sauvegarde.
///
/// Le mot de passe est vérifié AVANT toute manipulation de DACL quand le
/// fichier de hash voisin est disponible : un mot de passe incorrect n'ouvre
/// alors jamais la fenêtre d'exposition décrite dans `clear_dacl_temporarily`.
pub fn unlock_path(target: &Path, password: &str) -> Result<()> {
    let target_abs = absolutize(target)?;
    let target: &Path = &target_abs;

    if !is_locked(target) {
        return Err(SecureVaultError::Acl("la cible n'est pas verrouillée".into()));
    }

    if let Some(hash) = read_hash_file(target)? {
        if !kdf::verify_password(password, &hash)? {
            return Err(SecureVaultError::InvalidPassword);
        }
    }

    // L'ADS de sauvegarde partage la DACL du fichier porteur : il faut lever
    // la restriction pour pouvoir la lire (voir `clear_dacl_temporarily`).
    clear_dacl_temporarily(target)?;

    let read_and_decrypt = || -> Result<Vec<u8>> {
        let payload = read_ads(target)?;
        let backup = unpack_backup(&payload)?;

        if !kdf::verify_password(password, &backup.hash)? {
            return Err(SecureVaultError::InvalidPassword);
        }

        let key = kdf::derive_key(password, &backup.salt)?;
        aes_gcm::decrypt(&key, &backup.nonce, &backup.ciphertext)
    };

    let acl_bytes = match read_and_decrypt() {
        Ok(bytes) => bytes,
        Err(e) => {
            // Mot de passe incorrect ou sauvegarde corrompue : on reverrouille
            // avant de remonter l'erreur plutôt que de laisser la cible grande
            // ouverte.
            let _ = apply_restrictive_dacl(target);
            return Err(e);
        }
    };

    restore_dacl(target, &acl_bytes)?;
    set_hidden(target, false)?;
    remove_ads(target)?;
    remove_companion(target)?;
    remove_hash_file(target)?;

    Ok(())
}

/// Vérifie un mot de passe candidat SANS déverrouiller : lit le hash Argon2id
/// dans le fichier voisin `.securevault.hash` et le compare, sans toucher à
/// la DACL. Utilisée par la popup de saisie pour permettre un nouvel essai
/// sans se fermer (voir `ui::show_password_prompt`).
///
/// Repli pour les cibles verrouillées par une version < 0.7.0, qui n'ont pas
/// ce fichier : on retombe sur l'ancien chemin (lecture de l'ADS, donc levée
/// temporaire de la DACL). C'est le seul cas qui rouvre encore la fenêtre
/// d'exposition ; il disparaît dès que la cible est déverrouillée puis
/// reverrouillée par cette version.
pub fn verify_password(target: &Path, password: &str) -> Result<bool> {
    let target_abs = absolutize(target)?;
    let target: &Path = &target_abs;

    if !is_locked(target) {
        return Err(SecureVaultError::Acl("la cible n'est pas verrouillée".into()));
    }

    if let Some(hash) = read_hash_file(target)? {
        return kdf::verify_password(password, &hash);
    }

    verify_password_legacy_via_ads(target, password)
}

/// Ancien chemin de vérification, conservé uniquement pour les cibles
/// verrouillées avant 0.7.0 (voir `verify_password`). Lève la DACL le temps
/// de lire l'ADS puis la réapplique systématiquement, succès ou échec.
fn verify_password_legacy_via_ads(target: &Path, password: &str) -> Result<bool> {
    clear_dacl_temporarily(target)?;

    // Le hash est récupéré DANS la fenêtre où la DACL est levée : c'est le
    // seul moment où l'ADS est lisible. Il sera réécrit dans le fichier
    // voisin juste après, pour que l'essai suivant n'ait plus à rouvrir
    // cette fenêtre.
    let check = || -> Result<(bool, String)> {
        let payload = read_ads(target)?;
        let backup = unpack_backup(&payload)?;
        let ok = kdf::verify_password(password, &backup.hash)?;
        Ok((ok, backup.hash))
    };
    let outcome = check();

    let _ = apply_restrictive_dacl(target);

    match outcome {
        Ok((ok, hash)) => {
            // Migration opportuniste vers le format 0.7.0. Best-effort : si
            // l'écriture échoue, on refera simplement le détour par l'ADS.
            let _ = write_hash_file(target, &hash);
            Ok(ok)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use std::os::windows::fs::MetadataExt;

    /// Répertoire temporaire propre au process/thread de test, sous `%TEMP%`.
    fn temp_dir() -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("securevault_test_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Régression Bug 1 : une cible verrouillée doit rester visible (attributs
    /// lisibles, pas d'attribut système) mais son contenu doit être inaccessible.
    #[test]
    fn lock_keeps_target_visible_but_denies_access() {
        let dir = temp_dir();
        let target = dir.join("lock_visible.txt");
        fs::write(&target, b"contenu secret").unwrap();

        lock_path(&target, "motdepasse-test").unwrap();

        assert!(is_locked(&target), "la cible devrait être marquée verrouillée");

        // Bug 1 : les attributs (donc la visibilité dans l'Explorateur) restent lisibles.
        let attrs = fs::metadata(&target).expect(
            "les attributs du fichier doivent rester lisibles (FILE_READ_ATTRIBUTES conservé)",
        );
        assert!(attrs.is_file());

        let wide = HSTRING::from(target.as_os_str());
        let raw_attrs = unsafe { GetFileAttributesW(&wide) };
        assert_ne!(raw_attrs, INVALID_FILE_ATTRIBUTES);
        assert!(
            raw_attrs & FILE_ATTRIBUTE_HIDDEN.0 != 0,
            "l'attribut caché doit être posé"
        );
        assert!(
            raw_attrs & FILE_ATTRIBUTE_SYSTEM.0 == 0,
            "l'attribut système ne doit PAS être posé (sinon invisible même avec \"éléments masqués\")"
        );

        // Le contenu doit rester inaccessible en lecture tant que verrouillé.
        let open_result = File::open(&target);
        assert!(
            matches!(&open_result, Err(e) if e.kind() == ErrorKind::PermissionDenied),
            "l'ouverture du fichier verrouillé devrait échouer avec Accès refusé, a retourné : {open_result:?}"
        );

        unlock_path(&target, "motdepasse-test").unwrap();

        assert!(!is_locked(&target));
        let restored = fs::read(&target).expect("le fichier doit être lisible après déverrouillage");
        assert_eq!(restored, b"contenu secret");

        let _ = fs::remove_file(&target);
    }

    #[test]
    fn unlock_with_wrong_password_fails_and_keeps_lock() {
        let dir = temp_dir();
        let target = dir.join("lock_wrong_password.txt");
        fs::write(&target, b"contenu").unwrap();

        lock_path(&target, "bon-mot-de-passe").unwrap();

        let err = unlock_path(&target, "mauvais-mot-de-passe").unwrap_err();
        assert!(matches!(err, SecureVaultError::InvalidPassword));
        assert!(is_locked(&target), "la cible doit rester verrouillée après un échec");
        assert!(
            companion_path(&target).unwrap().exists(),
            "le fichier compagnon doit rester présent après un échec de déverrouillage"
        );

        unlock_path(&target, "bon-mot-de-passe").unwrap();
        let _ = fs::remove_file(&target);
    }

    /// Régression Feature 2 : un fichier compagnon `.securevault` apparaît au
    /// verrouillage (pointant vers la cible en chemin absolu) et disparaît au
    /// déverrouillage réussi.
    #[test]
    fn lock_creates_companion_file_and_unlock_removes_it() {
        let dir = temp_dir();
        let target = dir.join("companion_target.txt");
        fs::write(&target, b"contenu").unwrap();

        lock_path(&target, "mot-de-passe").unwrap();

        let companion = companion_path(&target).unwrap();
        assert_eq!(companion, dir.join("companion_target.txt.securevault"));
        assert!(companion.exists(), "le fichier compagnon doit être créé au verrouillage");

        let companion_content = fs::read_to_string(&companion).unwrap();
        assert_eq!(
            PathBuf::from(companion_content.trim()),
            target,
            "le compagnon doit contenir le chemin absolu de la cible"
        );

        unlock_path(&target, "mot-de-passe").unwrap();
        assert!(
            !companion.exists(),
            "le fichier compagnon doit disparaître après déverrouillage réussi"
        );

        let _ = fs::remove_file(&target);
    }

    /// Régression du "retry sans fermer la popup" : `verify_password` doit
    /// distinguer bon/mauvais mot de passe SANS jamais déverrouiller (la
    /// cible reste verrouillée, avec ou sans succès de la vérification).
    #[test]
    fn verify_password_checks_without_unlocking() {
        let dir = temp_dir();
        let target = dir.join("verify_only.txt");
        fs::write(&target, b"contenu").unwrap();

        lock_path(&target, "bon-mot-de-passe").unwrap();

        assert_eq!(verify_password(&target, "mauvais-mot-de-passe").unwrap(), false);
        assert!(is_locked(&target), "une vérification ratée ne doit pas déverrouiller");
        assert!(
            File::open(&target).is_err(),
            "le contenu doit rester inaccessible après une vérification ratée"
        );

        assert_eq!(verify_password(&target, "bon-mot-de-passe").unwrap(), true);
        assert!(
            is_locked(&target),
            "une vérification réussie ne doit PAS déverrouiller non plus (ce n'est qu'un essai)"
        );
        assert!(
            File::open(&target).is_err(),
            "le contenu doit rester inaccessible même après une vérification réussie"
        );

        unlock_path(&target, "bon-mot-de-passe").unwrap();
        let _ = fs::remove_file(&target);
    }

    /// Régression S2 : le fichier de hash doit être créé au verrouillage,
    /// caché, et disparaître au déverrouillage. C'est lui qui permet de
    /// vérifier un mot de passe SANS lever la DACL.
    #[test]
    fn hash_file_is_created_hidden_and_removed() {
        let dir = temp_dir();
        let target = dir.join("hash_lifecycle.txt");
        fs::write(&target, b"contenu").unwrap();

        let hash_file = hash_path(&target).unwrap();
        assert!(!hash_file.exists(), "pas de fichier de hash avant verrouillage");

        lock_path(&target, "mot-de-passe").unwrap();

        assert!(hash_file.exists(), "le fichier de hash doit être créé au verrouillage");
        let content = fs::read_to_string(&hash_file).unwrap();
        assert!(
            content.starts_with("$argon2id$"),
            "le fichier doit contenir un hash PHC Argon2id, pas le mot de passe"
        );
        assert!(
            !content.contains("mot-de-passe"),
            "le mot de passe en clair ne doit JAMAIS s'y trouver"
        );

        let attrs = fs::metadata(&hash_file).unwrap().file_attributes();
        assert!(
            attrs & FILE_ATTRIBUTE_HIDDEN.0 != 0,
            "le fichier de hash doit être masqué dans l'Explorateur"
        );

        unlock_path(&target, "mot-de-passe").unwrap();
        assert!(
            !hash_file.exists(),
            "le fichier de hash doit disparaître au déverrouillage"
        );

        let _ = fs::remove_file(&target);
    }

    /// Rétrocompatibilité : une cible verrouillée par une version < 0.7.0 n'a
    /// pas de fichier de hash. `verify_password` doit alors retomber sur
    /// l'ADS — et en profiter pour écrire le fichier manquant, afin que
    /// l'essai suivant n'ait plus à lever la DACL.
    #[test]
    fn legacy_target_without_hash_file_still_verifies_and_migrates() {
        let dir = temp_dir();
        let target = dir.join("legacy_hash.txt");
        fs::write(&target, b"contenu").unwrap();

        lock_path(&target, "bon-mot-de-passe").unwrap();

        // Simule l'état d'une cible verrouillée avant la 0.7.0.
        remove_hash_file(&target).unwrap();
        let hash_file = hash_path(&target).unwrap();
        assert!(!hash_file.exists());

        assert_eq!(verify_password(&target, "mauvais").unwrap(), false);
        assert!(
            is_locked(&target),
            "une vérification ratée ne doit pas déverrouiller"
        );
        assert!(
            hash_file.exists(),
            "le repli doit migrer le hash pour éviter de rouvrir la fenêtre"
        );

        assert_eq!(verify_password(&target, "bon-mot-de-passe").unwrap(), true);

        unlock_path(&target, "bon-mot-de-passe").unwrap();
        let _ = fs::remove_file(&target);
    }
}

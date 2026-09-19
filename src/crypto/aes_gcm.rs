use crate::crypto::archive;
use crate::crypto::kdf;
use crate::crypto::recovery;
use crate::errors::{Result, SecureVaultError};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

const VAULT_MAGIC: &[u8; 4] = b"SVLT";
/// Format historique (≤ 1.0.0) : données chiffrées directement avec la clé
/// dérivée du mot de passe. Lu, plus jamais écrit.
const VAULT_VERSION_V1: u8 = 1;
/// Format à double enveloppe (1.0.1) : voir `encrypt_to_vault`.
const VAULT_VERSION_V2: u8 = 2;
const VAULT_EXTENSION: &str = "vault";

/// Une clé AES-256 chiffrée en AES-256-GCM : 32 octets + tag de 16.
const WRAPPED_KEY_LEN: usize = KEY_LEN + TAG_LEN;
/// Magic + version + sel : commun aux deux formats.
const PREFIX_LEN: usize = 4 + 1 + kdf::SALT_LEN;
/// En-tête fixe v1 (nom d'origine exclu) : préfixe | nonce données |
/// recovery key chiffrée | longueur du nom.
const HEADER_V1_LEN: usize = PREFIX_LEN + NONCE_LEN + recovery::RECOVERY_KEY_ENCRYPTED_LEN + 2;
/// En-tête fixe v2 (nom d'origine exclu) : préfixe | nonce + FEK chiffrée
/// par le mot de passe | nonce + FEK chiffrée par la recovery key | nonce
/// données | longueur du nom. Soit 171 octets.
const HEADER_V2_LEN: usize = PREFIX_LEN + 2 * (NONCE_LEN + WRAPPED_KEY_LEN) + NONCE_LEN + 2;

/// Chiffre `plaintext` avec AES-256-GCM. Le nonce doit être généré aléatoirement
/// et n'être jamais réutilisé avec la même clé. Le tag d'authentification (16
/// octets) est ajouté à la fin du résultat.
pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_with_aad(key, nonce, plaintext, b"")
}

/// Déchiffre des données AES-256-GCM (avec tag en fin de buffer) et vérifie
/// l'authenticité via le tag GCM.
pub fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>> {
    decrypt_with_aad(key, nonce, ciphertext, b"")
}

/// Comme `encrypt`, en authentifiant aussi `aad` (non chiffré). Le déchiffrement
/// échoue si `aad` a changé d'un seul octet.
fn encrypt_with_aad(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|e| SecureVaultError::Crypto(format!("chiffrement AES-256-GCM échoué: {e}")))
}

fn decrypt_with_aad(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|e| SecureVaultError::Crypto(format!("déchiffrement AES-256-GCM échoué: {e}")))
}

/// Chiffre une clé de 32 octets (la FEK) avec une autre clé de 32 octets.
fn wrap_key(
    wrapping_key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    key: &[u8; KEY_LEN],
) -> Result<[u8; WRAPPED_KEY_LEN]> {
    encrypt(wrapping_key, nonce, key)?
        .try_into()
        .map_err(|_| SecureVaultError::Crypto("taille inattendue pour une clé chiffrée".into()))
}

/// Inverse de `wrap_key`. `None` si le tag GCM ne correspond pas, c'est-à-dire
/// si `wrapping_key` n'est pas la bonne — cas normal d'un mauvais secret, pas
/// une erreur.
fn unwrap_key(
    wrapping_key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    wrapped: &[u8; WRAPPED_KEY_LEN],
) -> Option<Zeroizing<[u8; KEY_LEN]>> {
    let plain = Zeroizing::new(decrypt(wrapping_key, nonce, wrapped).ok()?);
    let key: [u8; KEY_LEN] = plain.as_slice().try_into().ok()?;
    Some(Zeroizing::new(key))
}

/// Rend un chemin absolu sans exiger qu'il existe déjà (contrairement à
/// `fs::canonicalize`, et sans le préfixe `\\?\` que celui-ci ajoute sous
/// Windows). Indispensable ici : lancé depuis le menu contextuel de
/// l'Explorateur, le répertoire de travail du process n'a aucun rapport avec
/// le dossier du fichier ciblé, donc tout chemin relatif doit être résolu
/// explicitement plutôt que de compter sur le current directory.
fn absolutize(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Cœur commun au chiffrement fichier et dossier : chiffre `plaintext` et
/// écrit le fichier `.vault` v2 à `vault_path`, avec `stored_name` inscrit
/// dans l'en-tête (utilisé pour restaurer le nom — et distinguer
/// fichier/dossier — au déchiffrement).
///
/// **Double enveloppe** (1.0.1) :
/// 1. une clé de chiffrement de fichier (FEK) de 256 bits est tirée au hasard ;
/// 2. les données sont chiffrées avec la FEK ;
/// 3. la FEK est chiffrée une première fois avec la clé dérivée du mot de
///    passe (Argon2id), une seconde fois avec la recovery key elle-même.
///
/// Chacun des deux secrets suffit donc, seul, à retrouver la FEK. Jusqu'à la
/// 1.0.0, les données étaient chiffrées avec la clé du mot de passe et la
/// recovery key était enveloppée PAR cette même clé : sans le mot de passe,
/// la recovery key était illisible, donc inutile.
///
/// La recovery key n'est pas stockée dans le fichier (seule la FEK chiffrée
/// par elle l'est). Elle est retournée en base64 dans un `Zeroizing` : elle
/// transite jusqu'à l'affichage et jusqu'au registre, où elle est re-chiffrée
/// avec le Master Password (voir `dashboard::registry`).
///
/// L'en-tête complet (nom compris) est passé en données associées au
/// chiffrement des données : modifier le nom stocké, un nonce ou une
/// enveloppe fait échouer le déchiffrement au lieu de restaurer silencieusement
/// sous un autre nom.
fn encrypt_to_vault(
    vault_path: &Path,
    stored_name: &str,
    plaintext: &[u8],
    password: &str,
) -> Result<Zeroizing<String>> {
    if stored_name.len() > u16::MAX as usize {
        return Err(SecureVaultError::Crypto("nom stocké trop long".into()));
    }
    if vault_path.exists() {
        return Err(SecureVaultError::Crypto(format!(
            "le fichier '{}' existe déjà",
            vault_path.display()
        )));
    }

    let mut salt = [0u8; kdf::SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let password_nonce = random_nonce();
    let recovery_nonce = random_nonce();
    let data_nonce = random_nonce();

    let mut fek = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(fek.as_mut());

    let fek_by_password = {
        let password_key = kdf::derive_key(password, &salt)?;
        wrap_key(&password_key, &password_nonce, &fek)?
    };
    let (recovery_key, recovery_b64) = recovery::generate_recovery_key()?;
    let fek_by_recovery = wrap_key(&recovery_key, &recovery_nonce, &fek)?;
    // Les 32 octets bruts n'ont plus d'utilité une fois la FEK enveloppée.
    drop(recovery_key);

    let mut out = Vec::with_capacity(HEADER_V2_LEN + stored_name.len() + plaintext.len() + TAG_LEN);
    out.extend_from_slice(VAULT_MAGIC);
    out.push(VAULT_VERSION_V2);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&password_nonce);
    out.extend_from_slice(&fek_by_password);
    out.extend_from_slice(&recovery_nonce);
    out.extend_from_slice(&fek_by_recovery);
    out.extend_from_slice(&data_nonce);
    out.extend_from_slice(&(stored_name.len() as u16).to_le_bytes());
    out.extend_from_slice(stored_name.as_bytes());
    debug_assert_eq!(out.len(), HEADER_V2_LEN + stored_name.len());

    let ciphertext = encrypt_with_aad(&fek, &data_nonce, plaintext, &out)?;
    out.extend_from_slice(&ciphertext);

    fs::write(vault_path, out)?;

    Ok(recovery_b64)
}

/// Chiffre un fichier en mode Chiffrement Fort et écrit le résultat dans
/// `<source>.vault` (format v2, voir `encrypt_to_vault`).
///
/// Le `.vault` est toujours écrit à côté du fichier source (même dossier
/// parent), quel que soit le répertoire de travail du process.
pub fn encrypt_file(source_path: &Path, password: &str) -> Result<(PathBuf, Zeroizing<String>)> {
    let source_path = absolutize(source_path)?;

    if !source_path.is_file() {
        return Err(SecureVaultError::Crypto(format!(
            "'{}' n'est pas un fichier",
            source_path.display()
        )));
    }

    let file_name = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            SecureVaultError::Crypto("nom de fichier source invalide (non-UTF8)".into())
        })?;
    let parent = source_path.parent().ok_or_else(|| {
        SecureVaultError::Crypto("le chemin source n'a pas de dossier parent".into())
    })?;
    let vault_path = parent.join(format!("{file_name}.{VAULT_EXTENSION}"));

    // Contenu en clair du fichier source : `Zeroizing` pour qu'il ne reste pas
    // en mémoire après l'écriture du `.vault`.
    let plaintext = Zeroizing::new(fs::read(&source_path)?);
    let recovery_b64 = encrypt_to_vault(&vault_path, file_name, &plaintext, password)?;

    Ok((vault_path, recovery_b64))
}

/// Chiffre un dossier entier : empaquette son contenu en archive tar (voir
/// `archive::pack_directory`) puis le chiffre comme un fichier. Le nom stocké
/// dans l'en-tête se termine par `/` pour marquer que c'est un dossier (voir
/// `decrypt_path`). Le `.vault` est créé dans le dossier PARENT du dossier
/// source, nommé `<NomDuDossier>.vault`.
fn encrypt_directory(source_path: &Path, password: &str) -> Result<(PathBuf, Zeroizing<String>)> {
    let dir_name = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            SecureVaultError::Crypto("nom de dossier source invalide (non-UTF8)".into())
        })?;
    let parent = source_path.parent().ok_or_else(|| {
        SecureVaultError::Crypto("le chemin source n'a pas de dossier parent".into())
    })?;
    let vault_path = parent.join(format!("{dir_name}.{VAULT_EXTENSION}"));
    let stored_name = format!("{dir_name}/");

    // L'archive tar contient l'intégralité du dossier en clair : même
    // traitement que le contenu d'un fichier (voir `encrypt_file`).
    let plaintext = Zeroizing::new(archive::pack_directory(source_path)?);
    let recovery_b64 = encrypt_to_vault(&vault_path, &stored_name, &plaintext, password)?;

    Ok((vault_path, recovery_b64))
}

/// Point d'entrée du chiffrement fort : détecte si `source_path` est un
/// fichier ou un dossier et délègue en conséquence. Voir `encrypt_file` /
/// `encrypt_directory`.
pub fn encrypt_path(source_path: &Path, password: &str) -> Result<(PathBuf, Zeroizing<String>)> {
    let source_path = absolutize(source_path)?;
    if source_path.is_dir() {
        encrypt_directory(&source_path, password)
    } else if source_path.is_file() {
        encrypt_file(&source_path, password)
    } else {
        Err(SecureVaultError::Crypto(format!(
            "'{}' n'est ni un fichier ni un dossier",
            source_path.display()
        )))
    }
}

/// Enveloppe de clé d'un `.vault`, selon sa version.
enum Envelope {
    /// v1 : données chiffrées avec la clé dérivée du mot de passe. La recovery
    /// key enveloppée par cette même clé ne sert qu'à vérifier un mot de passe
    /// sans tout déchiffrer.
    V1 {
        data_nonce: [u8; NONCE_LEN],
        recovery_encrypted: [u8; recovery::RECOVERY_KEY_ENCRYPTED_LEN],
    },
    /// v2 : FEK enveloppée deux fois, données chiffrées par la FEK.
    V2 {
        password_nonce: [u8; NONCE_LEN],
        fek_by_password: [u8; WRAPPED_KEY_LEN],
        recovery_nonce: [u8; NONCE_LEN],
        fek_by_recovery: [u8; WRAPPED_KEY_LEN],
        data_nonce: [u8; NONCE_LEN],
    },
}

/// Partie fixe de l'en-tête d'un `.vault` (tout sauf le nom d'origine).
struct VaultHeader {
    salt: [u8; kdf::SALT_LEN],
    envelope: Envelope,
    /// Taille de la partie fixe : le nom d'origine commence à cet offset.
    fixed_len: usize,
    name_len: usize,
}

/// Longueur de l'en-tête fixe pour une version donnée.
fn fixed_header_len(version: u8) -> Result<usize> {
    match version {
        VAULT_VERSION_V1 => Ok(HEADER_V1_LEN),
        VAULT_VERSION_V2 => Ok(HEADER_V2_LEN),
        other => Err(SecureVaultError::InvalidFormat(format!(
            "version .vault non supportée: {other}"
        ))),
    }
}

/// Curseur de lecture minimal : les longueurs ont été vérifiées en amont par
/// `parse_fixed_header`, les tranches lues ici existent donc toujours.
struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl Cursor<'_> {
    fn take<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(&self.data[self.offset..self.offset + N]);
        self.offset += N;
        out
    }
}

/// Analyse la partie fixe de l'en-tête (magic, version, sel, enveloppes,
/// nonces, longueur du nom). `data` peut ne contenir que le début du fichier.
fn parse_fixed_header(data: &[u8]) -> Result<VaultHeader> {
    if data.len() < PREFIX_LEN {
        return Err(SecureVaultError::InvalidFormat("en-tête .vault tronqué".into()));
    }
    if &data[0..4] != VAULT_MAGIC {
        return Err(SecureVaultError::InvalidFormat("signature .vault invalide".into()));
    }
    let version = data[4];
    let fixed_len = fixed_header_len(version)?;
    if data.len() < fixed_len {
        return Err(SecureVaultError::InvalidFormat("en-tête .vault tronqué".into()));
    }

    let mut cursor = Cursor { data, offset: 5 };
    let salt = cursor.take::<{ kdf::SALT_LEN }>();
    let envelope = if version == VAULT_VERSION_V1 {
        Envelope::V1 {
            data_nonce: cursor.take(),
            recovery_encrypted: cursor.take(),
        }
    } else {
        Envelope::V2 {
            password_nonce: cursor.take(),
            fek_by_password: cursor.take(),
            recovery_nonce: cursor.take(),
            fek_by_recovery: cursor.take(),
            data_nonce: cursor.take(),
        }
    };
    let name_len = u16::from_le_bytes(cursor.take::<2>()) as usize;
    debug_assert_eq!(cursor.offset, fixed_len);

    Ok(VaultHeader {
        salt,
        envelope,
        fixed_len,
        name_len,
    })
}

/// Refuse un nom stocké qui sortirait du dossier du `.vault` une fois joint à
/// celui-ci. Un nom écrit par SecureVault est toujours un simple nom de
/// fichier (plus `/` final pour un dossier) ; tout le reste signale un
/// fichier fabriqué ou abîmé. En v1 le nom n'est pas authentifié, d'où ce
/// contrôle explicite plutôt que de compter sur le tag GCM.
fn validate_stored_name(name: &str) -> Result<()> {
    let base = name.strip_suffix('/').unwrap_or(name);
    let invalid = base.is_empty()
        || base == "."
        || base == ".."
        || base.contains(['/', '\\', ':']);
    if invalid {
        return Err(SecureVaultError::InvalidFormat(
            "nom d'origine .vault invalide".into(),
        ));
    }
    Ok(())
}

/// Retrouve la FEK d'un `.vault` v2 à partir d'un secret qui est SOIT le mot
/// de passe, SOIT la recovery key.
///
/// Une saisie qui a la forme d'une recovery key (voir
/// `recovery::parse_recovery_key`) est d'abord essayée comme telle —
/// instantané, pas d'Argon2id. En cas d'échec, ou si la saisie n'a pas cette
/// forme, elle est essayée comme mot de passe : un mot de passe peut très bien
/// ressembler à du base64 de 44 caractères.
///
/// `Ok(None)` : ni l'un ni l'autre ne convient (mauvais secret). Les erreurs
/// ne concernent que la dérivation de clé elle-même.
fn unwrap_fek(
    salt: &[u8; kdf::SALT_LEN],
    envelope: &Envelope,
    secret: &str,
) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>> {
    let Envelope::V2 {
        password_nonce,
        fek_by_password,
        recovery_nonce,
        fek_by_recovery,
        ..
    } = envelope
    else {
        return Ok(None);
    };

    if let Some(recovery_key) = recovery::parse_recovery_key(secret) {
        if let Some(fek) = unwrap_key(&recovery_key, recovery_nonce, fek_by_recovery) {
            return Ok(Some(fek));
        }
    }
    let password_key = kdf::derive_key(secret, salt)?;
    Ok(unwrap_key(&password_key, password_nonce, fek_by_password))
}

/// Résultat d'un déchiffrement réussi.
pub struct DecryptOutcome {
    /// Fichier ou dossier restauré.
    pub output_path: PathBuf,
    /// Le `.vault` était au format v1 (≤ 1.0.0), dont la recovery key n'a
    /// jamais été utilisable : l'appelant doit le signaler.
    pub legacy_format: bool,
}

/// Déchiffre un fichier `.vault` et restaure le fichier ou le dossier
/// d'origine (selon que le nom stocké se termine par `/`), sous son nom
/// d'origine, dans le dossier contenant le `.vault` (jamais dans le
/// répertoire de travail du process, qui n'a aucun rapport avec
/// l'emplacement du fichier quand l'exe est lancé depuis l'Explorateur).
///
/// `secret` est le mot de passe OU la recovery key (v2 uniquement), détectés
/// automatiquement — voir `unwrap_fek`. Un secret qui ne convient pas donne
/// `SecureVaultError::InvalidPassword`.
pub fn decrypt_path(vault_path: &Path, secret: &str) -> Result<DecryptOutcome> {
    let vault_path = absolutize(vault_path)?;
    let data = fs::read(&vault_path)?;
    let header = parse_fixed_header(&data)?;

    let name_end = header.fixed_len + header.name_len;
    if data.len() < name_end {
        return Err(SecureVaultError::InvalidFormat("nom de fichier .vault tronqué".into()));
    }
    let original_name = std::str::from_utf8(&data[header.fixed_len..name_end])
        .map_err(|_| SecureVaultError::InvalidFormat("nom de fichier .vault non-UTF8".into()))?;
    validate_stored_name(original_name)?;
    let (header_bytes, ciphertext) = data.split_at(name_end);

    // Données déchiffrées : contenu en clair du fichier (ou archive tar du
    // dossier). `Zeroizing` pour qu'elles ne survivent pas à l'écriture sur
    // disque, y compris si `unpack_directory`/`fs::write` échoue.
    let plaintext = match &header.envelope {
        Envelope::V1 { data_nonce, .. } => {
            // Le tag GCM valide à la fois l'intégrité et le mot de passe :
            // une mauvaise clé fait échouer la vérification.
            let key = kdf::derive_key(secret, &header.salt)?;
            Zeroizing::new(
                decrypt(&key, data_nonce, ciphertext).map_err(|_| SecureVaultError::InvalidPassword)?,
            )
        }
        Envelope::V2 { data_nonce, .. } => {
            let fek = unwrap_fek(&header.salt, &header.envelope, secret)?
                .ok_or(SecureVaultError::InvalidPassword)?;
            // La FEK est authentique à ce stade : un échec ici n'est pas un
            // mauvais secret mais un fichier modifié ou abîmé.
            Zeroizing::new(
                decrypt_with_aad(&fek, data_nonce, ciphertext, header_bytes).map_err(|_| {
                    SecureVaultError::InvalidFormat("données .vault corrompues ou modifiées".into())
                })?,
            )
        }
    };
    let legacy_format = matches!(header.envelope, Envelope::V1 { .. });

    let parent = vault_path.parent().ok_or_else(|| {
        SecureVaultError::Crypto("le chemin .vault n'a pas de dossier parent".into())
    })?;

    let output_path = if let Some(dir_name) = original_name.strip_suffix('/') {
        let output_path = parent.join(dir_name);
        if output_path.exists() {
            return Err(SecureVaultError::Crypto(format!(
                "le dossier de destination '{}' existe déjà",
                output_path.display()
            )));
        }
        archive::unpack_directory(&plaintext, &output_path)?;
        output_path
    } else {
        let output_path = parent.join(original_name);
        if output_path.exists() {
            return Err(SecureVaultError::Crypto(format!(
                "le fichier de destination '{}' existe déjà",
                output_path.display()
            )));
        }
        fs::write(&output_path, &*plaintext)?;
        output_path
    };

    Ok(DecryptOutcome {
        output_path,
        legacy_format,
    })
}

/// Lit la partie fixe de l'en-tête sans charger tout le fichier.
fn read_fixed_header(vault_path: &Path) -> Result<VaultHeader> {
    let vault_path = absolutize(vault_path)?;
    let mut head = Vec::with_capacity(HEADER_V2_LEN);
    // Un `.vault` v1 peut être plus court qu'un en-tête v2 : lire AU PLUS
    // cette taille, et laisser `parse_fixed_header` juger selon la version.
    fs::File::open(&vault_path)?
        .take(HEADER_V2_LEN.max(HEADER_V1_LEN) as u64)
        .read_to_end(&mut head)?;
    parse_fixed_header(&head)
}

/// Indique si `vault_path` est un `.vault` v1, dont la recovery key n'est pas
/// utilisable. Sert à adapter la popup de saisie ; `false` pour tout fichier
/// illisible (le déchiffrement remontera alors l'erreur réelle).
pub fn is_legacy_vault(vault_path: &Path) -> bool {
    matches!(
        read_fixed_header(vault_path),
        Ok(VaultHeader {
            envelope: Envelope::V1 { .. },
            ..
        })
    )
}

/// Vérifie qu'un secret (mot de passe, ou recovery key pour un `.vault` v2)
/// ouvre un fichier `.vault`, en ne lisant que l'en-tête : v2 déchiffre la
/// FEK (48 octets), v1 la recovery key enveloppée (48 octets). Utilisée par la
/// popup de saisie pour permettre un nouvel essai sans se fermer (voir
/// `ui::show_decrypt_prompt`) : bien moins coûteux qu'un déchiffrement
/// complet sur un gros fichier/dossier.
///
/// Ne retourne `Ok(false)` que pour un secret incorrect ; toute autre erreur
/// (fichier introuvable, format invalide) est propagée telle quelle.
pub fn verify_password(vault_path: &Path, secret: &str) -> Result<bool> {
    let header = read_fixed_header(vault_path)?;
    match &header.envelope {
        Envelope::V1 {
            recovery_encrypted, ..
        } => {
            let key = kdf::derive_key(secret, &header.salt)?;
            Ok(recovery::decrypt_recovery_key_v1(recovery_encrypted, &key, &header.salt).is_ok())
        }
        Envelope::V2 { .. } => Ok(unwrap_fek(&header.salt, &header.envelope, secret)?.is_some()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Répertoire temporaire propre au process de test, sous `%TEMP%`.
    fn temp_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("securevault_crypto_test_{}_{name}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Fabrique un `.vault` au format v1 exactement comme la 1.0.0 l'écrivait,
    /// pour vérifier la rétrocompatibilité. Retourne la recovery key de
    /// l'époque, pour prouver qu'elle ne permet PAS de déchiffrer.
    fn write_v1_vault(vault_path: &Path, stored_name: &str, plaintext: &[u8], password: &str) -> String {
        let mut salt = [0u8; kdf::SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let nonce = random_nonce();
        let key = kdf::derive_key(password, &salt).unwrap();
        let ciphertext = encrypt(&key, &nonce, plaintext).unwrap();
        let (recovery_key, recovery_b64) = recovery::generate_recovery_key().unwrap();
        let recovery_encrypted = recovery::encrypt_recovery_key_v1(&recovery_key, &key, &salt).unwrap();

        let mut out = Vec::new();
        out.extend_from_slice(VAULT_MAGIC);
        out.push(VAULT_VERSION_V1);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&recovery_encrypted);
        out.extend_from_slice(&(stored_name.len() as u16).to_le_bytes());
        out.extend_from_slice(stored_name.as_bytes());
        out.extend_from_slice(&ciphertext);
        fs::write(vault_path, out).unwrap();
        recovery_b64.to_string()
    }

    /// Régression Bug 2 : le `.vault` doit être créé à côté du fichier source
    /// même quand le répertoire de travail du process est complètement
    /// différent (cas réel : lancement depuis le menu contextuel de
    /// l'Explorateur, dont le cwd n'a aucun rapport avec le dossier ciblé).
    #[test]
    fn vault_is_written_next_to_source_regardless_of_cwd() {
        let source_dir = temp_dir("source");
        let elsewhere_dir = temp_dir("elsewhere");
        let source_path = source_dir.join("document.txt");
        fs::write(&source_path, b"contenu original").unwrap();

        let original_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&elsewhere_dir).unwrap();

        let encrypt_result = encrypt_file(&source_path, "mot-de-passe-test");

        std::env::set_current_dir(&original_cwd).unwrap();

        let (vault_path, _recovery_key) = encrypt_result.unwrap();

        assert_eq!(
            vault_path.parent().unwrap(),
            source_dir.as_path(),
            "le .vault doit être dans le même dossier que la source, pas dans le cwd du process"
        );
        assert!(vault_path.exists());

        // Le déchiffrement doit lui aussi ignorer le cwd et restaurer à côté du .vault.
        let restore_dir = temp_dir("restore_cwd");
        std::env::set_current_dir(&restore_dir).unwrap();
        fs::remove_file(&source_path).unwrap();

        let decrypt_result = decrypt_path(&vault_path, "mot-de-passe-test");
        std::env::set_current_dir(&original_cwd).unwrap();

        let restored_path = decrypt_result.unwrap().output_path;
        assert_eq!(restored_path, source_path);
        assert_eq!(fs::read(&restored_path).unwrap(), b"contenu original");

        let _ = fs::remove_file(&vault_path);
        let _ = fs::remove_file(&restored_path);
    }

    /// Régression du "retry sans fermer la popup" pour `decrypt` :
    /// `verify_password` doit distinguer bon/mauvais mot de passe en ne
    /// déchiffrant que l'en-tête, sans jamais produire le fichier restauré.
    #[test]
    fn verify_password_checks_header_only() {
        let dir = temp_dir("verify_only");
        let source_path = dir.join("secret.txt");
        fs::write(&source_path, b"contenu confidentiel").unwrap();

        let (vault_path, _recovery_key) = encrypt_file(&source_path, "bon-mot-de-passe").unwrap();
        fs::remove_file(&source_path).unwrap();

        assert_eq!(verify_password(&vault_path, "mauvais-mot-de-passe").unwrap(), false);
        assert_eq!(verify_password(&vault_path, "bon-mot-de-passe").unwrap(), true);

        // Une vérification, même réussie, ne doit produire aucun fichier restauré.
        assert!(!source_path.exists());

        let _ = fs::remove_file(&vault_path);
    }

    /// Feature 4 : round-trip complet sur un dossier avec sous-dossiers,
    /// fichier vide, et noms avec espaces/accents.
    #[test]
    fn encrypt_and_decrypt_directory_round_trip() {
        let workdir = temp_dir("dir_roundtrip");
        let source = workdir.join("Mon Dossier Secret");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("racine.txt"), b"contenu racine").unwrap();
        fs::create_dir_all(source.join("sous-dossier accentué")).unwrap();
        fs::write(
            source.join("sous-dossier accentué/fichier imbriqué.txt"),
            b"contenu imbrique",
        )
        .unwrap();
        fs::create_dir_all(source.join("dossier vide")).unwrap();
        fs::write(source.join("vide.txt"), b"").unwrap();

        let (vault_path, _recovery_key) = encrypt_path(&source, "mot-de-passe-dossier").unwrap();
        assert_eq!(vault_path, workdir.join("Mon Dossier Secret.vault"));
        assert!(vault_path.exists());

        // L'original n'est pas touché par le chiffrement (la suppression est
        // une étape séparée, décidée par l'appelant — voir main.rs).
        assert!(source.exists());
        fs::remove_dir_all(&source).unwrap();

        let restored = decrypt_path(&vault_path, "mot-de-passe-dossier").unwrap().output_path;
        assert_eq!(restored, source);
        assert!(restored.is_dir());
        assert_eq!(fs::read(restored.join("racine.txt")).unwrap(), b"contenu racine");
        assert_eq!(
            fs::read(restored.join("sous-dossier accentué/fichier imbriqué.txt")).unwrap(),
            b"contenu imbrique"
        );
        assert!(restored.join("dossier vide").is_dir());
        assert_eq!(fs::read(restored.join("vide.txt")).unwrap(), b"");

        assert_eq!(
            verify_password(&vault_path, "mauvais-mot-de-passe").unwrap(),
            false
        );
        assert_eq!(
            verify_password(&vault_path, "mot-de-passe-dossier").unwrap(),
            true
        );

        let _ = fs::remove_file(&vault_path);
        let _ = fs::remove_dir_all(&restored);
    }

    /// `encrypt_path` sur un simple fichier doit se comporter exactement
    /// comme `encrypt_file` (pas de régression du cas non-dossier).
    #[test]
    fn encrypt_path_on_file_behaves_like_encrypt_file() {
        let dir = temp_dir("path_file");
        let source = dir.join("fichier.txt");
        fs::write(&source, b"contenu simple").unwrap();

        let (vault_path, _recovery_key) = encrypt_path(&source, "mdp").unwrap();
        assert_eq!(vault_path, dir.join("fichier.txt.vault"));
        fs::remove_file(&source).unwrap();

        let restored = decrypt_path(&vault_path, "mdp").unwrap().output_path;
        assert_eq!(restored, source);
        assert_eq!(fs::read(&restored).unwrap(), b"contenu simple");

        let _ = fs::remove_file(&vault_path);
        let _ = fs::remove_file(&restored);
    }

    /// 1.0.1 — le format écrit est bien le v2 décrit dans `encrypt_to_vault`, et le
    /// mot de passe le déchiffre.
    #[test]
    fn v2_layout_and_password_round_trip() {
        let dir = temp_dir("v2_password");
        let source = dir.join("rapport.txt");
        fs::write(&source, b"contenu v2").unwrap();

        let (vault_path, _recovery_key) = encrypt_file(&source, "mot-de-passe").unwrap();
        fs::remove_file(&source).unwrap();

        let raw = fs::read(&vault_path).unwrap();
        assert_eq!(&raw[0..4], b"SVLT");
        assert_eq!(raw[4], 0x02);
        assert_eq!(HEADER_V2_LEN, 171);
        assert_eq!(u16::from_le_bytes([raw[169], raw[170]]) as usize, "rapport.txt".len());
        assert_eq!(&raw[171..171 + "rapport.txt".len()], b"rapport.txt");
        assert!(!is_legacy_vault(&vault_path));

        let outcome = decrypt_path(&vault_path, "mot-de-passe").unwrap();
        assert!(!outcome.legacy_format);
        assert_eq!(fs::read(&outcome.output_path).unwrap(), b"contenu v2");

        let _ = fs::remove_file(&vault_path);
        let _ = fs::remove_file(&outcome.output_path);
    }

    /// 1.0.1 — LE correctif : la recovery key seule, sans le mot de passe,
    /// déchiffre le fichier (y compris collée avec des blancs autour).
    #[test]
    fn recovery_key_alone_decrypts() {
        let dir = temp_dir("v2_recovery");
        let source = dir.join("contrat.pdf");
        fs::write(&source, b"contenu recuperable").unwrap();

        let (vault_path, recovery_key) = encrypt_file(&source, "mot-de-passe-oublie").unwrap();
        fs::remove_file(&source).unwrap();

        // La recovery key n'est pas écrite dans le fichier.
        let raw = fs::read(&vault_path).unwrap();
        let decoded = recovery::parse_recovery_key(&recovery_key).unwrap();
        assert!(!raw.windows(KEY_LEN).any(|w| w == decoded.as_slice()));
        assert!(!raw.windows(recovery_key.len()).any(|w| w == recovery_key.as_bytes()));

        assert!(verify_password(&vault_path, &recovery_key).unwrap());
        let pasted = format!("  {}\r\n", recovery_key.as_str());
        let outcome = decrypt_path(&vault_path, &pasted).unwrap();
        assert_eq!(outcome.output_path, source);
        assert_eq!(fs::read(&source).unwrap(), b"contenu recuperable");

        let _ = fs::remove_file(&vault_path);
        let _ = fs::remove_file(&source);
    }

    /// 1.0.1 — mauvais mot de passe refusé, puis la recovery key ouvre le
    /// même fichier.
    #[test]
    fn wrong_password_then_recovery_key() {
        let dir = temp_dir("v2_wrong_then_recovery");
        let source = dir.join("notes.txt");
        fs::write(&source, b"contenu").unwrap();

        let (vault_path, recovery_key) = encrypt_file(&source, "bon-mot-de-passe").unwrap();
        fs::remove_file(&source).unwrap();

        assert!(!verify_password(&vault_path, "mauvais").unwrap());
        assert!(matches!(
            decrypt_path(&vault_path, "mauvais"),
            Err(SecureVaultError::InvalidPassword)
        ));
        assert!(!source.exists());

        // Une recovery key d'un AUTRE fichier ne doit pas convenir non plus.
        let (_, other_key) = recovery::generate_recovery_key().unwrap();
        assert!(!verify_password(&vault_path, &other_key).unwrap());

        assert!(verify_password(&vault_path, &recovery_key).unwrap());
        let outcome = decrypt_path(&vault_path, &recovery_key).unwrap();
        assert_eq!(fs::read(&outcome.output_path).unwrap(), b"contenu");

        let _ = fs::remove_file(&vault_path);
        let _ = fs::remove_file(&outcome.output_path);
    }

    /// 1.0.1 — un dossier chiffré s'ouvre aussi par sa recovery key.
    #[test]
    fn recovery_key_decrypts_directory() {
        let workdir = temp_dir("v2_recovery_dir");
        let source = workdir.join("Photos");
        fs::create_dir_all(source.join("2026")).unwrap();
        fs::write(source.join("2026/plage.jpg"), b"pixels").unwrap();

        let (vault_path, recovery_key) = encrypt_path(&source, "mdp-dossier").unwrap();
        fs::remove_dir_all(&source).unwrap();

        let outcome = decrypt_path(&vault_path, &recovery_key).unwrap();
        assert_eq!(fs::read(outcome.output_path.join("2026/plage.jpg")).unwrap(), b"pixels");

        let _ = fs::remove_file(&vault_path);
        let _ = fs::remove_dir_all(&outcome.output_path);
    }

    /// 1.0.1 — l'en-tête est authentifié : renommer le fichier stocké dans un
    /// `.vault` v2 fait échouer le déchiffrement au lieu de restaurer sous un
    /// autre nom.
    #[test]
    fn tampered_v2_header_is_rejected() {
        let dir = temp_dir("v2_tamper");
        let source = dir.join("aaaa.txt");
        fs::write(&source, b"contenu").unwrap();

        let (vault_path, _recovery_key) = encrypt_file(&source, "mdp").unwrap();
        fs::remove_file(&source).unwrap();

        let mut raw = fs::read(&vault_path).unwrap();
        raw[HEADER_V2_LEN] = b'b'; // "aaaa.txt" -> "baaa.txt"
        fs::write(&vault_path, &raw).unwrap();

        assert!(matches!(
            decrypt_path(&vault_path, "mdp"),
            Err(SecureVaultError::InvalidFormat(_))
        ));
        assert!(!dir.join("baaa.txt").exists());

        let _ = fs::remove_file(&vault_path);
    }

    /// 1.0.1 — rétrocompatibilité : un `.vault` v1 reste déchiffrable par son
    /// mot de passe, et il est signalé comme ancien format. Sa recovery key,
    /// elle, n'ouvre rien (c'était le défaut corrigé).
    #[test]
    fn v1_vault_decrypts_with_password_and_is_flagged() {
        let dir = temp_dir("v1_compat");
        let vault_path = dir.join("ancien.txt.vault");
        let restored = dir.join("ancien.txt");
        let _ = fs::remove_file(&vault_path);
        let _ = fs::remove_file(&restored);

        let old_recovery_key = write_v1_vault(&vault_path, "ancien.txt", b"contenu v1", "mdp-v1");
        assert!(is_legacy_vault(&vault_path));

        assert!(verify_password(&vault_path, "mdp-v1").unwrap());
        assert!(!verify_password(&vault_path, "mauvais").unwrap());
        assert!(!verify_password(&vault_path, &old_recovery_key).unwrap());
        assert!(matches!(
            decrypt_path(&vault_path, &old_recovery_key),
            Err(SecureVaultError::InvalidPassword)
        ));

        let outcome = decrypt_path(&vault_path, "mdp-v1").unwrap();
        assert!(outcome.legacy_format);
        assert_eq!(outcome.output_path, restored);
        assert_eq!(fs::read(&restored).unwrap(), b"contenu v1");

        let _ = fs::remove_file(&vault_path);
        let _ = fs::remove_file(&restored);
    }

    /// Un nom stocké qui sortirait du dossier du `.vault` est refusé.
    #[test]
    fn stored_name_cannot_escape_vault_folder() {
        assert!(validate_stored_name("document.txt").is_ok());
        assert!(validate_stored_name("Mon Dossier/").is_ok());
        for bad in ["", "/", "..", "../", "../evil.txt", "a\\b.txt", "sub/file.txt", "C:evil"] {
            assert!(validate_stored_name(bad).is_err(), "{bad:?} aurait dû être refusé");
        }

        let dir = temp_dir("v1_traversal");
        let vault_path = dir.join("piege.vault");
        let _ = fs::remove_file(&vault_path);
        write_v1_vault(&vault_path, "..\\evil.txt", b"x", "mdp");
        assert!(matches!(
            decrypt_path(&vault_path, "mdp"),
            Err(SecureVaultError::InvalidFormat(_))
        ));
        let _ = fs::remove_file(&vault_path);
    }

    /// Versions inconnues et fichiers tronqués : erreur de format, jamais de
    /// panique (le curseur ne lit qu'après vérification des longueurs).
    #[test]
    fn unknown_version_and_truncated_headers_are_rejected() {
        let dir = temp_dir("bad_headers");
        let path = dir.join("bad.vault");

        let mut raw = b"SVLT".to_vec();
        raw.push(9);
        raw.extend_from_slice(&[0u8; 300]);
        fs::write(&path, &raw).unwrap();
        assert!(matches!(verify_password(&path, "x"), Err(SecureVaultError::InvalidFormat(_))));

        for (version, len) in [(1u8, HEADER_V1_LEN - 1), (2u8, HEADER_V2_LEN - 1), (2u8, 3)] {
            let mut raw = b"SVLT".to_vec();
            raw.push(version);
            raw.resize(len, 0);
            fs::write(&path, &raw).unwrap();
            assert!(matches!(verify_password(&path, "x"), Err(SecureVaultError::InvalidFormat(_))));
            assert!(matches!(decrypt_path(&path, "x"), Err(SecureVaultError::InvalidFormat(_))));
            assert!(!is_legacy_vault(&path));
        }
        let _ = fs::remove_file(&path);
    }
}

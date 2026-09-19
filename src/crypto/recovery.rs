use crate::crypto::aes_gcm::{self, KEY_LEN, NONCE_LEN, TAG_LEN};
use crate::crypto::kdf::SALT_LEN;
use crate::errors::{Result, SecureVaultError};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

pub const RECOVERY_KEY_LEN: usize = KEY_LEN;
pub const RECOVERY_KEY_ENCRYPTED_LEN: usize = RECOVERY_KEY_LEN + TAG_LEN;

/// Longueur de l'encodage base64 (avec padding) d'une recovery key :
/// 32 octets → 44 caractères, dont un `=` final.
const RECOVERY_KEY_B64_LEN: usize = 44;

/// Génère une recovery key aléatoire (32 octets) ainsi que son encodage
/// base64, destiné à être affiché une seule fois à l'utilisateur pour
/// sauvegarde hors-ligne. Les deux formes sont `Zeroizing` : la recovery key
/// ouvre le `.vault` sans le mot de passe, elle ne doit pas traîner en
/// mémoire après usage.
///
/// Depuis le format v2 (1.0.1), ces 32 octets sont directement une clé
/// AES-256 : ils enveloppent la clé de chiffrement du fichier (FEK), sans
/// passer par Argon2id — une clé aléatoire de 256 bits n'a pas besoin d'être
/// renforcée contre la force brute, contrairement à un mot de passe.
pub fn generate_recovery_key() -> Result<(Zeroizing<[u8; RECOVERY_KEY_LEN]>, Zeroizing<String>)> {
    let mut key = Zeroizing::new([0u8; RECOVERY_KEY_LEN]);
    OsRng.fill_bytes(key.as_mut());
    let encoded = Zeroizing::new(STANDARD.encode(key.as_ref()));
    Ok((key, encoded))
}

/// Reconnaît une recovery key dans une saisie de la popup de déchiffrement,
/// qui accepte indifféremment un mot de passe ou une recovery key.
///
/// Les blancs sont ignorés (un copier-coller depuis le fichier d'export ou un
/// e-mail ramène souvent un espace ou un retour à la ligne). Retourne `None`
/// si la saisie n'a pas la forme d'une recovery key : 44 caractères base64
/// décodant en exactement 32 octets. Un mot de passe qui aurait par hasard
/// cette forme n'est pas un problème — l'appelant essaie de toute façon
/// l'autre chemin en cas d'échec (voir `aes_gcm::unwrap_fek`).
pub fn parse_recovery_key(input: &str) -> Option<Zeroizing<[u8; RECOVERY_KEY_LEN]>> {
    let compact: Zeroizing<String> =
        Zeroizing::new(input.chars().filter(|c| !c.is_whitespace()).collect());
    if compact.len() != RECOVERY_KEY_B64_LEN {
        return None;
    }
    let decoded = Zeroizing::new(STANDARD.decode(compact.as_bytes()).ok()?);
    let key: [u8; RECOVERY_KEY_LEN] = decoded.as_slice().try_into().ok()?;
    Some(Zeroizing::new(key))
}

/// Nonce du format v1 : dérivé des 12 premiers octets du sel. Conservé
/// uniquement pour relire les `.vault` v1.
fn recovery_nonce_v1(salt: &[u8; SALT_LEN]) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&salt[..NONCE_LEN]);
    nonce
}

/// Écrit l'enveloppe de recovery key du format v1 — **tests uniquement**,
/// pour fabriquer des `.vault` v1 et vérifier qu'ils restent lisibles.
///
/// Ce format est la raison d'être de la 1.0.1 : la recovery key y était
/// chiffrée avec la clé dérivée du MOT DE PASSE. Perdre le mot de passe,
/// c'était perdre aussi le seul moyen de relire la recovery key — elle ne
/// pouvait donc jamais servir de recours.
#[cfg(test)]
pub fn encrypt_recovery_key_v1(
    key: &[u8; RECOVERY_KEY_LEN],
    derived_key: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
) -> Result<[u8; RECOVERY_KEY_ENCRYPTED_LEN]> {
    let nonce = recovery_nonce_v1(salt);
    let ciphertext = aes_gcm::encrypt(derived_key, &nonce, key)?;
    ciphertext.try_into().map_err(|_| {
        SecureVaultError::Crypto("taille inattendue pour la recovery key chiffrée".into())
    })
}

/// Déchiffre l'enveloppe de recovery key d'un `.vault` v1. Ne sert plus qu'à
/// vérifier un mot de passe sur un fichier v1 (voir `aes_gcm::verify_password`).
pub fn decrypt_recovery_key_v1(
    data: &[u8; RECOVERY_KEY_ENCRYPTED_LEN],
    derived_key: &[u8; KEY_LEN],
    salt: &[u8; SALT_LEN],
) -> Result<Zeroizing<[u8; RECOVERY_KEY_LEN]>> {
    let nonce = recovery_nonce_v1(salt);
    let plaintext = Zeroizing::new(aes_gcm::decrypt(derived_key, &nonce, data)?);
    let key: [u8; RECOVERY_KEY_LEN] = plaintext.as_slice().try_into().map_err(|_| {
        SecureVaultError::Crypto("taille inattendue pour la recovery key déchiffrée".into())
    })?;
    Ok(Zeroizing::new(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_is_recognized() {
        let (key, encoded) = generate_recovery_key().unwrap();
        assert_eq!(encoded.len(), RECOVERY_KEY_B64_LEN);
        let parsed = parse_recovery_key(&encoded).expect("recovery key reconnue");
        assert_eq!(*parsed, *key);
    }

    #[test]
    fn pasted_key_with_whitespace_is_recognized() {
        let (key, encoded) = generate_recovery_key().unwrap();
        let (a, b) = encoded.split_at(20);
        let pasted = format!("  {a}\r\n{b} \n");
        assert_eq!(*parse_recovery_key(&pasted).unwrap(), *key);
    }

    #[test]
    fn ordinary_passwords_are_not_recovery_keys() {
        assert!(parse_recovery_key("").is_none());
        assert!(parse_recovery_key("mot-de-passe").is_none());
        // Bonne longueur mais pas du base64.
        assert!(parse_recovery_key(&"!".repeat(RECOVERY_KEY_B64_LEN)).is_none());
        // Base64 valide de 44 caractères, mais pas 32 octets : 31 octets
        // (padding `==`) et 33 octets (sans padding) ont la même longueur
        // encodée qu'une recovery key.
        assert!(parse_recovery_key(&STANDARD.encode([7u8; 31])).is_none());
        assert!(parse_recovery_key(&STANDARD.encode([7u8; 33])).is_none());
    }
}

use crate::errors::{Result, SecureVaultError};
use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 32;
pub const KEY_LEN: usize = 32;

const ARGON2_MEMORY_KIB: u32 = 65536;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

fn argon2() -> Result<Argon2<'static>> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(KEY_LEN),
    )
    .map_err(|e| SecureVaultError::Crypto(format!("paramètres Argon2id invalides: {e}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Dérive une clé de 32 octets à partir d'un mot de passe et d'un sel via Argon2id
/// (m=65536 KiB, t=3, p=4). Utilisée comme clé AES-256-GCM.
///
/// Retourne un `Zeroizing` : c'est LE point de passage obligé de toutes les
/// clés de l'application, donc l'endroit où garantir l'effacement mémoire une
/// fois pour toutes plutôt que dans chaque appelant. Le buffer intermédiaire
/// est lui aussi zéroïsé, y compris sur le chemin d'erreur (`Zeroizing` est
/// déposé par `Drop`, qu'on sorte par `?` ou par `Ok`).
pub fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2()?
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| SecureVaultError::Crypto(format!("dérivation de clé échouée: {e}")))?;
    Ok(key)
}

/// Hash un mot de passe avec Argon2id (format PHC) pour stockage/vérification,
/// avec un sel aléatoire généré de façon cryptographiquement sûre.
/// Retourne le hash encodé ainsi que le sel brut utilisé (réutilisable pour `derive_key`).
pub fn hash_password(password: &str) -> Result<(String, [u8; SALT_LEN])> {
    let mut salt_bytes = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt_bytes);

    let salt_string = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| SecureVaultError::Crypto(format!("encodage du sel échoué: {e}")))?;

    let hash = argon2()?
        .hash_password(password.as_bytes(), &salt_string)
        .map_err(|e| SecureVaultError::Crypto(format!("hachage du mot de passe échoué: {e}")))?
        .to_string();

    Ok((hash, salt_bytes))
}

/// Vérifie un mot de passe contre un hash Argon2id (format PHC) stocké.
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(hash)
        .map_err(|e| SecureVaultError::Crypto(format!("hash Argon2id invalide: {e}")))?;
    Ok(argon2()?
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

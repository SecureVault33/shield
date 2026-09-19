//! Quotas de la version gratuite.
//!
//! **Version gratuite open source** : ce module ne contient que les limites de
//! la version gratuite. L'activation de SecureVault Pro n'est pas incluse dans
//! ce code source ; `is_pro` vaut donc toujours `false`.
//!
//! Gratuit : `FREE_LOCK_LIMIT` verrouillages et `FREE_ENCRYPT_LIMIT`
//! chiffrements.
//!
//! **Règle non négociable** : déverrouiller, déchiffrer, exporter ses recovery
//! keys et forcer le déverrouillage restent TOUJOURS gratuits et illimités.
//! Seule la création de nouvelles protections est limitée ; personne ne doit
//! perdre l'accès à un fichier qu'il a déjà protégé.
//!
//! Les compteurs (`usage.json`) sont un fichier local en clair : c'est une
//! barrière d'honnêteté, pas un DRM.

use crate::errors::{Result, SecureVaultError};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const FREE_LOCK_LIMIT: u32 = 20;
pub const FREE_ENCRYPT_LIMIT: u32 = 3;

const USAGE_FILE: &str = "usage.json";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageCounters {
    #[serde(default)]
    pub locks_used: u32,
    #[serde(default)]
    pub encrypts_used: u32,
}

/// Action soumise à quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quota {
    Lock,
    Encrypt,
}

impl Quota {
    pub fn limit(self) -> u32 {
        match self {
            Quota::Lock => FREE_LOCK_LIMIT,
            Quota::Encrypt => FREE_ENCRYPT_LIMIT,
        }
    }

    fn used(self, usage: &UsageCounters) -> u32 {
        match self {
            Quota::Lock => usage.locks_used,
            Quota::Encrypt => usage.encrypts_used,
        }
    }
}

/// Photographie de l'état de licence, pour l'interface. Le dashboard la garde
/// dans son état et la relit après chaque action : la barre de statut est
/// repeinte à chaque frame d'animation, elle ne doit pas relire le fichier
/// 60 fois par seconde.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseStatus {
    /// Toujours `false` dans la version gratuite open source.
    pub pro: bool,
    pub usage: UsageCounters,
}

impl LicenseStatus {
    /// Actions restantes, `None` en Pro (illimité).
    pub fn remaining(&self, quota: Quota) -> Option<u32> {
        if self.pro {
            None
        } else {
            Some(quota.limit().saturating_sub(quota.used(&self.usage)))
        }
    }

    /// `count` nouvelles protections sont-elles autorisées ?
    pub fn allows(&self, quota: Quota, count: u32) -> bool {
        self.remaining(quota).is_none_or(|left| left >= count)
    }
}

/// Accès au fichier de compteurs d'un répertoire. L'application utilise
/// `%LOCALAPPDATA%\SecureVault` ; les tests, un répertoire temporaire — ils ne
/// touchent jamais aux fichiers réels de l'utilisateur.
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Store { dir: dir.into() }
    }

    /// Store de l'application.
    pub fn app() -> Result<Self> {
        let local = std::env::var("LOCALAPPDATA")
            .map_err(|_| SecureVaultError::License("variable LOCALAPPDATA introuvable".into()))?;
        Ok(Store::new(PathBuf::from(local).join("SecureVault")))
    }

    fn path(&self, file: &str) -> PathBuf {
        self.dir.join(file)
    }

    /// Compteurs d'utilisation ; zéro si le fichier est absent ou illisible
    /// (même tolérance que `config.json` : un fichier abîmé ne doit jamais
    /// bloquer l'application).
    pub fn load_usage(&self) -> UsageCounters {
        fs::read_to_string(self.path(USAGE_FILE))
            .ok()
            .and_then(|content| serde_json::from_str(&content).ok())
            .unwrap_or_default()
    }

    pub fn save_usage(&self, counters: &UsageCounters) -> Result<()> {
        write_json(&self.path(USAGE_FILE), counters)
    }

    pub fn status(&self) -> LicenseStatus {
        LicenseStatus { pro: false, usage: self.load_usage() }
    }

    /// Enregistre `count` actions réussies.
    pub fn record(&self, quota: Quota, count: u32) -> Result<()> {
        if count == 0 {
            return Ok(());
        }
        let mut usage = self.load_usage();
        match quota {
            Quota::Lock => usage.locks_used = usage.locks_used.saturating_add(count),
            Quota::Encrypt => usage.encrypts_used = usage.encrypts_used.saturating_add(count),
        }
        self.save_usage(&usage)
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(value)
        .map_err(|e| SecureVaultError::License(format!("sérialisation échouée : {e}")))?;
    fs::write(path, content)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// API de l'application
// ---------------------------------------------------------------------------
//
// Un `Store` introuvable (LOCALAPPDATA absent) est traité comme « version
// gratuite sans compteurs » : on ne bloque ni ne plante l'application.
//
// L'API est volontairement réduite à `status()` (lecture) et `record()`
// (décompte) : les lots de l'Explorateur et du dashboard doivent vérifier et
// décompter N éléments d'un coup, et un seul chemin de code évite que les
// deux divergent.

/// Toujours `false` : l'activation Pro n'est pas incluse dans ce code source.
pub fn is_pro() -> bool {
    false
}

pub fn status() -> LicenseStatus {
    match Store::app() {
        Ok(store) => store.status(),
        Err(_) => LicenseStatus { pro: false, usage: UsageCounters::default() },
    }
}

/// Enregistre plusieurs actions d'un coup (lots de l'Explorateur, dashboard).
pub fn record(quota: Quota, count: u32) -> Result<()> {
    Store::app()?.record(quota, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Répertoire temporaire propre à chaque test, supprimé à la fin.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "securevault_license_test_{}_{name}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn fresh_install_is_free_with_full_quotas() {
        let dir = TempDir::new("fresh");
        let status = Store::new(&dir.0).status();
        assert!(!status.pro);
        assert_eq!(status.remaining(Quota::Lock), Some(FREE_LOCK_LIMIT));
        assert_eq!(status.remaining(Quota::Encrypt), Some(FREE_ENCRYPT_LIMIT));
    }

    #[test]
    fn quotas_run_out_exactly_at_the_limit() {
        let dir = TempDir::new("limits");
        let s = Store::new(&dir.0);
        for _ in 0..FREE_ENCRYPT_LIMIT - 1 {
            s.record(Quota::Encrypt, 1).unwrap();
        }
        assert!(s.status().allows(Quota::Encrypt, 1), "il reste 1 chiffrement");
        assert!(!s.status().allows(Quota::Encrypt, 2), "pas assez pour un lot de 2");
        s.record(Quota::Encrypt, 1).unwrap();
        assert!(!s.status().allows(Quota::Encrypt, 1));
        assert_eq!(s.status().remaining(Quota::Encrypt), Some(0));
        // Les verrouillages ont leur propre compteur.
        assert_eq!(s.status().remaining(Quota::Lock), Some(FREE_LOCK_LIMIT));
    }

    #[test]
    fn remaining_never_underflows() {
        let dir = TempDir::new("underflow");
        let s = Store::new(&dir.0);
        s.save_usage(&UsageCounters { locks_used: 999, encrypts_used: 999 }).unwrap();
        assert_eq!(s.status().remaining(Quota::Lock), Some(0));
    }

    #[test]
    fn corrupted_usage_file_falls_back_to_zero() {
        let dir = TempDir::new("corrupt");
        fs::write(dir.0.join(USAGE_FILE), "{ pas du json").unwrap();
        assert_eq!(Store::new(&dir.0).load_usage(), UsageCounters::default());
    }

    #[test]
    fn free_version_is_never_pro() {
        assert!(!is_pro());
        assert!(!status().pro);
    }
}

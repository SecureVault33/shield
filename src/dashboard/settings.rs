//! Paramètres utilisateur, persistés dans `%LOCALAPPDATA%\SecureVault\config.json`.
//!
//! Règle de ce module : un champ n'existe ici QUE si quelque chose le lit.
//! Les 0.5.0–0.6.1 exposaient `auto_lock_minutes` et `hotkey_lock_all` dans
//! l'onglet Paramètres alors qu'aucun timer ni `RegisterHotKey` n'existait —
//! l'utilisateur réglait un verrouillage automatique qui ne se produisait
//! jamais. Un réglage de sécurité qu'on croit actif est pire que pas de
//! réglage du tout ; les deux champs ont été retirés en 0.7.0. Ils sont
//! simplement ignorés s'ils traînent encore dans un `config.json` existant
//! (serde ignore les champs inconnus par défaut).

use crate::errors::{Result, SecureVaultError};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    pub version: u32,
    pub language: String,
    pub theme: String,
    pub security_reminder_hours: u32,
    pub security_reminder_enabled: bool,
    pub recovery_keys_export_path: String,
    pub first_launch_done: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            version: 1,
            language: "fr".to_string(),
            theme: "red".to_string(),
            security_reminder_hours: 6,
            security_reminder_enabled: true,
            recovery_keys_export_path: String::new(),
            first_launch_done: false,
        }
    }
}

fn settings_path() -> Result<PathBuf> {
    let local_app_data = std::env::var("LOCALAPPDATA")
        .map_err(|_| SecureVaultError::Registry("variable LOCALAPPDATA introuvable".into()))?;
    let dir = PathBuf::from(local_app_data).join("SecureVault");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("config.json"))
}

/// Charge les paramètres ; les valeurs par défaut si le fichier n'existe pas
/// encore ou est invalide (jamais une erreur fatale — les paramètres ne
/// doivent jamais bloquer le reste de l'application).
pub fn load_settings() -> Settings {
    (|| -> Result<Settings> {
        let path = settings_path()?;
        if !path.exists() {
            return Ok(Settings::default());
        }
        let content = std::fs::read_to_string(&path)?;
        serde_json::from_str(&content)
            .map_err(|e| SecureVaultError::Registry(format!("config JSON invalide: {e}")))
    })()
    .unwrap_or_default()
}

/// Sauvegarde les paramètres, indentés pour rester lisibles/éditables à la main.
pub fn save_settings(settings: &Settings) -> Result<()> {
    let path = settings_path()?;
    let content = serde_json::to_string_pretty(settings)
        .map_err(|e| SecureVaultError::Registry(format!("sérialisation config échouée: {e}")))?;
    std::fs::write(&path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Même précaution que `dashboard::registry::tests` (ressource partagée
    // sous `%LOCALAPPDATA%`) : verrouillé + `cargo test -- --test-threads=1`.
    static SETTINGS_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn with_clean_settings<F: FnOnce()>(f: F) {
        // Garde récupérée même si un test précédent a paniqué : sinon le
        // mutex empoisonné ferait échouer tous les suivants SANS restaurer la
        // config réelle de l'utilisateur.
        let _guard = SETTINGS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = settings_path().unwrap();
        let original = std::fs::read_to_string(&path).ok();

        crate::dashboard::remove_until_gone(&path);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

        match original {
            Some(content) => std::fs::write(&path, content).unwrap(),
            None => {
                let _ = std::fs::remove_file(&path);
            }
        }

        if let Err(panic) = outcome {
            std::panic::resume_unwind(panic);
        }
    }

    /// Régression I1 : un `config.json` hérité d'une 0.6.x contient encore
    /// `auto_lock_minutes` et `hotkey_lock_all`. Il doit se charger sans
    /// erreur, ces champs étant simplement ignorés.
    #[test]
    fn legacy_config_with_removed_fields_still_loads() {
        with_clean_settings(|| {
            let path = settings_path().unwrap();
            std::fs::write(
                &path,
                r#"{"version":1,"language":"en","theme":"blue","security_reminder_hours":9,
                     "security_reminder_enabled":true,"auto_lock_minutes":30,
                     "recovery_keys_export_path":"","first_launch_done":true,
                     "hotkey_lock_all":"Ctrl+Alt+L"}"#,
            )
            .unwrap();

            let loaded = load_settings();
            assert_eq!(loaded.language, "en");
            assert_eq!(loaded.theme, "blue");
            assert_eq!(loaded.security_reminder_hours, 9);
            assert!(loaded.first_launch_done);
        });
    }

    #[test]
    fn missing_file_yields_defaults() {
        with_clean_settings(|| {
            assert_eq!(load_settings(), Settings::default());
        });
    }

    #[test]
    fn save_then_load_round_trips() {
        with_clean_settings(|| {
            let mut settings = Settings::default();
            settings.security_reminder_hours = 12;
            settings.security_reminder_enabled = false;
            settings.theme = "blue".to_string();
            settings.recovery_keys_export_path = "C:\\Users\\Test\\Documents".to_string();

            save_settings(&settings).unwrap();
            let loaded = load_settings();
            assert_eq!(loaded, settings);
        });
    }

    #[test]
    fn invalid_json_falls_back_to_defaults() {
        with_clean_settings(|| {
            let path = settings_path().unwrap();
            std::fs::write(&path, "{ceci n'est pas du JSON").unwrap();
            assert_eq!(load_settings(), Settings::default());
        });
    }
}

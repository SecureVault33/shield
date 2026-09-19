//! Rappel de sécurité : prévient l'utilisateur qu'un fichier/dossier déchiffré
//! ou déverrouillé l'est resté depuis trop longtemps. Vérifié périodiquement
//! par un timer Windows tant que le dashboard est ouvert — voir
//! `dashboard::window` (`WM_TIMER` / `SetTimer`).

use crate::dashboard::{registry, settings};
use std::path::Path;

use windows::core::HSTRING;
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, MB_ICONWARNING, MB_OK, MB_SYSTEMMODAL,
};

fn display_name(entry: &registry::VaultEntry) -> String {
    Path::new(&entry.original_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&entry.original_path)
        .to_string()
}

fn show_reminder(message: &str) {
    let title = HSTRING::from("⚠️ SecureVault — Rappel de sécurité");
    let message_w = HSTRING::from(message);
    unsafe {
        MessageBoxW(HWND::default(), &message_w, &title, MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
    }
}

/// Cœur pur (sans I/O ni popup) de la vérification : marque `reminder_sent`
/// sur les entrées nouvellement éligibles et retourne `(nom affiché, heures
/// d'exposition)` pour chacune. Séparé de `check_and_notify` pour être
/// testable sans dépendre du système de fichiers ni de l'UI Win32.
fn compute_newly_eligible(
    entries: &mut [registry::VaultEntry],
    reminder_hours: u32,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<(String, i64)> {
    let threshold = chrono::Duration::hours(reminder_hours as i64);
    let mut newly_eligible = Vec::new();

    for entry in entries.iter_mut() {
        if entry.status != "unlocked" || entry.reminder_sent {
            continue;
        }
        // Exposition = temps écoulé depuis le DÉVERROUILLAGE, pas depuis la
        // protection. Une entrée sans `unlocked_at` vient d'un registre
        // antérieur à la 0.7.0 : on ne sait pas quand elle a été exposée, et
        // deviner avec `protected_at` donnerait « exposé depuis 3 mois » pour
        // un fichier ouvert il y a deux minutes. On attend donc le prochain
        // cycle verrouillage/déverrouillage pour la prendre en compte.
        let Some(unlocked_at) = entry.unlocked_at.as_deref() else {
            continue;
        };
        let Ok(unlocked_at) = chrono::DateTime::parse_from_rfc3339(unlocked_at) else {
            continue;
        };
        let elapsed = now.signed_duration_since(unlocked_at.with_timezone(&chrono::Utc));
        if elapsed >= threshold {
            newly_eligible.push((display_name(entry), elapsed.num_hours()));
            entry.reminder_sent = true;
        }
    }

    newly_eligible
}

fn format_reminder_message(newly_eligible: &[(String, i64)], reminder_hours: u32) -> String {
    if newly_eligible.len() == 1 {
        let (name, hours) = &newly_eligible[0];
        format!(
            "Le fichier {name} est déchiffré/déverrouillé depuis {hours}h.\n\nPensez à le re-protéger si vous avez fini de l'utiliser."
        )
    } else {
        format!(
            "{} fichiers sont exposés depuis plus de {}h.\n\nPensez à les re-protéger si vous avez fini de les utiliser.",
            newly_eligible.len(),
            reminder_hours
        )
    }
}

/// Vérifie le registre pour des fichiers exposés (`status == "unlocked"`)
/// depuis plus longtemps que `security_reminder_hours`, et affiche un rappel
/// unique par fichier (`reminder_sent` évite les doublons). Best-effort de
/// bout en bout : une erreur de lecture/écriture du registre ou des
/// paramètres ne doit jamais faire planter le dashboard, elle est simplement
/// ignorée (le prochain tick réessaiera).
pub fn check_and_notify() {
    // Fonctionnalité Pro (1.0.0). Le réglage enregistré est conservé tel quel :
    // il reprend effet dès l'activation d'une licence, sans reconfiguration.
    if !crate::license::is_pro() {
        return;
    }
    let cfg = settings::load_settings();
    if !cfg.security_reminder_enabled {
        return;
    }

    let mut registry = match registry::load_registry() {
        Ok(r) => r,
        Err(_) => return,
    };

    let newly_eligible = compute_newly_eligible(&mut registry.entries, cfg.security_reminder_hours, chrono::Utc::now());

    if !newly_eligible.is_empty() {
        let _ = registry::save_registry(&registry);
        show_reminder(&format_reminder_message(&newly_eligible, cfg.security_reminder_hours));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `unlocked_at` porte l'horodatage significatif ici : c'est lui qui
    /// détermine l'exposition depuis la 0.7.0. `protected_at` est
    /// volontairement placé un an dans le passé pour qu'un test qui passerait
    /// accidentellement à cause de l'ancien comportement se voie.
    fn entry(
        status: &str,
        unlocked_at: chrono::DateTime<chrono::Utc>,
        reminder_sent: bool,
    ) -> registry::VaultEntry {
        registry::VaultEntry {
            id: "test-id".to_string(),
            original_path: r"C:\Users\Test\document.txt".to_string(),
            protected_path: r"C:\Users\Test\document.txt".to_string(),
            mode: "acl_locked".to_string(),
            protected_at: (chrono::Utc::now() - chrono::Duration::days(365)).to_rfc3339(),
            status: status.to_string(),
            is_directory: false,
            reminder_sent,
            unlocked_at: Some(unlocked_at.to_rfc3339()),
            recovery_key: None,
            recovery_key_nonce: None,
        }
    }

    /// Regression I2 : une entree heritee d'un registre < 0.7.0 n'a pas
    /// d'`unlocked_at`. Elle ne doit PAS declencher de rappel calcule sur
    /// `protected_at` (ici vieux d'un an), sinon chaque deverrouillage recent
    /// serait annonce comme « expose depuis un an ».
    #[test]
    fn entry_without_unlocked_at_is_skipped() {
        let now = chrono::Utc::now();
        let mut legacy = entry("unlocked", now, false);
        legacy.unlocked_at = None;

        let mut entries = vec![legacy];
        let eligible = compute_newly_eligible(&mut entries, 6, now);

        assert!(eligible.is_empty());
        assert!(!entries[0].reminder_sent);
    }

    #[test]
    fn locked_entries_are_never_eligible() {
        let now = chrono::Utc::now();
        let mut entries = vec![entry("locked", now - chrono::Duration::hours(100), false)];
        let eligible = compute_newly_eligible(&mut entries, 6, now);
        assert!(eligible.is_empty());
        assert!(!entries[0].reminder_sent);
    }

    #[test]
    fn unlocked_entry_past_threshold_becomes_eligible_once() {
        let now = chrono::Utc::now();
        let mut entries = vec![entry("unlocked", now - chrono::Duration::hours(7), false)];
        let eligible = compute_newly_eligible(&mut entries, 6, now);
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].0, "document.txt");
        assert!(entries[0].reminder_sent);

        // Un second appel ne doit pas re-signaler la même entrée.
        let eligible_again = compute_newly_eligible(&mut entries, 6, now);
        assert!(eligible_again.is_empty());
    }

    #[test]
    fn unlocked_entry_below_threshold_is_not_yet_eligible() {
        let now = chrono::Utc::now();
        let mut entries = vec![entry("unlocked", now - chrono::Duration::hours(2), false)];
        let eligible = compute_newly_eligible(&mut entries, 6, now);
        assert!(eligible.is_empty());
        assert!(!entries[0].reminder_sent);
    }

    #[test]
    fn multiple_eligible_entries_are_all_reported() {
        let now = chrono::Utc::now();
        let mut entries = vec![
            entry("unlocked", now - chrono::Duration::hours(10), false),
            entry("unlocked", now - chrono::Duration::hours(8), false),
            entry("unlocked", now - chrono::Duration::hours(1), false),
        ];
        let eligible = compute_newly_eligible(&mut entries, 6, now);
        assert_eq!(eligible.len(), 2);
    }

    #[test]
    fn message_formatting_singular_vs_plural() {
        let single = format_reminder_message(&[("a.txt".to_string(), 7)], 6);
        assert!(single.contains("a.txt"));
        assert!(single.contains("7h"));

        let plural = format_reminder_message(&[("a.txt".to_string(), 7), ("b.txt".to_string(), 9)], 6);
        assert!(plural.contains("2 fichiers"));
        assert!(plural.contains("6h"));
    }
}

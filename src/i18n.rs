//! Traductions de l'interface — approche volontairement simple (table de
//! correspondance statique en mémoire), sans dépendance i18n lourde.
//!
//! **Français uniquement depuis la 1.0.2.** La table anglaise a été retirée :
//! elle n'a jamais fonctionné correctement de bout en bout, et une traduction
//! à moitié juste est pire que pas de traduction. Tous les appels `t("clé")`
//! restent en place : une future version internationale n'aura qu'à rajouter
//! une table et à la sélectionner dans `load_translations`.

use std::collections::HashMap;
use std::sync::OnceLock;

pub struct Translations {
    strings: HashMap<&'static str, &'static str>,
}

impl Translations {
    /// Retourne la traduction de `key`, ou `key` lui-même si absente de la
    /// table (filet de sécurité : un texte non traduit reste visible et
    /// identifiable plutôt que de faire planter l'UI).
    pub fn get(&self, key: &'static str) -> &'static str {
        self.strings.get(key).copied().unwrap_or(key)
    }
}

static CURRENT: OnceLock<Translations> = OnceLock::new();

/// Initialise la table active pour tout le processus — à appeler une seule
/// fois, tôt dans `main()`, à partir de `settings::load_settings().language`.
/// La langue demandée est actuellement ignorée (voir `load_translations`).
pub fn init(lang: &str) {
    let _ = CURRENT.set(load_translations(lang));
}

/// Raccourci global : `i18n::t("dashboard.tab.files")`. Retombe sur le
/// français si `init` n'a jamais été appelé (tests, usage isolé).
pub fn t(key: &'static str) -> &'static str {
    CURRENT.get_or_init(|| load_translations("fr")).get(key)
}

macro_rules! translations {
    ($lang:expr, { $($key:literal => $value:literal),* $(,)? }) => {{
        let mut map = HashMap::new();
        $(map.insert($key, $value);)*
        map
    }};
}

pub fn load_translations(_lang: &str) -> Translations {
    // Français quelle que soit la langue demandée : une configuration
    // antérieure à la 1.0.2 peut encore contenir `"language": "en"`.
    let strings = translations!(fr, {
        // Popup mot de passe
        "password.title.lock" => "🔒 Verrouiller — Choisir un mot de passe",
        "password.title.unlock" => "🔓 Déverrouiller",
        "password.title.encrypt" => "🛡️ Chiffrer — Choisir un mot de passe",
        "password.title.decrypt" => "🔑 Déchiffrer",
        "password.label" => "Mot de passe :",
        "password.confirm" => "Confirmer :",
        "password.enter" => "Entrez le mot de passe pour continuer",
        "password.placeholder" => "Entrez votre mot de passe...",
        // Déchiffrement : mot de passe OU recovery key (1.0.1)
        "decrypt.label" => "Mot de passe ou recovery key :",
        "decrypt.placeholder" => "Mot de passe ou clé de récupération...",
        "decrypt.wrong" => "❌ Mot de passe ou recovery key incorrect — réessayez",
        "decrypt.legacy_label" => "⚠️ Ancien format de fichier : seul le mot de passe fonctionne.",
        "decrypt.legacy_warning" => "⚠️ Ce fichier a été chiffré avec une ancienne version. La recovery key n'est pas utilisable. Seul le mot de passe fonctionne.\nRechiffrez-le pour obtenir une recovery key utilisable.",
        "decrypt.legacy_batch" => "⚠️ {count} fichier(s) chiffré(s) avec une ancienne version : leur recovery key n'est pas utilisable, seul le mot de passe fonctionne. Rechiffrez-les pour obtenir une recovery key utilisable.",
        "password.choose_lock" => "Choisissez un mot de passe pour verrouiller ce fichier",
        "password.choose_encrypt" => "Définissez un mot de passe pour chiffrer ce fichier",
        "password.mismatch" => "Les mots de passe ne correspondent pas.",
        "password.empty" => "Le mot de passe ne peut pas être vide.",
        "password.wrong" => "❌ Mot de passe incorrect — réessayez",
        "password.cancel" => "Annuler",
        "password.validate" => "Valider",
        "password.master_required_title" => "🛡️ Master Password requis",
        "strength.very_weak" => "Très faible",
        "strength.weak" => "Faible",
        "strength.medium" => "Moyen",
        "strength.strong" => "Fort",
        "strength.very_strong" => "Très fort",

        // Master Password setup
        "master.setup_title" => "🛡️ SecureVault — Créer le Master Password",
        "master.setup_label" => "Ce mot de passe permet le déverrouillage forcé en cas d'urgence — conservez-le précieusement.",
        "master.already_set" => "Master password déjà configuré",
        "master.not_set" => "Master password non configuré",
        "master.configured" => "Master Password configuré.",
        "install.done" => "Menu contextuel SecureVault installé.",
        "uninstall.done" => "Menu contextuel SecureVault désinstallé.",
        "export.no_keys" => "Aucune recovery key enregistrée à exporter.",
        "export.choose_folder" => "Choisir le dossier d'export des recovery keys",
        "error.not_found" => "Introuvable : {path}",

        // Messages de succès/erreur
        "success.locked.file" => "Fichier verrouillé. Il reste visible dans l'Explorateur mais ne s'ouvre plus. Double-cliquez sur le fichier .securevault à côté (ou clic droit → Déverrouiller) pour le récupérer.",
        "success.locked.dir" => "Dossier verrouillé. Il reste visible dans l'Explorateur mais ne s'ouvre plus. Double-cliquez sur le fichier .securevault à côté (ou clic droit → Déverrouiller) pour le récupérer.",
        "success.unlocked.file" => "Fichier déverrouillé avec succès.",
        "success.unlocked.dir" => "Dossier déverrouillé avec succès.",
        "success.decrypted" => "Déchiffré → {path}",
        "error.wrong_password" => "❌ Mot de passe incorrect.",

        // Dashboard
        "dashboard.title" => "🛡️ SecureVault — Centre d'administration",
        "dashboard.tab.files" => "📋 Fichiers protégés",
        "dashboard.tab.settings" => "⚙️ Paramètres",
        "dashboard.tab.about" => "ℹ️ À propos",
        "dashboard.stats.total" => "Total",
        "dashboard.stats.quick" => "Rapide",
        "dashboard.stats.encrypted" => "Chiffré",
        "dashboard.col.name" => "Nom",
        "dashboard.col.path" => "Chemin",
        "dashboard.col.mode" => "Mode",
        "dashboard.col.date" => "Date",
        "dashboard.col.status" => "Statut",
        "dashboard.mode.quick" => "Rapide",
        "dashboard.mode.strong" => "Fort",
        "dashboard.btn.unlock" => "🔓 Déverrouiller",
        "dashboard.btn.decrypt" => "🔑 Déchiffrer",
        "dashboard.btn.remove" => "❌ Retirer",
        "dashboard.btn.refresh" => "🔄 Rafraîchir",
        "dashboard.btn.force" => "🔓 Forcer le déverrouillage",
        "dashboard.btn.force_all" => "🔓 Tout déverrouiller",
        "dashboard.btn.export" => "📥 Exporter les recovery keys",
        "dashboard.force_section" => "Déverrouillage forcé (Admin requis)",

        // Paramètres
        "settings.title" => "⚙️ Paramètres",
        "settings.security" => "Sécurité",
        "settings.reminder" => "Rappel de sécurité :",
        "settings.enabled" => "Activé",
        "settings.delay" => "Délai :",
        "settings.hours" => "heures",
        "settings.appearance" => "Apparence",
        "settings.theme" => "Thème :",
        "settings.theme.red" => "Rouge",
        "settings.theme.blue" => "Bleu",
        "settings.theme.green" => "Vert",
        "settings.backup" => "Sauvegarde",
        "settings.export_path" => "Dossier d'export des recovery keys :",
        "settings.browse" => "Parcourir",
        "settings.save" => "Sauvegarder",
        "settings.saved" => "✅ Paramètres sauvegardés",
        "settings.saved_restart" => "✅ Paramètres sauvegardés.\n\nLes changements prendront effet à la prochaine ouverture du dashboard.",

        // À propos
        "about.version" => "Version {version}",
        "about.description" => "Outil de sécurisation de fichiers pour Windows.",
        "about.developer" => "Développé par SecureVaultPro",
        "about.copyright" => "© 2026 SecureVault33 — Licence MIT",
        "about.docs" => "📖 Documentation :",
        "about.docs_btn" => "Ouvrir la documentation",
        "about.install_dir" => "📁 Dossier d'installation :",
        "about.local_data" => "🔧 Données locales :",
        "about.open" => "Ouvrir",
        "about.built_with" => "Construit avec Rust 🦀",
        "about.crypto" => "Chiffrement : AES-256-GCM + Argon2id",

        // Onboarding
        "onboarding.slide1.title" => "Bienvenue dans SecureVault",
        "onboarding.slide1.body" => "Protégez vos fichiers et dossiers en deux clics, directement depuis l'Explorateur Windows.\n\nDeux niveaux de sécurité adaptés à vos besoins.",
        "onboarding.slide2.title" => "Deux modes de protection",
        "onboarding.slide2.quick_title" => "🔒 Mode Rapide",
        "onboarding.slide2.quick_body" => "Bloque l'accès en un instant.\n\nIdéal pour le quotidien.\n\nRéversible par un admin.",
        "onboarding.slide2.strong_title" => "🛡️ Mode Fort",
        "onboarding.slide2.strong_body" => "Chiffrement AES-256 militaire.\n\nPour vos fichiers les plus sensibles.\n\nIrréversible sans le mot de passe.",
        "onboarding.slide3.title" => "Créez votre Master Password",
        "onboarding.slide3.body" => "Ce mot de passe unique vous permet de forcer le déverrouillage de vos fichiers en mode Rapide en cas d'urgence.",
        "onboarding.btn.next" => "Suivant →",
        "onboarding.btn.prev" => "← Précédent",
        "onboarding.btn.start" => "Commencer ✓",
        "onboarding.window_title" => "🛡️ SecureVault — Bienvenue",

        // Menu contextuel
        "menu.root" => "🛡️ SecureVault",
        "menu.lock" => "🔒 Verrouiller (Rapide)",
        "menu.unlock" => "🔓 Déverrouiller",
        "menu.encrypt" => "🛡️ Chiffrer (Fort)",
        "menu.decrypt" => "🔑 Déchiffrer",
        "menu.dashboard" => "📊 Centre d'administration",

        // --- Chiffrement (mono-element) ---
        "encrypt.delete_confirm.file" => "Fichier chiffré → {path}\n\n⚠️ Supprimer l'original « {name} » de manière sécurisée ?\n(3 passes d'écrasement — irréversible)",
        "encrypt.delete_confirm.dir" => "Dossier chiffré → {path}\n\n⚠️ Supprimer le dossier original de manière sécurisée ?\n(Tous les fichiers écrasés 3 fois — irréversible)",
        "encrypt.deleted.file" => "Le fichier original a été supprimé de façon sécurisée.",
        "encrypt.deleted.dir" => "Le dossier original a été supprimé de façon sécurisée.",
        "encrypt.kept.file" => "Le fichier original a été conservé (non supprimé).",
        "encrypt.kept.dir" => "⚠️ Le dossier original est toujours présent (non supprimé).",
        "encrypt.recovery_notice" => "Conservez cette clé de récupération hors-ligne : elle ne sera plus jamais affichée.\n\n{key}\n\nMot de passe perdu ? Collez cette clé dans le champ mot de passe au moment de déchiffrer.\n\n{note}",

        // --- Lots (selection multiple dans l'Explorateur) ---
        "batch.lock_prompt" => "Choisissez un mot de passe pour verrouiller {count} éléments",
        "batch.encrypt_prompt" => "Définissez un mot de passe pour chiffrer {count} éléments",
        "batch.locked_summary" => "✅ {ok} élément(s) verrouillé(s)",
        "batch.encrypted_summary" => "✅ {ok} élément(s) chiffré(s)",
        "batch.unlocked_summary" => "✅ {ok} déverrouillé(s), ❌ {fail} échoué(s) (mot de passe incorrect)",
        "batch.decrypted_summary" => "✅ {ok} déchiffré(s), ❌ {fail} échoué(s) (mot de passe ou recovery key incorrect)",
        "batch.failures" => "❌ {count} échec(s)",
        "batch.delete_all_confirm" => "{count} élément(s) chiffré(s).\n\n⚠️ Supprimer TOUS les originaux de manière sécurisée ?\n(3 passes d'écrasement — irréversible)",
        "batch.deleted_all" => "Les originaux ont été supprimés de façon sécurisée.",
        "batch.kept_all" => "Les originaux ont été conservés (non supprimés).",
        "batch.recovery_stored" => "Les recovery keys ont été enregistrées : utilisez « Exporter les recovery keys » dans le Centre d'administration pour les récupérer.",
        "batch.unavailable" => "⚠️ La coordination multi-fichiers est indisponible sur ce système : chaque élément sélectionné sera traité séparément, avec une saisie de mot de passe par élément.",

        // --- Deverrouillage force ---
        "force.unlocked_one" => "✅ Fichier déverrouillé de force.",
        "force.summary" => "✅ {ok} fichier(s) déverrouillé(s)\n❌ {fail} échec(s)",
        "force.none_locked" => "Aucun fichier verrouillé à déverrouiller.",
        "force.confirm" => "⚠️ Déverrouiller de force {count} fichier(s) ?\n\nCette action nécessite les droits administrateur.",
        "force.encrypted_blocked" => "Impossible pour les fichiers chiffrés — utilisez la recovery key.",
        "force.skipped" => ", ⚠️ {count} ignoré(s) (chiffrement fort — utilisez la recovery key)",
        "force.elevation_failed" => "L'élévation des privilèges a échoué ou a été refusée.",

        // --- Dashboard : actions ---
        "dashboard.btn.lock" => "🔒 Verrouiller",
        "dashboard.btn.encrypt" => "🛡️ Chiffrer",
        "dashboard.remove_confirm" => "Retirer {count} entrées de la liste ?",
        "dashboard.relock_done" => "✅ {ok} élément(s) re-protégé(s)",
        "dashboard.nothing_selected" => "Sélectionnez d'abord au moins un élément.",

        // --- Export des recovery keys ---
        "export.done" => "✅ Recovery keys exportées dans {path}\n\n⚠️ Imprimez ce fichier et stockez-le en lieu sûr, puis supprimez le fichier numérique.",
        "export.failed" => "Export échoué : {error}",
        "export.unreadable" => "⚠️ {count} clé(s) illisible(s) (scellée(s) avec un Master Password précédent).",
        "export.header_generated" => "Généré le :",
        "export.header_encrypted_on" => "Chiffré le :",
        "export.header_warning" => "Sans ces clés, vos fichiers chiffrés sont IRRÉCUPÉRABLES",
        "export.header_title" => "SECUREVAULT — RECOVERY KEYS",
        "export.header_keep" => "Conservez ce document en lieu sûr.",

        // --- Master Password ---
        "settings.change_master" => "Changer le Master Password",
        "master.change_title" => "🛡️ Changer le Master Password",
        "master.change_old" => "Saisissez votre Master Password ACTUEL",
        "master.change_new" => "Choisissez votre NOUVEAU Master Password",
        "master.changed" => "✅ Master Password modifié. Vos recovery keys ont été re-chiffrées avec le nouveau.",
        "master.recovery_seal_title" => "🛡️ Master Password — enregistrer la recovery key",

        // --- Infobulles des boutons du dashboard ---
        "tip.lock" => "Verrouiller l'élément sélectionné (mode Rapide — permissions NTFS)",
        "tip.unlock" => "Déverrouiller l'élément sélectionné (mode Rapide)",
        "tip.encrypt" => "Chiffrer l'élément sélectionné (mode Fort — AES-256-GCM)",
        "tip.decrypt" => "Déchiffrer le fichier .vault sélectionné (mode Fort)",
        "tip.remove" => "Retirer l'entrée de cette liste — le fichier n'est pas touché",
        "tip.export" => "Exporter toutes les recovery keys enregistrées dans un fichier texte",
        "tip.refresh" => "Recharger la liste depuis le registre",
        "tip.force" => "Reprendre possession de l'élément sélectionné sans son mot de passe (admin requis)",
        "tip.force_all" => "Déverrouiller de force tous les éléments en mode Rapide (admin requis)",

        // --- Licence (1.0.0) ---
        "license.limit_title" => "SecureVault — Version Gratuite",
        "license.locks_limit" => "Vous avez utilisé vos {max} verrouillages gratuits.",
        "license.encrypts_limit" => "Vous avez utilisé vos {max} chiffrements gratuits.",
        "license.locks_insufficient" => "Il vous reste {remaining} verrouillage(s) gratuit(s), mais {count} éléments sont sélectionnés.",
        "license.encrypts_insufficient" => "Il vous reste {remaining} chiffrement(s) gratuit(s), mais {count} éléments sont sélectionnés.",
        "license.upgrade_pitch" => "Passez à SecureVault Pro pour un accès illimité — 20€, une seule fois, pour toujours.",
        "license.buy" => "Acheter sur securevault-app.com",
        "license.later" => "Plus tard",
        "license.status_free" => "SecureVault Gratuit",
        "license.locks_counter" => "Verrouillages : {used}/{max}",
        "license.encrypts_counter" => "Chiffrements : {used}/{max}",
        "license.go_pro" => "Passer à Pro →",
        "license.limit_tip" => "Limite atteinte — Passez à Pro",
        "license.pro_only" => "(Pro)",
        "license.about_title" => "📋 Licence :",
        "license.about_free" => "Version gratuite ({locks_used}/{locks_max} verrouillages, {encrypts_used}/{encrypts_max} chiffrements)",
    });

    Translations { strings }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_key_returns_french_translation() {
        let fr = load_translations("fr");
        assert_eq!(fr.get("dashboard.btn.refresh"), "🔄 Rafraîchir");
    }

    #[test]
    fn unknown_key_falls_back_to_itself() {
        let fr = load_translations("fr");
        assert_eq!(fr.get("this.key.does.not.exist"), "this.key.does.not.exist");
    }

    /// 1.0.2 : l'anglais est retiré. Un `config.json` qui demande encore
    /// `"en"` (ou n'importe quelle autre langue) obtient le français, jamais
    /// des clés brutes.
    #[test]
    fn any_requested_language_gets_french() {
        for lang in ["en", "de", ""] {
            let table = load_translations(lang);
            assert_eq!(table.get("password.validate"), "Valider", "langue {lang:?}");
            assert_eq!(table.strings.len(), load_translations("fr").strings.len());
        }
    }

    /// Le sélecteur de langue a disparu de l'interface : sa clé aussi.
    #[test]
    fn language_setting_label_is_gone() {
        let fr = load_translations("fr");
        assert_eq!(fr.get("settings.language"), "settings.language");
    }

    /// Accolades équilibrées dans chaque texte : un `{count` mal fermé ne se
    /// voit qu'à l'exécution, sous la forme d'un message tronqué.
    #[test]
    fn placeholders_are_well_formed() {
        let fr = load_translations("fr");
        let mut broken = Vec::new();
        for (key, value) in fr.strings.iter() {
            if value.matches('{').count() != value.matches('}').count() {
                broken.push(*key);
            }
        }
        broken.sort();
        assert!(broken.is_empty(), "marqueurs mal formés : {broken:?}");
    }
}

#![windows_subsystem = "windows"]

mod acl;
mod batch;
mod cli;
mod crypto;
mod dashboard;
mod errors;
mod i18n;
mod license;
mod onboarding;
mod registry;
mod ui;

use cli::Action;
use errors::{Result, SecureVaultError};
use i18n::t;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Titre générique, pour les messages non liés à une action de mot de passe
/// précise (install/uninstall, erreurs génériques).
const APP_TITLE: &str = "🔒 SecureVault";

fn lock_title() -> &'static str {
    t("password.title.lock")
}
fn unlock_title() -> &'static str {
    t("password.title.unlock")
}
fn encrypt_title() -> &'static str {
    t("password.title.encrypt")
}
fn decrypt_title() -> &'static str {
    t("password.title.decrypt")
}
fn master_setup_title() -> &'static str {
    t("master.setup_title")
}
fn master_setup_label() -> &'static str {
    t("master.setup_label")
}

/// Substitution de paramètres dans une chaîne traduite : `{count}`, `{path}`…
/// Les clés i18n portent ces marqueurs plutôt que d'être découpées en
/// morceaux concaténés, parce que l'ordre des mots change d'une langue à
/// l'autre.
fn fill(template: &str, params: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (key, value) in params {
        out = out.replace(&format!("{{{key}}}"), value);
    }
    out
}

/// Message adapté à la nature de la cible : les clés `*.file` et `*.dir`
/// existent en double précisément pour ne pas annoncer « Fichier verrouillé »
/// après avoir verrouillé un dossier.
fn t_kind(base: &'static str, is_directory: bool) -> &'static str {
    // Les clés i18n sont des `&'static str` : la concaténation doit se faire
    // sur une table fermée, pas dynamiquement.
    match (base, is_directory) {
        ("success.locked", false) => t("success.locked.file"),
        ("success.locked", true) => t("success.locked.dir"),
        ("success.unlocked", false) => t("success.unlocked.file"),
        ("success.unlocked", true) => t("success.unlocked.dir"),
        ("encrypt.delete_confirm", false) => t("encrypt.delete_confirm.file"),
        ("encrypt.delete_confirm", true) => t("encrypt.delete_confirm.dir"),
        ("encrypt.deleted", false) => t("encrypt.deleted.file"),
        ("encrypt.deleted", true) => t("encrypt.deleted.dir"),
        ("encrypt.kept", false) => t("encrypt.kept.file"),
        ("encrypt.kept", true) => t("encrypt.kept.dir"),
        _ => base,
    }
}

/// Retourne le mot de passe fourni en argument, ou sollicite la popup simple
/// sinon (déverrouillage, déchiffrement — vérification d'un mot de passe
/// EXISTANT : pas de barre de force, pas de confirmation). `validator`, s'il
/// est fourni, permet à la popup de proposer un nouvel essai sur place en cas
/// de mot de passe incorrect au lieu de se fermer immédiatement — voir
/// `ui::show_password_prompt`. Sans effet quand `password` est déjà fourni
/// (usage scriptable via `--password`, pas de popup dans ce cas).
///
/// Le `Zeroizing` est propagé jusqu'aux fonctions crypto plutôt que copié
/// dans une `String` ordinaire : c'était le trou de la 0.6.1, où toute la
/// protection de la popup était annulée par un `.to_string()`.
fn resolve_password(
    password: Option<String>,
    title: &str,
    validator: Option<ui::PasswordValidator>,
) -> Result<Zeroizing<String>> {
    match password {
        Some(p) => Ok(Zeroizing::new(p)),
        None => {
            let prompt = ui::show_password_prompt(title, validator)?;
            Ok(prompt.password)
        }
    }
}

/// Retourne le mot de passe fourni en argument, ou sollicite la popup avec
/// confirmation + indicateur de force sinon — à chaque fois qu'on CRÉE un
/// mot de passe (verrouillage ET chiffrement).
fn resolve_password_confirm(
    password: Option<String>,
    title: &str,
    label: &str,
) -> Result<Zeroizing<String>> {
    match password {
        Some(p) => Ok(Zeroizing::new(p)),
        None => {
            let prompt = ui::show_password_confirm_prompt(title, label)?;
            Ok(prompt.password)
        }
    }
}

/// S'assure qu'un Master Password est configuré, en le demandant à
/// l'utilisateur si besoin (premier `lock`/`encrypt`/`install`, ou usage
/// portable sans passer par `install`).
///
/// Retourne `Some(mot de passe)` UNIQUEMENT quand il vient d'être créé dans
/// cet appel : c'est le seul moment où on le connaît sans le redemander, et
/// il sert alors à sceller la recovery key (voir `ask_master_for_recovery`).
fn ensure_master_password() -> Result<Option<Zeroizing<String>>> {
    if dashboard::master::is_master_password_set() {
        return Ok(None);
    }
    let prompt = ui::show_password_confirm_prompt(master_setup_title(), master_setup_label())?;
    dashboard::master::setup_master_password(&prompt.password)?;
    Ok(Some(prompt.password))
}

/// Demande le Master Password pour pouvoir CHIFFRER la recovery key avant de
/// l'enregistrer dans le registre.
///
/// Volontairement annulable : la recovery key vient d'être affichée à
/// l'utilisateur, qui peut très bien l'avoir notée et ne pas vouloir d'une
/// copie sur disque. Annuler ne fait pas échouer le chiffrement — on
/// n'enregistre simplement rien, ce qui est strictement plus sûr que
/// l'ancien comportement (0.6.1 écrivait la clé EN CLAIR dans le JSON, sans
/// rien demander à personne).
///
/// `already_known` court-circuite la popup quand le Master Password vient
/// d'être créé dans la même commande.
fn ask_master_for_recovery(already_known: Option<Zeroizing<String>>) -> Option<Zeroizing<String>> {
    if let Some(master) = already_known {
        return Some(master);
    }
    if !dashboard::master::is_master_password_set() {
        return None;
    }

    let validator: ui::PasswordValidator = Box::new(|candidate: &str| {
        dashboard::master::verify_master_password(candidate).unwrap_or(false)
    });
    ui::show_password_prompt(t("master.recovery_seal_title"), Some(validator))
        .ok()
        .map(|prompt| prompt.password)
}

/// Vérifie le quota gratuit AVANT toute saisie : faire taper un mot de passe
/// pour ensuite refuser l'action serait une mauvaise surprise. Si le quota est
/// insuffisant, la popup de mise à niveau est proposée ; l'annuler sort en
/// silence (`Cancelled`).
///
/// N'est appelée QUE pour créer une protection (verrouiller, chiffrer) :
/// déverrouiller et déchiffrer ne sont jamais soumis à licence.
fn require_quota(quota: license::Quota, count: usize) -> Result<()> {
    if ui::license_prompt::offer_upgrade(quota, count as u32) {
        Ok(())
    } else {
        Err(SecureVaultError::Cancelled)
    }
}

/// Décompte best-effort, APRÈS succès : une protection déjà appliquée ne doit
/// jamais être annulée ni signalée en erreur parce que `usage.json` n'a pas pu
/// être écrit.
fn record_usage(quota: license::Quota, count: usize) {
    let _ = license::record(quota, count as u32);
}

fn run_lock(chemin: &Path, password: Option<String>) -> Result<()> {
    require_quota(license::Quota::Lock, 1)?;
    ensure_master_password()?;

    // Nouveau mot de passe : barre de force + confirmation, comme pour `encrypt`.
    let password = resolve_password_confirm(password, lock_title(), t("password.choose_lock"))?;
    let is_directory = chemin.is_dir();
    acl::lock(chemin, &password)?;
    record_usage(license::Quota::Lock, 1);

    if let Some(path_str) = chemin.to_str() {
        let _ = dashboard::registry::add_entry(
            path_str,
            path_str,
            "acl_locked",
            is_directory,
            None,
            None,
        );
    }

    ui::show_info(APP_TITLE, t_kind("success.locked", is_directory));
    Ok(())
}

fn run_unlock(chemin: &Path, password: Option<String>) -> Result<()> {
    // Mot de passe existant : pas de barre de force ni de confirmation. Le
    // validateur vérifie le mot de passe SANS déverrouiller (voir
    // `acl::verify_password`) : en cas d'échec, la popup reste ouverte pour
    // un nouvel essai au lieu de se fermer sur une erreur définitive.
    let target = chemin.to_path_buf();
    let validator: ui::PasswordValidator =
        Box::new(move |candidate: &str| acl::verify_password(&target, candidate).unwrap_or(false));
    let password = resolve_password(password, unlock_title(), Some(validator))?;

    // Relevé AVANT le déverrouillage : après restauration de la DACL, la
    // cible est bien toujours là, mais autant ne pas dépendre de l'ordre.
    let is_directory = chemin.is_dir();

    acl::unlock(chemin, &password)?;

    if let Some(path_str) = chemin.to_str() {
        let _ = dashboard::registry::update_status(path_str, "unlocked");
    }

    ui::show_info(APP_TITLE, t_kind("success.unlocked", is_directory));
    Ok(())
}

/// Lit le chemin cible stocké dans un fichier compagnon `.securevault` (texte
/// brut, chemin absolu), créé par `lock_path` à côté de l'élément verrouillé.
fn run_unlock_companion(companion_path: &Path, password: Option<String>) -> Result<()> {
    let content = std::fs::read_to_string(companion_path).map_err(|_| {
        SecureVaultError::InvalidFormat("fichier .securevault introuvable ou illisible".into())
    })?;
    let target = PathBuf::from(content.trim());
    if target.as_os_str().is_empty() {
        return Err(SecureVaultError::InvalidFormat(
            "fichier .securevault vide ou corrompu".into(),
        ));
    }

    run_unlock(&target, password)
}

fn run_encrypt(
    chemin: &Path,
    password: &str,
    master_if_just_created: Option<Zeroizing<String>>,
) -> Result<()> {
    // Vérifié AVANT chiffrement : la source n'est pas encore touchée à ce
    // stade (la suppression, elle, est une étape séparée et confirmée
    // ci-dessous), donc `chemin` reflète encore fidèlement fichier/dossier.
    let is_directory = chemin.is_dir();

    let (vault_path, recovery_key) = crypto::encrypt_path(chemin, password)?;
    record_usage(license::Quota::Encrypt, 1);
    let vault_display = vault_path.display().to_string();

    let name = chemin
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();

    let delete_original = ui::show_confirm(
        APP_TITLE,
        &fill(
            t_kind("encrypt.delete_confirm", is_directory),
            &[("path", &vault_display), ("name", &name)],
        ),
    );

    let deletion_note = if delete_original {
        if is_directory {
            crypto::secure_delete::secure_delete_directory(chemin)?;
        } else {
            crypto::secure_delete::secure_delete(chemin)?;
        }
        t_kind("encrypt.deleted", is_directory)
    } else {
        t_kind("encrypt.kept", is_directory)
    };

    ui::show_info(
        APP_TITLE,
        &fill(
            t("encrypt.recovery_notice"),
            &[("key", &recovery_key), ("note", deletion_note)],
        ),
    );

    // Après l'affichage : l'utilisateur a eu la clé sous les yeux, la question
    // « voulez-vous que SecureVault la garde ? » a du sens à ce moment-là.
    let master = ask_master_for_recovery(master_if_just_created);
    if let (Some(original_str), Some(vault_str)) = (chemin.to_str(), vault_path.to_str()) {
        let _ = dashboard::registry::add_entry(
            original_str,
            vault_str,
            "encrypted",
            is_directory,
            Some(&recovery_key),
            master.as_ref().map(|m| m.as_str()),
        );
    }

    Ok(())
}

fn run_decrypt(chemin: &Path, password: Option<String>) -> Result<()> {
    // Secret existant : pas de barre de force ni de confirmation. La popup
    // accepte le mot de passe OU la recovery key (détection automatique dans
    // `crypto::decrypt_path`). Le validateur ne déchiffre que l'en-tête
    // (~48 octets) plutôt que le fichier/dossier complet à chaque essai —
    // voir `crypto::aes_gcm::verify_password`.
    let secret = match password {
        Some(p) => Zeroizing::new(p),
        None => {
            let target = chemin.to_path_buf();
            let validator: ui::PasswordValidator = Box::new(move |candidate: &str| {
                crypto::verify_password(&target, candidate).unwrap_or(false)
            });
            let legacy = crypto::is_legacy_vault(chemin);
            ui::show_decrypt_prompt(decrypt_title(), legacy, Some(validator))?.password
        }
    };

    let outcome = crypto::decrypt_path(chemin, &secret)?;

    if let Some(vault_str) = chemin.to_str() {
        let _ = dashboard::registry::update_status(vault_str, "unlocked");
    }

    let mut message = fill(
        t("success.decrypted"),
        &[("path", &outcome.output_path.display().to_string())],
    );
    if outcome.legacy_format {
        message.push_str("\n\n");
        message.push_str(t("decrypt.legacy_warning"));
    }
    ui::show_info(APP_TITLE, &message);
    Ok(())
}

/// Ligne « ❌ N échec(s) » suivie du détail, ajoutée à un résumé de lot.
fn append_failures(message: &mut String, failures: &[(String, String)]) {
    if failures.is_empty() {
        return;
    }
    message.push('\n');
    message.push_str(&fill(
        t("batch.failures"),
        &[("count", &failures.len().to_string())],
    ));
    for (path, err) in failures {
        message.push_str(&format!("\n  • {path} : {err}"));
    }
}

/// Verrouille tous les `chemins` avec UN SEUL mot de passe (demandé une
/// fois), puis affiche UN SEUL résumé — utilisé quand plusieurs instances de
/// l'exe ont été lancées simultanément par l'Explorateur (sélection
/// multiple + clic droit → Verrouiller) et coordonnées via `batch`. Appelé
/// uniquement quand `chemins.len() > 1` : le cas à un seul fichier passe par
/// `run_lock`, inchangé.
fn run_lock_batch(chemins: &[PathBuf]) -> Result<()> {
    require_quota(license::Quota::Lock, chemins.len())?;
    ensure_master_password()?;
    let label = fill(t("batch.lock_prompt"), &[("count", &chemins.len().to_string())]);
    let password = resolve_password_confirm(None, lock_title(), &label)?;

    let mut ok = 0usize;
    let mut failures: Vec<(String, String)> = Vec::new();
    for chemin in chemins {
        let is_directory = chemin.is_dir();
        match acl::lock(chemin, &password) {
            Ok(()) => {
                ok += 1;
                if let Some(path_str) = chemin.to_str() {
                    let _ = dashboard::registry::add_entry(
                        path_str,
                        path_str,
                        "acl_locked",
                        is_directory,
                        None,
                        None,
                    );
                }
            }
            Err(e) => failures.push((chemin.display().to_string(), e.to_string())),
        }
    }

    record_usage(license::Quota::Lock, ok);
    let mut message = fill(t("batch.locked_summary"), &[("ok", &ok.to_string())]);
    append_failures(&mut message, &failures);
    ui::show_info(APP_TITLE, &message);
    Ok(())
}

/// Déverrouille tous les `chemins` — un seul prompt de mot de passe (sans
/// validateur ciblé sur un fichier précis, puisque plusieurs fichiers avec
/// des mots de passe différents peuvent être dans le lot), tenté sur
/// chacun, avec un résumé succès/échec unique.
fn run_unlock_batch(chemins: &[PathBuf]) -> Result<()> {
    let Ok(prompt) = ui::show_password_prompt(unlock_title(), None) else {
        return Ok(());
    };

    let mut ok = 0usize;
    for chemin in chemins {
        if acl::unlock(chemin, &prompt.password).is_ok() {
            ok += 1;
            if let Some(path_str) = chemin.to_str() {
                let _ = dashboard::registry::update_status(path_str, "unlocked");
            }
        }
    }
    let fail = chemins.len() - ok;
    ui::show_info(
        APP_TITLE,
        &fill(
            t("batch.unlocked_summary"),
            &[("ok", &ok.to_string()), ("fail", &fail.to_string())],
        ),
    );
    Ok(())
}

/// Chiffre tous les `chemins` avec UN SEUL mot de passe, une seule
/// confirmation de suppression sécurisée des originaux (appliquée à tous),
/// et un résumé unique. Les recovery keys individuelles ne sont pas
/// ré-affichées ici (illisible pour un lot) : elles sont enregistrées
/// chiffrées dans le registre, récupérables via "Exporter les recovery keys"
/// dans le dashboard.
fn run_encrypt_batch(chemins: &[PathBuf]) -> Result<()> {
    require_quota(license::Quota::Encrypt, chemins.len())?;
    let master_if_just_created = ensure_master_password()?;
    let label = fill(
        t("batch.encrypt_prompt"),
        &[("count", &chemins.len().to_string())],
    );
    let password = resolve_password_confirm(None, encrypt_title(), &label)?;

    // Demandé une seule fois pour tout le lot, avant la boucle : c'est la
    // condition pour enregistrer les recovery keys chiffrées.
    let master = ask_master_for_recovery(master_if_just_created);

    let mut ok = 0usize;
    let mut failures: Vec<(String, String)> = Vec::new();
    let mut encrypted_originals: Vec<(PathBuf, bool)> = Vec::new();

    for chemin in chemins {
        let is_directory = chemin.is_dir();
        match crypto::encrypt_path(chemin, &password) {
            Ok((vault_path, recovery_key)) => {
                ok += 1;
                if let (Some(original_str), Some(vault_str)) =
                    (chemin.to_str(), vault_path.to_str())
                {
                    let _ = dashboard::registry::add_entry(
                        original_str,
                        vault_str,
                        "encrypted",
                        is_directory,
                        Some(&recovery_key),
                        master.as_ref().map(|m| m.as_str()),
                    );
                }
                encrypted_originals.push((chemin.clone(), is_directory));
            }
            Err(e) => failures.push((chemin.display().to_string(), e.to_string())),
        }
    }
    record_usage(license::Quota::Encrypt, ok);

    let confirm_delete = !encrypted_originals.is_empty()
        && ui::show_confirm(
            APP_TITLE,
            &fill(
                t("batch.delete_all_confirm"),
                &[("count", &encrypted_originals.len().to_string())],
            ),
        );

    let deletion_note = if confirm_delete {
        for (original, is_directory) in &encrypted_originals {
            let result = if *is_directory {
                crypto::secure_delete::secure_delete_directory(original)
            } else {
                crypto::secure_delete::secure_delete(original)
            };
            if let Err(e) = result {
                failures.push((original.display().to_string(), e.to_string()));
            }
        }
        t("batch.deleted_all")
    } else if encrypted_originals.is_empty() {
        ""
    } else {
        t("batch.kept_all")
    };

    let mut message = fill(t("batch.encrypted_summary"), &[("ok", &ok.to_string())]);
    append_failures(&mut message, &failures);
    if !deletion_note.is_empty() {
        message.push_str("\n\n");
        message.push_str(deletion_note);
    }
    if master.is_some() {
        message.push_str("\n\n");
        message.push_str(t("batch.recovery_stored"));
    }
    ui::show_info(APP_TITLE, &message);
    Ok(())
}

/// Déchiffre tous les `chemins` — un seul prompt de mot de passe tenté sur
/// chacun, résumé unique.
fn run_decrypt_batch(chemins: &[PathBuf]) -> Result<()> {
    // Une recovery key est propre à UN fichier : collée ici, elle n'ouvre que
    // celui-là et les autres comptent comme échecs — comportement attendu.
    let Ok(prompt) = ui::show_decrypt_prompt(decrypt_title(), false, None) else {
        return Ok(());
    };

    let mut ok = 0usize;
    let mut legacy = 0usize;
    for chemin in chemins {
        if let Ok(outcome) = crypto::decrypt_path(chemin, &prompt.password) {
            ok += 1;
            if outcome.legacy_format {
                legacy += 1;
            }
            if let Some(vault_str) = chemin.to_str() {
                let _ = dashboard::registry::update_status(vault_str, "unlocked");
            }
        }
    }
    let fail = chemins.len() - ok;
    let mut message = fill(
        t("batch.decrypted_summary"),
        &[("ok", &ok.to_string()), ("fail", &fail.to_string())],
    );
    if legacy > 0 {
        message.push_str("\n\n");
        message.push_str(&fill(t("decrypt.legacy_batch"), &[("count", &legacy.to_string())]));
    }
    ui::show_info(APP_TITLE, &message);
    Ok(())
}

/// Coordonne les instances lancées en parallèle par l'Explorateur (sélection
/// multiple) via `batch::try_become_leader`. Une instance `Follower` a déjà
/// déposé son chemin pour le leader et doit se terminer silencieusement
/// (`Ok(())`, aucune popup). Le leader traite le lot : `chemins.len() == 1`
/// (cas normal, un seul fichier sélectionné) délègue à `single` pour un
/// comportement strictement inchangé ; sinon `batch` gère le résumé unique.
///
/// `scripted` (un `--password` en ligne de commande) court-circuite tout le
/// mécanisme : une invocation scriptée n'a aucune raison d'attendre 500 ms,
/// ni de ramasser les chemins d'une sélection Explorateur en cours, ni — bien
/// pire — de se retrouver `Follower` et de ne RIEN faire en silence avec un
/// code de sortie 0.
fn run_batched(
    action: &str,
    chemin: &Path,
    scripted: bool,
    single: impl FnOnce(&Path) -> Result<()>,
    batch: impl FnOnce(&[PathBuf]) -> Result<()>,
) -> Result<()> {
    if scripted {
        return single(chemin);
    }

    let Some(chemin_str) = chemin.to_str() else {
        return single(chemin);
    };

    match crate::batch::try_become_leader(action, chemin_str) {
        crate::batch::LeaderStatus::Follower => Ok(()),
        crate::batch::LeaderStatus::Unavailable => {
            // Mieux vaut prévenir et agir que disparaître sans bruit.
            ui::show_info(APP_TITLE, t("batch.unavailable"));
            single(chemin)
        }
        crate::batch::LeaderStatus::Leader(guard) => {
            let chemins: Vec<PathBuf> = guard.paths.iter().map(PathBuf::from).collect();
            let result = if chemins.len() <= 1 {
                single(chemin)
            } else {
                batch(&chemins)
            };
            guard.finish();
            result
        }
    }
}

/// Affiche l'écran de bienvenue au tout premier lancement (voir
/// `onboarding`), sauf pour les utilisateurs qui ont déjà un Master Password
/// configuré (mise à niveau depuis une version antérieure à 0.6.0 : la
/// config `first_launch_done` n'existe pas encore, mais l'onboarding
/// n'apporterait rien à quelqu'un qui utilise déjà l'outil — on marque
/// simplement `first_launch_done` sans rien afficher). Retourne `false` si
/// l'utilisateur a fermé l'onboarding sans le terminer : l'appelant doit
/// alors s'arrêter là plutôt que d'ouvrir le dashboard sans Master Password.
fn maybe_show_onboarding() -> Result<bool> {
    let mut cfg = dashboard::settings::load_settings();
    if cfg.first_launch_done {
        return Ok(true);
    }
    if dashboard::master::is_master_password_set() {
        cfg.first_launch_done = true;
        let _ = dashboard::settings::save_settings(&cfg);
        return Ok(true);
    }
    onboarding::show()
}

fn run(args: cli::Cli) -> Result<()> {
    match args.action.unwrap_or(Action::Dashboard) {
        Action::Lock { chemin, password } => {
            let scripted = password.is_some();
            run_batched(
                "lock",
                &chemin,
                scripted,
                |c| run_lock(c, password.clone()),
                run_lock_batch,
            )
        }
        Action::Unlock { chemin, password } => {
            let scripted = password.is_some();
            run_batched(
                "unlock",
                &chemin,
                scripted,
                |c| run_unlock(c, password.clone()),
                run_unlock_batch,
            )
        }
        Action::UnlockCompanion { chemin, password } => run_unlock_companion(&chemin, password),
        Action::Encrypt { chemin, password } => {
            let scripted = password.is_some();
            run_batched(
                "encrypt",
                &chemin,
                scripted,
                |c| {
                    require_quota(license::Quota::Encrypt, 1)?;
                    let master_if_just_created = ensure_master_password()?;
                    let pwd = resolve_password_confirm(
                        password.clone(),
                        encrypt_title(),
                        t("password.choose_encrypt"),
                    )?;
                    run_encrypt(c, &pwd, master_if_just_created)
                },
                run_encrypt_batch,
            )
        }
        Action::Decrypt { chemin, password } => {
            let scripted = password.is_some();
            run_batched(
                "decrypt",
                &chemin,
                scripted,
                |c| run_decrypt(c, password.clone()),
                run_decrypt_batch,
            )
        }
        Action::Install => {
            if !maybe_show_onboarding()? {
                return Ok(());
            }
            ensure_master_password()?;
            registry::install_context_menu()?;
            ui::show_info(APP_TITLE, t("install.done"));
            Ok(())
        }
        Action::Uninstall => {
            registry::uninstall_context_menu()?;
            ui::show_info(APP_TITLE, t("uninstall.done"));
            Ok(())
        }
        Action::Dashboard => {
            if !maybe_show_onboarding()? {
                return Ok(());
            }
            dashboard::window::show()
        }
        Action::ForceUnlock { chemins } => {
            let mut ok = 0usize;
            let mut failures: Vec<(String, String)> = Vec::new();
            for chemin in &chemins {
                match dashboard::force_unlock::force_unlock_path(chemin) {
                    Ok(()) => ok += 1,
                    Err(e) => failures.push((chemin.display().to_string(), e.to_string())),
                }
            }
            if chemins.len() == 1 && failures.is_empty() {
                ui::show_info(APP_TITLE, t("force.unlocked_one"));
            } else {
                let mut message = fill(
                    t("force.summary"),
                    &[("ok", &ok.to_string()), ("fail", &failures.len().to_string())],
                );
                for (path, err) in &failures {
                    message.push_str(&format!("\n  • {path} : {err}"));
                }
                ui::show_info(APP_TITLE, &message);
            }
            Ok(())
        }
        Action::ForceUnlockAll => {
            if !dashboard::master::is_master_password_set() {
                return Err(SecureVaultError::MasterPassword(t("master.not_set").into()));
            }
            let validator: ui::PasswordValidator = Box::new(|candidate: &str| {
                dashboard::master::verify_master_password(candidate).unwrap_or(false)
            });
            ui::show_password_prompt(t("password.master_required_title"), Some(validator))?;

            let candidates = dashboard::registry::find_locked_acl_entries()?;
            let results = dashboard::force_unlock::force_unlock_all(&candidates)?;
            let ok = results.iter().filter(|(_, r)| r.is_ok()).count();
            let failures: Vec<(String, String)> = results
                .iter()
                .filter_map(|(path, r)| r.as_ref().err().map(|e| (path.clone(), e.to_string())))
                .collect();
            let mut message = fill(
                t("force.summary"),
                &[("ok", &ok.to_string()), ("fail", &failures.len().to_string())],
            );
            for (path, err) in &failures {
                message.push_str(&format!("\n  • {path} : {err}"));
            }
            ui::show_info(APP_TITLE, &message);
            Ok(())
        }
        Action::SetupMaster => {
            if dashboard::master::is_master_password_set() {
                return Err(SecureVaultError::MasterPassword(
                    t("master.already_set").into(),
                ));
            }
            let prompt =
                ui::show_password_confirm_prompt(master_setup_title(), master_setup_label())?;
            dashboard::master::setup_master_password(&prompt.password)?;
            ui::show_info(APP_TITLE, t("master.configured"));
            Ok(())
        }
    }
}

fn main() {
    // Langue et thème sont figés pour toute la durée du processus — voir les
    // notes dans `i18n`/`ui::theme` sur pourquoi un redémarrage du dashboard
    // est nécessaire après un changement dans les paramètres.
    let cfg = dashboard::settings::load_settings();
    i18n::init(&cfg.language);
    ui::theme::init_theme(&cfg.theme);

    let args = cli::parse();
    if let Err(e) = run(args) {
        match e {
            // Fermer une popup est une décision de l'utilisateur, pas un
            // incident : sortir sans rien afficher, et avec un code 0 pour
            // qu'un script n'y voie pas un échec.
            SecureVaultError::Cancelled => return,
            SecureVaultError::InvalidPassword => {
                ui::show_error(APP_TITLE, t("error.wrong_password"));
            }
            other => {
                ui::show_error(APP_TITLE, &other.to_string());
            }
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::sync::Mutex;

    // Même précaution que `dashboard::registry::tests` / `dashboard::master::tests`
    // (ressource partagée sous `%LOCALAPPDATA%`) : verrouillé + `--test-threads=1`.
    static INTEGRATION_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn temp_dir(name: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("securevault_main_test_{}_{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Reproduit le câblage réel de `run_lock`/`run_unlock` (appel ACL puis
    /// bookkeeping du registre), sans passer par `ensure_master_password` ni
    /// les popups Win32 (non pertinents ici et incompatibles avec un test
    /// automatisé/headless).
    #[test]
    fn lock_then_unlock_updates_registry_status() {
        let _guard = INTEGRATION_TEST_LOCK.lock().unwrap();
        let registry_path = dashboard::registry::get_registry_path().unwrap();
        let original_registry = std::fs::read_to_string(&registry_path).ok();
        let _ = std::fs::remove_file(&registry_path);

        let dir = temp_dir("lock_unlock_integration");
        let target = dir.join("document.txt");
        std::fs::write(&target, b"contenu").unwrap();
        let path_str = target.to_str().unwrap();

        // --- lock ---
        acl::lock(&target, "mot-de-passe-integration").unwrap();
        dashboard::registry::add_entry(path_str, path_str, "acl_locked", false, None, None).unwrap();

        let entries = dashboard::registry::list_entries().unwrap();
        let entry = entries
            .iter()
            .find(|e| e.original_path == path_str)
            .expect("l'entrée doit apparaître dans le registre après lock");
        assert_eq!(entry.mode, "acl_locked");
        assert_eq!(entry.status, "locked");
        assert!(!entry.is_directory);

        let locked = dashboard::registry::find_locked_acl_entries().unwrap();
        assert!(locked.iter().any(|e| e.original_path == path_str));

        // --- unlock ---
        acl::unlock(&target, "mot-de-passe-integration").unwrap();
        dashboard::registry::update_status(path_str, "unlocked").unwrap();

        let entries = dashboard::registry::list_entries().unwrap();
        let entry = entries
            .iter()
            .find(|e| e.original_path == path_str)
            .expect("l'entrée doit toujours être présente après unlock");
        assert_eq!(entry.status, "unlocked");

        let locked = dashboard::registry::find_locked_acl_entries().unwrap();
        assert!(!locked.iter().any(|e| e.original_path == path_str));

        assert_eq!(std::fs::read(&target).unwrap(), b"contenu");

        // Nettoyage.
        let _ = std::fs::remove_file(&target);
        match original_registry {
            Some(content) => std::fs::write(&registry_path, content).unwrap(),
            None => {
                let _ = std::fs::remove_file(&registry_path);
            }
        }
    }
}

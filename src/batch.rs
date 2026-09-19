//! Coordonne plusieurs instances de `securevault.exe` lancées SIMULTANÉMENT
//! par l'Explorateur Windows : quand l'utilisateur sélectionne plusieurs
//! fichiers puis clic droit → SecureVault → Verrouiller (ou Chiffrer, etc.),
//! Windows lance une instance de l'exe PAR fichier sélectionné, chacune ne
//! recevant qu'un seul `%1`. Sans coordination, chaque instance afficherait
//! sa propre popup de mot de passe en même temps.
//!
//! Mécanisme : la première instance à créer un mutex nommé
//! `Global\SecureVaultBatch_<action>` devient le "leader" — elle attend que
//! les autres instances se signalent, lit tous les chemins déposés dans un
//! fichier temporaire partagé, traite le tout et affiche un résumé unique.
//! Les instances suivantes ("followers") déposent juste leur chemin dans ce
//! fichier et se terminent silencieusement (le leader les traitera).

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use windows::core::HSTRING;
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
use windows::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject, INFINITE};

/// Durée pendant laquelle le leader attend les autres instances du lot.
const COLLECT_WINDOW: Duration = Duration::from_millis(500);

/// Durée au-delà de laquelle une ligne du fichier batch est considérée comme
/// orpheline et jetée.
///
/// Sans cette péremption, un chemin déposé APRÈS que le leader ait vidé le
/// fichier y restait indéfiniment — et se faisait traiter par le lot suivant,
/// des heures ou des jours plus tard, avec le mot de passe de CE lot-là.
/// L'utilisateur se retrouvait avec un fichier chiffré qu'il n'avait pas
/// sélectionné, sous un mot de passe qu'il n'associait pas à lui.
const ORPHAN_TTL: Duration = Duration::from_secs(5);

/// Résultat de `try_become_leader`.
pub enum LeaderStatus {
    /// Cette instance doit traiter tous les chemins du lot puis appeler
    /// `LeaderGuard::finish` une fois terminé (relâche le mutex de lot).
    Leader(LeaderGuard),
    /// Une autre instance est déjà leader pour cette action ; le chemin de
    /// cette instance a été déposé dans le fichier batch partagé. Cette
    /// instance doit se terminer immédiatement, sans rien afficher.
    Follower,
    /// La coordination inter-process est indisponible (création du mutex
    /// refusée : privilège manquant, quota, politique système). Cette
    /// instance traite son propre chemin SEULE.
    ///
    /// C'est volontairement un état distinct de `Follower` : renvoyer
    /// `Follower` dans ce cas — ce que faisait la 0.6.1 — faisait abandonner
    /// TOUTES les instances en silence, exit code 0, sans la moindre popup.
    /// L'utilisateur croyait ses fichiers protégés alors que rien ne s'était
    /// produit. Mieux vaut N popups qu'aucune action.
    Unavailable,
}

/// Garde le mutex de leadership vivant : le relâcher trop tôt permettrait à
/// une instance lancée un peu plus tard (l'Explorateur peut échelonner le
/// lancement des process sur plusieurs centaines de ms) de devenir à son
/// tour leader et de traiter une partie des fichiers en double.
pub struct LeaderGuard {
    mutex: HANDLE,
    pub paths: Vec<String>,
}

impl LeaderGuard {
    /// À appeler une fois tous les chemins du lot traités et le résumé
    /// affiché : relâche puis ferme le mutex de leadership.
    pub fn finish(self) {
        unsafe {
            let _ = ReleaseMutex(self.mutex);
            let _ = CloseHandle(self.mutex);
        }
    }
}

/// Fichier batch, un par action (`lock`, `unlock`, `encrypt`, `decrypt`) —
/// et non un nom fixe unique — pour ne jamais mélanger les chemins d'un
/// `lock` et d'un `encrypt` déclenchés au même moment sur deux sélections
/// différentes dans l'Explorateur.
fn batch_file_path(action: &str) -> PathBuf {
    std::env::temp_dir().join(format!("securevault_batch_{action}.txt"))
}

fn leader_mutex_name(action: &str) -> HSTRING {
    HSTRING::from(format!("Global\\SecureVaultBatch_{action}"))
}

fn file_lock_mutex_name(action: &str) -> HSTRING {
    HSTRING::from(format!("Global\\SecureVaultBatchFile_{action}"))
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Analyse une ligne du fichier batch (`<timestamp_ms>|<chemin>`) et ne la
/// retourne que si elle est encore fraîche.
///
/// Les lignes sans séparateur viennent d'une instance 0.6.x lancée en
/// parallèle pendant une mise à jour : sans horodatage on ne peut pas juger
/// de leur fraîcheur, donc on les jette plutôt que risquer de traiter un
/// fichier arbitraire.
fn parse_fresh_line(line: &str, now_ms: u128) -> Option<String> {
    let (timestamp, path) = line.split_once('|')?;
    let timestamp: u128 = timestamp.trim().parse().ok()?;
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    if now_ms.saturating_sub(timestamp) > ORPHAN_TTL.as_millis() {
        return None;
    }
    Some(path.to_string())
}

/// Section critique courte, protégée par un mutex DÉDIÉ (distinct de celui
/// du leadership) : ajoute `path` au fichier batch, horodaté. Utilisé aussi
/// bien par le leader (dépose son propre chemin) que par les followers.
fn append_path_locked(action: &str, path: &str) {
    let name = file_lock_mutex_name(action);
    let Ok(handle) = (unsafe { CreateMutexW(None, false, &name) }) else {
        return;
    };
    unsafe {
        WaitForSingleObject(handle, INFINITE);
    }

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(batch_file_path(action))
    {
        let _ = writeln!(file, "{}|{}", now_millis(), path);
    }

    unsafe {
        let _ = ReleaseMutex(handle);
        let _ = CloseHandle(handle);
    }
}

/// Même section critique : lit puis vide le fichier batch, en ne retenant que
/// les lignes de moins de `ORPHAN_TTL`. Le fichier est supprimé dans tous les
/// cas — les lignes périmées disparaissent donc définitivement ici.
fn drain_batch_file(action: &str) -> Vec<String> {
    let name = file_lock_mutex_name(action);
    let Ok(handle) = (unsafe { CreateMutexW(None, false, &name) }) else {
        return Vec::new();
    };
    unsafe {
        WaitForSingleObject(handle, INFINITE);
    }

    let path = batch_file_path(action);
    let now_ms = now_millis();
    let paths = std::fs::read_to_string(&path)
        .map(|content| {
            content
                .lines()
                .filter_map(|line| parse_fresh_line(line, now_ms))
                .collect()
        })
        .unwrap_or_default();
    let _ = std::fs::remove_file(&path);

    unsafe {
        let _ = ReleaseMutex(handle);
        let _ = CloseHandle(handle);
    }

    paths
}

/// Tente de devenir le leader du lot pour `action` (`"lock"`, `"unlock"`,
/// `"encrypt"` ou `"decrypt"`). Dépose systématiquement `path` dans le
/// fichier batch partagé de cette action, que l'instance devienne leader ou
/// follower.
pub fn try_become_leader(action: &str, path: &str) -> LeaderStatus {
    let name = leader_mutex_name(action);
    let result = unsafe { CreateMutexW(None, true, &name) };

    // `CreateMutexW` réussit même si le mutex existait déjà (on obtient un
    // handle vers l'objet existant) : `ERROR_ALREADY_EXISTS` est le seul
    // moyen de distinguer "je viens de le créer" (donc j'en suis
    // propriétaire, même avec `bInitialOwner=true`) de "il existait déjà"
    // (auquel cas la demande de propriété initiale est ignorée par Windows).
    let is_leader = match &result {
        Ok(_) => (unsafe { GetLastError() } != ERROR_ALREADY_EXISTS),
        Err(_) => false,
    };

    // Coordination impossible : on ne dépose rien (personne ne viendrait le
    // lire) et l'appelant traite son chemin seul.
    let Ok(handle) = result else {
        return LeaderStatus::Unavailable;
    };

    append_path_locked(action, path);

    if is_leader {
        // Laisse le temps aux autres instances, lancées quasi simultanément
        // par l'Explorateur, de déposer leur propre chemin avant de lire le
        // fichier batch.
        std::thread::sleep(COLLECT_WINDOW);
        let paths = drain_batch_file(action);
        LeaderStatus::Leader(LeaderGuard { mutex: handle, paths })
    } else {
        // Follower : ce handle ne nous appartient pas (on ne l'a pas créé),
        // on le ferme simplement sans le relâcher.
        unsafe {
            let _ = CloseHandle(handle);
        }
        LeaderStatus::Follower
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_caller_becomes_leader_and_collects_its_own_path() {
        let action = format!("test_leader_{}", std::process::id());
        match try_become_leader(&action, "C:\\a.txt") {
            LeaderStatus::Leader(guard) => {
                assert!(guard.paths.contains(&"C:\\a.txt".to_string()));
                guard.finish();
            }
            _ => panic!("la première instance doit devenir leader"),
        }
    }

    #[test]
    fn second_caller_while_leader_is_active_becomes_follower() {
        let action = format!("test_follower_{}", std::process::id());
        let guard = match try_become_leader(&action, "C:\\a.txt") {
            LeaderStatus::Leader(guard) => guard,
            _ => panic!("la première instance doit devenir leader"),
        };

        // Tant que `guard` (donc le mutex) est vivant, un second appel pour
        // la même action doit se voir refuser le leadership.
        assert!(matches!(
            try_become_leader(&action, "C:\\b.txt"),
            LeaderStatus::Follower
        ));

        guard.finish();
    }

    /// Régression B1 : un chemin déposé après le drain du leader ne doit PAS
    /// être ramassé par un lot ultérieur. En 0.6.1 il restait dans le fichier
    /// et se faisait chiffrer/verrouiller avec le mot de passe du lot suivant.
    #[test]
    fn stale_orphan_paths_are_discarded() {
        let now = now_millis();

        // Ligne fraîche : conservée.
        assert_eq!(
            parse_fresh_line(&format!("{now}|C:\\frais.txt"), now),
            Some("C:\\frais.txt".to_string())
        );

        // Ligne déposée il y a plus de ORPHAN_TTL : jetée.
        let stale = now.saturating_sub(ORPHAN_TTL.as_millis() + 1_000);
        assert_eq!(parse_fresh_line(&format!("{stale}|C:\\vieux.txt"), now), None);

        // Ligne sans horodatage (format 0.6.x) : jetée, faute de pouvoir
        // juger de sa fraîcheur.
        assert_eq!(parse_fresh_line("C:\\sans_horodatage.txt", now), None);

        // Lignes vides / malformées.
        assert_eq!(parse_fresh_line("", now), None);
        assert_eq!(parse_fresh_line(&format!("{now}|   "), now), None);
    }

    /// Le drain doit purger le fichier même quand tout est périmé, sinon les
    /// orphelins s'accumuleraient indéfiniment.
    #[test]
    fn drain_purges_the_file_even_when_everything_is_stale() {
        let action = format!("test_purge_{}", std::process::id());
        let path = batch_file_path(&action);
        let stale = now_millis().saturating_sub(ORPHAN_TTL.as_millis() + 10_000);
        std::fs::write(&path, format!("{stale}|C:\\orphelin.txt\n")).unwrap();

        let collected = drain_batch_file(&action);

        assert!(collected.is_empty(), "un orphelin périmé ne doit pas être traité");
        assert!(!path.exists(), "le fichier batch doit être purgé");
    }
}

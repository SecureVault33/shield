use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "securevault", about = "Sécurisation de fichiers Windows")]
pub struct Cli {
    /// Aucune sous-commande : ouvre le Centre d'administration (comme
    /// `dashboard`), après l'écran de bienvenue au tout premier lancement.
    #[command(subcommand)]
    pub action: Option<Action>,
}

#[derive(Subcommand, Debug)]
pub enum Action {
    /// Verrouiller un fichier/dossier (mode Accès Rapide, ACL)
    Lock {
        chemin: PathBuf,
        /// Mot de passe (usage scriptable ; sinon une popup le demandera)
        #[arg(long)]
        password: Option<String>,
    },
    /// Déverrouiller un fichier/dossier (mode Accès Rapide, ACL)
    Unlock {
        chemin: PathBuf,
        #[arg(long)]
        password: Option<String>,
    },
    /// Chiffrer un fichier (mode Chiffrement Fort)
    Encrypt {
        chemin: PathBuf,
        #[arg(long)]
        password: Option<String>,
    },
    /// Déchiffrer un fichier .vault (mode Chiffrement Fort)
    Decrypt {
        chemin: PathBuf,
        #[arg(long)]
        password: Option<String>,
    },
    /// Déverrouiller via le fichier compagnon `.securevault` (double-clic dans l'Explorateur)
    UnlockCompanion {
        chemin: PathBuf,
        #[arg(long)]
        password: Option<String>,
    },
    /// Installer le menu contextuel SecureVault dans l'Explorateur Windows
    Install,
    /// Désinstaller le menu contextuel SecureVault
    Uninstall,
    /// Ouvrir le Centre d'administration (liste des éléments protégés)
    Dashboard,
    /// Déverrouillage forcé (mode ACL uniquement, admin requis) — utilisé en
    /// interne par le dashboard lors de la relance élevée. Accepte un ou
    /// plusieurs chemins (sélection multiple dans le dashboard).
    ForceUnlock {
        #[arg(required = true, num_args = 1..)]
        chemins: Vec<PathBuf>,
    },
    /// Déverrouillage forcé de TOUS les éléments verrouillés en mode ACL —
    /// utilisé en interne par le dashboard (bouton "Tout déverrouiller")
    /// lors de la relance élevée. Vérifie le Master Password lui-même car il
    /// s'exécute dans un processus élevé séparé.
    ForceUnlockAll,
    /// Configurer manuellement le Master Password
    SetupMaster,
}

pub fn parse() -> Cli {
    Cli::parse()
}

use std::fmt;

#[derive(Debug)]
pub enum SecureVaultError {
    Io(std::io::Error),
    Crypto(String),
    Acl(String),
    Registry(String),
    /// Erreurs liées au Master Password (non configuré, déjà configuré,
    /// déchiffrement d'une recovery key impossible). Distinct de `Crypto` :
    /// ce ne sont pas des échecs cryptographiques mais des erreurs d'état,
    /// et le préfixe affiché à l'utilisateur doit le refléter.
    MasterPassword(String),
    /// Licence : compteurs de la version gratuite illisibles ou non écrits.
    License(String),
    InvalidPassword,
    InvalidFormat(String),
    /// L'utilisateur a fermé une popup sans valider. Ce n'est PAS une erreur :
    /// jusqu'à la 0.7.0 une annulation remontait comme `Crypto("saisie du mot
    /// de passe annulée")`, et `main` affichait donc une boîte « erreur
    /// cryptographique » à quelqu'un qui venait simplement de cliquer sur
    /// Annuler. Ce variant permet de sortir en silence.
    Cancelled,
}

impl fmt::Display for SecureVaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecureVaultError::Io(e) => write!(f, "erreur E/S: {e}"),
            SecureVaultError::Crypto(msg) => write!(f, "erreur cryptographique: {msg}"),
            SecureVaultError::Acl(msg) => write!(f, "erreur ACL: {msg}"),
            SecureVaultError::Registry(msg) => write!(f, "erreur registre: {msg}"),
            SecureVaultError::MasterPassword(msg) => write!(f, "Master Password: {msg}"),
            SecureVaultError::License(msg) => write!(f, "licence : {msg}"),
            SecureVaultError::InvalidPassword => write!(f, "mot de passe invalide"),
            SecureVaultError::InvalidFormat(msg) => write!(f, "format .vault invalide: {msg}"),
            SecureVaultError::Cancelled => write!(f, "opération annulée"),
        }
    }
}

impl std::error::Error for SecureVaultError {}

impl From<std::io::Error> for SecureVaultError {
    fn from(e: std::io::Error) -> Self {
        SecureVaultError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, SecureVaultError>;

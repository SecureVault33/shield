pub mod force_unlock;
pub mod master;
pub mod notifier;
pub mod registry;
pub mod settings;
pub mod window;

/// Supprime `path` et n'en revient qu'une fois la disparition CONSTATÉE.
///
/// Utilisé par les tests des trois modules qui partagent des fichiers sous
/// `%LOCALAPPDATA%` (`master`, `registry`, `settings`). Sous Windows, un
/// antivirus ou l'indexeur garde régulièrement un handle ouvert sur un fichier
/// qui vient d'être écrit : `remove_file` échoue alors silencieusement, le
/// test démarre sur l'ancien contenu et échoue de façon intermittente — pas à
/// cause du code testé, mais de cette course.
#[cfg(test)]
pub(crate) fn remove_until_gone(path: &std::path::Path) {
    for _ in 0..50 {
        if !path.exists() {
            return;
        }
        let _ = std::fs::remove_file(path);
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!(
        "impossible de supprimer {} — un autre process le verrouille",
        path.display()
    );
}

pub mod icons;

use crate::errors::{Result, SecureVaultError};
use crate::i18n::t;
use std::path::PathBuf;
use windows::core::{Interface, HSTRING, PCWSTR};
use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY,
    HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
};
use windows::Win32::UI::Shell::{
    IShellLinkW, ShellLink, SHChangeNotify, SHCNE_ASSOCCHANGED, SHCNF_IDLIST,
};

/// Racines du registre sous lesquelles le sous-menu est installé : fichiers (`*`) et dossiers.
const ROOTS: [&str; 2] = ["*", "Directory"];

/// (sous-clé, libellé affiché, action CLI, fichier icône) pour chaque entrée
/// du sous-menu cascadé. Fonction plutôt que constante : le libellé dépend
/// de la langue active (`i18n::t`), lue à l'exécution.
fn entries() -> [(&'static str, &'static str, &'static str, &'static str); 4] {
    [
        ("01_Lock", t("menu.lock"), "lock", "lock.ico"),
        ("02_Unlock", t("menu.unlock"), "unlock", "unlock.ico"),
        ("03_Encrypt", t("menu.encrypt"), "encrypt", "encrypt.ico"),
        ("04_Decrypt", t("menu.decrypt"), "decrypt", "decrypt.ico"),
    ]
}

/// ProgID enregistré pour le type de fichier compagnon `.securevault`.
const COMPANION_PROGID: &str = "SecureVault.LockedItem";

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn check_win32(status: WIN32_ERROR, context: String) -> Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(SecureVaultError::Registry(format!(
            "{context} (code Win32 {})",
            status.0
        )))
    }
}

/// Répertoire `%LOCALAPPDATA%\SecureVault\` utilisé pour stocker les icônes
/// générées. N'a pas besoin de droits administrateur.
fn app_data_dir() -> Result<PathBuf> {
    let local_app_data = std::env::var("LOCALAPPDATA")
        .map_err(|_| SecureVaultError::Registry("variable LOCALAPPDATA introuvable".into()))?;
    Ok(PathBuf::from(local_app_data).join("SecureVault"))
}

/// Chemin de l'icône de l'application, si elle a été générée.
///
/// `None` quand l'installation n'a jamais tourné : les fenêtres gardent alors
/// l'icône par défaut de Windows plutôt que d'échouer.
pub fn app_icon_path() -> Option<PathBuf> {
    let path = icons_dir().ok()?.join(icons::APP_ICON_FILE);
    path.exists().then_some(path)
}

fn icons_dir() -> Result<PathBuf> {
    Ok(app_data_dir()?.join("icons"))
}

/// Chemin du raccourci `%APPDATA%\Microsoft\Windows\Start Menu\Programs\SecureVault.lnk`
/// (menu Démarrer de l'utilisateur courant), qui permet de lancer le
/// dashboard depuis la recherche Windows.
fn start_menu_shortcut_path() -> Result<PathBuf> {
    let app_data = std::env::var("APPDATA")
        .map_err(|_| SecureVaultError::Registry("variable APPDATA introuvable".into()))?;
    Ok(PathBuf::from(app_data)
        .join("Microsoft\\Windows\\Start Menu\\Programs")
        .join("SecureVault.lnk"))
}

/// Chemin du raccourci commun `%ProgramData%\Microsoft\Windows\Start Menu\Programs\SecureVault.lnk`
/// (menu Démarrer visible par tous les utilisateurs). Écrire ici nécessite
/// généralement des droits administrateur — voir `install_common_start_menu_shortcut`,
/// qui traite l'échec comme best-effort plutôt que comme une erreur bloquante.
fn common_start_menu_shortcut_path() -> Result<PathBuf> {
    let program_data = std::env::var("ProgramData")
        .map_err(|_| SecureVaultError::Registry("variable ProgramData introuvable".into()))?;
    Ok(PathBuf::from(program_data)
        .join("Microsoft\\Windows\\Start Menu\\Programs")
        .join("SecureVault.lnk"))
}

/// Crée un raccourci `.lnk` vers `"<exe>" dashboard` au chemin donné, via les
/// API COM `IShellLinkW`/`IPersistFile`.
fn create_shortcut_at(shortcut_path: &std::path::Path, exe_str: &str) -> Result<()> {
    let exe_path = std::path::Path::new(exe_str);
    let working_dir = exe_path.parent().unwrap_or_else(|| std::path::Path::new("."));

    // `CoInitializeEx` peut légitimement échouer avec `RPC_E_CHANGED_MODE` si
    // le thread a déjà initialisé COM dans un autre mode d'appartement — dans
    // ce cas COM reste utilisable, mais on ne doit PAS appeler
    // `CoUninitialize` (on n'est pas propriétaire de cette initialisation).
    let init_hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    let owns_com = init_hr.is_ok();

    let result: Result<()> = (|| unsafe {
        let shell_link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| SecureVaultError::Registry(format!("CoCreateInstance(ShellLink) échoué: {e}")))?;

        shell_link
            .SetPath(&HSTRING::from(exe_str))
            .map_err(|e| SecureVaultError::Registry(format!("IShellLinkW::SetPath échoué: {e}")))?;
        shell_link
            .SetArguments(&HSTRING::from("dashboard"))
            .map_err(|e| SecureVaultError::Registry(format!("IShellLinkW::SetArguments échoué: {e}")))?;
        shell_link
            .SetDescription(&HSTRING::from("SecureVault — Centre d'administration"))
            .map_err(|e| SecureVaultError::Registry(format!("IShellLinkW::SetDescription échoué: {e}")))?;
        // Icône du raccourci : le `.ico` généré (bouclier dans la couleur
        // d'accent) plutôt que l'icône par défaut de l'exe — l'exe n'embarque
        // pas de ressource icône, faute de compilateur de ressources dans la
        // chaîne de build.
        let icon_source = match icons_dir() {
            Ok(dir) => {
                let candidate = dir.join(icons::APP_ICON_FILE);
                if candidate.exists() {
                    candidate.to_string_lossy().into_owned()
                } else {
                    exe_str.to_string()
                }
            }
            Err(_) => exe_str.to_string(),
        };
        shell_link
            .SetIconLocation(&HSTRING::from(icon_source.as_str()), 0)
            .map_err(|e| SecureVaultError::Registry(format!("IShellLinkW::SetIconLocation échoué: {e}")))?;
        shell_link
            .SetWorkingDirectory(&HSTRING::from(working_dir.as_os_str()))
            .map_err(|e| SecureVaultError::Registry(format!("IShellLinkW::SetWorkingDirectory échoué: {e}")))?;

        let persist_file: IPersistFile = shell_link
            .cast()
            .map_err(|e| SecureVaultError::Registry(format!("cast vers IPersistFile échoué: {e}")))?;
        persist_file
            .Save(&HSTRING::from(shortcut_path.as_os_str()), true)
            .map_err(|e| SecureVaultError::Registry(format!("IPersistFile::Save échoué: {e}")))?;

        Ok(())
    })();

    if owns_com {
        unsafe { CoUninitialize() };
    }

    result
}

/// Force le shell (Explorateur / index de recherche du menu Démarrer) à
/// invalider son cache d'associations. Sans cet appel, un raccourci `.lnk`
/// créé par programme (via `IPersistFile::Save`, plutôt que par
/// l'Explorateur lui-même) peut rester invisible dans la recherche Windows
/// pendant un certain temps — c'est l'équivalent programmatique de
/// `rundll32 shell32.dll,SHChangeNotify 0x8000000 0 0 0`.
fn notify_shell_start_menu_changed() {
    unsafe {
        SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None);
    }
}

/// Crée le raccourci du menu Démarrer de l'utilisateur courant (aucun droit
/// administrateur requis), puis tente également le raccourci commun à tous
/// les utilisateurs (best-effort : nécessite typiquement des droits
/// administrateur, une installation non élevée l'ignore silencieusement).
fn install_start_menu_shortcut(exe_str: &str) -> Result<()> {
    let shortcut_path = start_menu_shortcut_path()?;
    create_shortcut_at(&shortcut_path, exe_str)?;

    if let Ok(common_path) = common_start_menu_shortcut_path() {
        let _ = create_shortcut_at(&common_path, exe_str);
    }

    notify_shell_start_menu_changed();
    Ok(())
}

/// Supprime le(s) raccourci(s) du menu Démarrer. Idempotent : leur absence
/// n'est pas une erreur (le raccourci commun peut ne jamais avoir existé si
/// l'installation n'était pas élevée).
fn remove_start_menu_shortcut() -> Result<()> {
    let shortcut_path = start_menu_shortcut_path()?;
    match std::fs::remove_file(&shortcut_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    if let Ok(common_path) = common_start_menu_shortcut_path() {
        let _ = std::fs::remove_file(&common_path);
    }

    notify_shell_start_menu_changed();
    Ok(())
}

/// Crée (ou ouvre) une clé de registre sous `HKEY_CURRENT_USER`, avec les droits en écriture.
fn create_key(path: &str) -> Result<HKEY> {
    let wide_path = to_wide(path);
    let mut hkey = HKEY::default();
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            PCWSTR(wide_path.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
    };
    check_win32(status, format!("création de la clé '{path}'"))?;
    Ok(hkey)
}

/// Écrit une valeur chaîne (REG_SZ) nommée dans une clé ouverte. `name` vide
/// (`""`) écrit la valeur par défaut de la clé.
fn set_string_value(hkey: HKEY, name: &str, value: &str) -> Result<()> {
    let wide_name = to_wide(name);
    let name_ptr = if name.is_empty() {
        PCWSTR::null()
    } else {
        PCWSTR(wide_name.as_ptr())
    };

    let mut wide_value: Vec<u16> = value.encode_utf16().collect();
    wide_value.push(0);
    let bytes = unsafe {
        std::slice::from_raw_parts(wide_value.as_ptr() as *const u8, wide_value.len() * 2)
    };

    let status = unsafe { RegSetValueExW(hkey, name_ptr, 0, REG_SZ, Some(bytes)) };
    check_win32(status, format!("écriture de la valeur '{name}'"))
}

fn close_key(hkey: HKEY) {
    unsafe {
        let _ = RegCloseKey(hkey);
    }
}

fn delete_tree(path: &str) -> Result<()> {
    let wide_path = to_wide(path);
    let status = unsafe { RegDeleteTreeW(HKEY_CURRENT_USER, PCWSTR(wide_path.as_ptr())) };
    if status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND {
        return Err(SecureVaultError::Registry(format!(
            "suppression de la clé '{path}' échouée (code Win32 {})",
            status.0
        )));
    }
    Ok(())
}

fn install_for_root(root: &str, exe_str: &str, icons_dir: &std::path::Path) -> Result<()> {
    let base = format!("Software\\Classes\\{root}\\shell\\SecureVault");

    // Sous-menu parent : MUIVerb pour le libellé, SubCommands="" pour activer
    // le cascading vers les sous-clés `shell\*` (voir ENTRIES ci-dessous).
    let hkey_menu = create_key(&base)?;
    set_string_value(hkey_menu, "MUIVerb", t("menu.root"))?;
    set_string_value(hkey_menu, "SubCommands", "")?;
    set_string_value(hkey_menu, "Icon", exe_str)?;
    close_key(hkey_menu);

    for (subkey, display_name, action, icon_file) in entries() {
        let entry_path = format!("{base}\\shell\\{subkey}");
        let hkey_entry = create_key(&entry_path)?;
        set_string_value(hkey_entry, "", display_name)?;
        let icon_path = icons::icon_path(icons_dir, icon_file);
        let icon_str = icon_path
            .to_str()
            .ok_or_else(|| SecureVaultError::Registry("chemin d'icône non-UTF8".into()))?;
        set_string_value(hkey_entry, "Icon", icon_str)?;
        close_key(hkey_entry);

        let command_path = format!("{entry_path}\\command");
        let hkey_command = create_key(&command_path)?;
        let command_line = format!("\"{exe_str}\" {action} \"%1\"");
        set_string_value(hkey_command, "", &command_line)?;
        close_key(hkey_command);
    }

    // Centre d'administration : n'agit pas sur l'élément cliqué (pas de
    // `"%1"`), donc pas d'icône dédiée générée — réutilise celle de l'exe,
    // comme le sous-menu parent.
    let dashboard_path = format!("{base}\\shell\\05_Dashboard");
    let hkey_dashboard = create_key(&dashboard_path)?;
    set_string_value(hkey_dashboard, "", t("menu.dashboard"))?;
    set_string_value(hkey_dashboard, "Icon", exe_str)?;
    close_key(hkey_dashboard);

    let dashboard_command_path = format!("{dashboard_path}\\command");
    let hkey_dashboard_command = create_key(&dashboard_command_path)?;
    set_string_value(hkey_dashboard_command, "", &format!("\"{exe_str}\" dashboard"))?;
    close_key(hkey_dashboard_command);

    Ok(())
}

/// Enregistre le type de fichier compagnon `.securevault` (créé à côté de
/// chaque élément verrouillé) : double-cliquer dessus dans l'Explorateur
/// lance `unlock-companion <fichier>`.
fn install_companion_file_type(exe_str: &str, icons_dir: &std::path::Path) -> Result<()> {
    let ext_key = create_key("Software\\Classes\\.securevault")?;
    set_string_value(ext_key, "", COMPANION_PROGID)?;
    close_key(ext_key);

    let progid_base = format!("Software\\Classes\\{COMPANION_PROGID}");

    let progid_key = create_key(&progid_base)?;
    set_string_value(progid_key, "", "Élément verrouillé SecureVault")?;
    close_key(progid_key);

    let icon_path = icons::icon_path(icons_dir, "lock.ico");
    let icon_str = icon_path
        .to_str()
        .ok_or_else(|| SecureVaultError::Registry("chemin d'icône non-UTF8".into()))?;
    let icon_key = create_key(&format!("{progid_base}\\DefaultIcon"))?;
    set_string_value(icon_key, "", icon_str)?;
    close_key(icon_key);

    let command_key = create_key(&format!("{progid_base}\\shell\\open\\command"))?;
    set_string_value(command_key, "", &format!("\"{exe_str}\" unlock-companion \"%1\""))?;
    close_key(command_key);

    Ok(())
}

fn uninstall_companion_file_type() -> Result<()> {
    delete_tree("Software\\Classes\\.securevault")?;
    delete_tree(&format!("Software\\Classes\\{COMPANION_PROGID}"))?;
    Ok(())
}

/// Installe le sous-menu contextuel "SecureVault" (4 entrées : verrouiller,
/// déverrouiller, chiffrer, déchiffrer) dans le registre Windows, pour les
/// fichiers et les dossiers, avec icônes colorées générées localement, ainsi
/// que le type de fichier compagnon `.securevault` (double-clic = déverrouillage).
/// Utilise `HKEY_CURRENT_USER` : aucun droit administrateur requis.
pub fn install_context_menu() -> Result<()> {
    let exe = std::env::current_exe()?;
    let exe_str = exe
        .to_str()
        .ok_or_else(|| SecureVaultError::Registry("chemin de l'exécutable non-UTF8".into()))?;

    let icons_dir = icons_dir()?;
    icons::write_icons(&icons_dir)?;
    icons::write_app_icon(&icons_dir)?;

    for root in ROOTS {
        install_for_root(root, exe_str, &icons_dir)?;
    }

    install_companion_file_type(exe_str, &icons_dir)?;
    install_start_menu_shortcut(exe_str)?;

    Ok(())
}

/// Supprime le sous-menu contextuel "SecureVault" du registre Windows
/// (fichiers, dossiers, type de fichier compagnon `.securevault`) ainsi que
/// les icônes générées sous `%LOCALAPPDATA%\SecureVault\`. Idempotent :
/// l'absence d'une clé ou d'un dossier n'est pas une erreur.
pub fn uninstall_context_menu() -> Result<()> {
    for root in ROOTS {
        delete_tree(&format!("Software\\Classes\\{root}\\shell\\SecureVault"))?;
    }

    uninstall_companion_file_type()?;
    remove_start_menu_shortcut()?;

    // Best-effort : les icônes générées sont un cache jetable (régénéré au
    // prochain `install`), pas une donnée critique. Un blocage transitoire
    // du système de fichiers ici (observé en pratique : "point d'analyse
    // rencontré", probablement lié à un antivirus scannant les .ico) ne doit
    // pas faire échouer tout le reste de la désinstallation, déjà effectué
    // avec succès à ce stade (registre, type de fichier compagnon, raccourci).
    if let Ok(dir) = app_data_dir() {
        let _ = std::fs::remove_dir_all(&dir);
    }

    Ok(())
}

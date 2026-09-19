//! Centre d'administration : fenêtre Win32 (redimensionnable) listant les
//! fichiers/dossiers protégés (registre `dashboard::registry`), avec actions
//! de déverrouillage/déchiffrement/retrait et une zone de déverrouillage
//! forcé (`dashboard::force_unlock`) séparée, réservée aux cas d'urgence et
//! protégée par le Master Password (`dashboard::master`). Voir `show()`.

use crate::dashboard::{force_unlock, master, notifier, registry, settings};
use crate::errors::{Result, SecureVaultError};
use crate::i18n::t;
use crate::license::{self, LicenseStatus, Quota};
use crate::ui::{self, gfx, theme};
use std::cell::Cell;
use crate::{acl, crypto};

use std::ffi::c_void;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use zeroize::Zeroizing;

use windows::core::{w, HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{BOOL, COLORREF, HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreatePen, CreateSolidBrush, DeleteObject, DrawTextW, EndPaint,
    FillRect, GetMonitorInfoW, GetStockObject, InvalidateRect, LineTo, MonitorFromWindow, MoveToEx,
    GetTextExtentPoint32W, Rectangle, ScreenToClient, SelectObject, SetBkColor, SetBkMode, SetTextColor, DT_LEFT,
    DT_SINGLELINE, DT_VCENTER, FW_BOLD, FW_NORMAL, HBRUSH, HDC, HFONT, MONITORINFO,
    MONITOR_DEFAULTTONEAREST, NULL_BRUSH, PAINTSTRUCT, PS_SOLID, TRANSPARENT,
};
use windows::Win32::System::Com::{
    CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_APARTMENTTHREADED,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{
    InitCommonControlsEx, SetWindowTheme, DRAWITEMSTRUCT, HDITEMW, HDI_TEXT, HDM_GETITEMCOUNT,
    HDM_GETITEMRECT, HDM_GETITEMW, ICC_LISTVIEW_CLASSES, ICC_UPDOWN_CLASS, INITCOMMONCONTROLSEX,
    LVCF_TEXT, LVCF_WIDTH, LVCOLUMNW, LVIF_TEXT, LVITEMW, LVNI_SELECTED, LVN_ITEMCHANGED,
    LVS_EX_FULLROWSELECT, LVS_REPORT, NMHDR, NMLVCUSTOMDRAW, NM_CUSTOMDRAW, NM_DBLCLK,
    LVHITTESTINFO, LVIS_SELECTED, LVM_GETITEMSTATE, LVM_HITTEST, TTF_IDISHWND, TTF_SUBCLASS, TTM_ADDTOOLW, TTM_UPDATETIPTEXTW, TTS_ALWAYSTIP,
    TTTOOLINFOW, TOOLTIPS_CLASSW, UDM_GETPOS32, UDM_SETBUDDY, UDM_SETPOS32, UDM_SETRANGE32,
    UDS_ALIGNRIGHT, UDS_ARROWKEYS, UDS_SETBUDDYINT, UPDOWN_CLASS, WC_LISTVIEWW,
};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{WaitForSingleObject, INFINITE};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    EnableWindow, IsWindowEnabled, SetFocus, TrackMouseEvent, TME_LEAVE, TRACKMOUSEEVENT,
};
use windows::Win32::UI::Shell::Common::ITEMIDLIST;
use windows::Win32::UI::Shell::{
    IsUserAnAdmin, SHBrowseForFolderW, SHGetPathFromIDListW, ShellExecuteExW, ShellExecuteW,
    BIF_NEWDIALOGSTYLE, BIF_RETURNONLYFSDIRS, BROWSEINFOW, SEE_MASK_NOCLOSEPROCESS,
    SHELLEXECUTEINFOW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect,
    GetMessageW, GetSystemMetrics, GetWindowLongPtrW, KillTimer, LoadCursorW, MoveWindow,
    GetDlgCtrlID, GetParent, IsZoomed, PostMessageW, PostQuitMessage, RegisterClassW, SendMessageW,
    SetCursor, SetTimer, SetWindowLongPtrW, ShowWindow,
    TranslateMessage, BM_GETCHECK, BM_SETCHECK, BN_CLICKED, BS_AUTOCHECKBOX, BS_AUTORADIOBUTTON,
    BS_OWNERDRAW, CS_HREDRAW,
    CS_VREDRAW, ES_AUTOHSCROLL, GWLP_USERDATA, GWLP_WNDPROC, HMENU, HTCAPTION, HTCLIENT,
    IDC_ARROW, IDC_HAND, IDC_WAIT, MSG, SM_CXSCREEN, SM_CYSCREEN, SW_HIDE, SW_MAXIMIZE, SW_MINIMIZE,
    SW_RESTORE, SW_SHOW, SW_SHOWNORMAL, WM_CLOSE, WM_COMMAND, WM_CTLCOLORBTN, WM_CTLCOLOREDIT,
    WM_CTLCOLORSTATIC, WM_DESTROY, WM_DRAWITEM, WM_ERASEBKGND, WM_GETMINMAXINFO, WM_NOTIFY,
    WM_APP, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE, WM_NCHITTEST, WM_PAINT, WM_SETCURSOR, WM_SETFONT,
    WM_SIZE, WM_TIMER, WNDCLASSW, WS_CHILD, WS_CLIPCHILDREN, WS_GROUP,
    WS_EX_APPWINDOW, WS_MAXIMIZEBOX, WS_MINIMIZEBOX, WS_POPUP, WS_SYSMENU, WS_TABSTOP,
    WS_THICKFRAME, WS_VISIBLE, WINDOW_EX_STYLE, WINDOW_STYLE,
};
use windows::Win32::UI::Controls::{BST_CHECKED, BST_UNCHECKED};

const CLASS_NAME: PCWSTR = w!("SecureVaultDashboardClass");
const APP_TITLE: &str = "🔒 SecureVault";

const CARD_BG: u32 = 0x002d2d2d; // #2d2d2d
const CARD_BORDER: u32 = 0x00333333; // #333333
const HEADER_BG: u32 = 0x001a1a1a; // #1a1a1a
const HEADER_TEXT: u32 = 0x00888888; // #888888

const WINDOW_WIDTH: i32 = 800;
const WINDOW_HEIGHT: i32 = 688;
const MIN_WIDTH: i32 = 650;
const MIN_HEIGHT: i32 = 558;
const MARGIN: i32 = 20;
const CARD_H: i32 = 70;
const CARD_GAP: i32 = 20;
const ROW1_H: i32 = 40;
const ROW2_H: i32 = 40;
/// Hauteur de la barre d'onglets, en haut de la fenêtre — tout le contenu de
/// l'onglet "Fichiers protégés" (cartes, liste, boutons...) est décalé vers
/// le bas de cette hauteur par rapport aux versions antérieures à 0.5.0.
const TAB_BAR_H: i32 = 40;

/// Bandeau de titre dessiné par l'application (0.8.0). La fenêtre n'a plus de
/// `WS_CAPTION` : voir `window_style()` et le traitement de `WM_NCHITTEST`.
const HEADER_H: i32 = 50;
/// Épaisseur de la ligne indiquant l'onglet actif.
const TAB_INDICATOR_H: i32 = 3;
/// Largeur d'un bouton de fenêtre (─ □ ✕) dans le bandeau.
const WINDOW_BTN_W: i32 = 46;

/// Rayon des coins des boutons d'action.
const BTN_RADIUS: i32 = 6;
/// Écart horizontal entre boutons d'une même rangée.
const BTN_GAP: i32 = 8;

/// Cadence commune des animations (~60 fps).
const ANIM_INTERVAL_MS: u32 = 16;
/// Compteurs des cartes : ~400 ms à 16 ms/frame.
const TIMER_COUNTERS: usize = 2;
const COUNTER_STEP: f32 = 16.0 / 400.0;
/// Glissement de l'indicateur d'onglet : ~200 ms.
const TIMER_TAB_INDICATOR: usize = 3;
const TAB_INDICATOR_STEP: f32 = 16.0 / 200.0;
/// Survol des cartes statistiques : ~120 ms.
const TIMER_CARD_HOVER: usize = 4;
const CARD_HOVER_STEP: f32 = 16.0 / 120.0;

/// `WM_MOUSELEAVE` — absent des bindings générés, valeur stable de `winuser.h`
/// (même constante que dans `ui::mod`).
const WM_MOUSELEAVE: u32 = 0x02A3;

/// Variante visuelle d'un bouton d'action.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ButtonKind {
    /// Fond accent plein — action principale du panneau.
    Primary,
    /// Fond transparent, contour discret — action de gestion.
    Secondary,
    /// Fond orange — action destructrice ou nécessitant l'élévation.
    Danger,
}

fn button_kind(id: i32) -> ButtonKind {
    match id {
        ID_BTN_UNLOCK | ID_BTN_DECRYPT | ID_BTN_LOCK | ID_BTN_ENCRYPT => ButtonKind::Primary,
        ID_BTN_FORCE_ONE | ID_BTN_FORCE_ALL => ButtonKind::Danger,
        _ => ButtonKind::Secondary,
    }
}

/// Style de la fenêtre principale : `WS_POPUP` (donc pas de barre de titre
/// système, on dessine la nôtre) MAIS `WS_THICKFRAME` pour conserver le
/// redimensionnement, l'accrochage aux bords et le double-clic d'agrandissement
/// — c'est `DefWindowProc` qui fournit tout ça via `WM_NCHITTEST`, à condition
/// de lui laisser le dernier mot en dehors du bandeau.
fn window_style() -> WINDOW_STYLE {
    WS_POPUP | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU | WS_CLIPCHILDREN
}

const ID_BTN_UNLOCK: i32 = 300;
const ID_BTN_DECRYPT: i32 = 301;
const ID_BTN_REMOVE: i32 = 302;
const ID_BTN_FORCE_ONE: i32 = 303;
const ID_BTN_FORCE_ALL: i32 = 304;
const ID_BTN_EXPORT: i32 = 305;
const ID_BTN_REFRESH: i32 = 306;
const ID_BTN_LOCK: i32 = 307;
const ID_BTN_ENCRYPT: i32 = 308;

const ID_TAB_FILES: i32 = 400;
const ID_TAB_SETTINGS: i32 = 401;
const ID_TAB_ABOUT: i32 = 402;

const ID_CHK_REMINDER_ENABLED: i32 = 410;
const ID_EDIT_REMINDER_HOURS: i32 = 412;
const ID_RADIO_THEME_RED: i32 = 415;
const ID_RADIO_THEME_BLUE: i32 = 416;
const ID_RADIO_THEME_GREEN: i32 = 417;
const ID_EDIT_EXPORT_PATH: i32 = 419;
const ID_BTN_BROWSE_EXPORT_PATH: i32 = 420;
const ID_BTN_SAVE_SETTINGS: i32 = 421;
const ID_BTN_CHANGE_MASTER: i32 = 422;

/// Boutons de la barre de titre custom (0.8.0).
const ID_BTN_MINIMIZE: i32 = 320;
const ID_BTN_MAXIMIZE: i32 = 321;
const ID_BTN_CLOSE: i32 = 322;

const ID_BTN_OPEN_DOCS: i32 = 430;
const ID_BTN_OPEN_INSTALL_DIR: i32 = 431;
const ID_BTN_OPEN_LOCAL_DATA: i32 = 432;
/// « Entrer une clé de licence » (onglet À propos).
const ID_BTN_LICENSE_KEY: i32 = 433;

/// Barre de statut de licence, en bas de l'onglet Fichiers.
const STATUS_H: i32 = 28;

/// Timer Windows du rappel de sécurité, déclenché toutes les 15 minutes tant
/// que le dashboard est ouvert — voir `notifier::check_and_notify`.
const TIMER_SECURITY_CHECK: usize = 1;
const SECURITY_CHECK_INTERVAL_MS: u32 = 900_000;

/// Message privé déclenchant la relance du dashboard après un changement de
/// langue/thème.
///
/// Pourquoi ne pas appeler `DestroyWindow` directement depuis le handler du
/// bouton « Sauvegarder » : `DestroyWindow` envoie `WM_DESTROY` de façon
/// SYNCHRONE, et c'est `WM_DESTROY` qui libère le `Box<DashboardState>`. Le
/// `&mut DashboardState` du `WM_COMMAND` en cours pointerait alors sur de la
/// mémoire libérée jusqu'à la fin de son scope. `PostMessageW` diffère la
/// destruction au tour de boucle suivant, quand plus aucune référence à
/// l'état n'est vivante.
const WM_APP_RELAUNCH: u32 = WM_APP + 1;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Files,
    Settings,
    About,
}

struct DashboardState {
    hwnd_listview: HWND,
    /// Rectangles des trois cartes, recalculés par `layout` et relus par le
    /// `WM_PAINT` du parent (les cartes ne sont plus des contrôles).
    card_rects: [RECT; 3],
    /// Rectangle de l'encadré « Déverrouillage forcé ».
    force_zone_rect: RECT,
    hwnd_btn_unlock: HWND,
    hwnd_btn_decrypt: HWND,
    hwnd_btn_remove: HWND,
    hwnd_btn_force_one: HWND,
    hwnd_btn_force_all: HWND,
    hwnd_btn_export: HWND,
    hwnd_btn_refresh: HWND,
    hwnd_btn_lock: HWND,
    hwnd_btn_encrypt: HWND,
    hwnd_btn_minimize: HWND,
    hwnd_btn_maximize: HWND,
    hwnd_btn_close: HWND,

    hwnd_tab_files: HWND,
    hwnd_tab_settings: HWND,
    hwnd_tab_about: HWND,
    current_tab: Tab,
    files_tab_controls: Vec<HWND>,
    settings_tab_controls: Vec<HWND>,
    about_tab_controls: Vec<HWND>,

    // Contrôles de l'onglet Paramètres dont la valeur est relue au clic sur
    // "Sauvegarder".
    hwnd_chk_reminder_enabled: HWND,
    hwnd_updown_reminder_hours: HWND,
    hwnd_radio_theme_blue: HWND,
    hwnd_radio_theme_green: HWND,
    hwnd_edit_export_path: HWND,

    font: HFONT,
    font_bold: HFONT,
    font_small: HFONT,
    font_header: HFONT,
    brush_background: HBRUSH,
    brush_card_bg: HBRUSH,
    brush_card_border: HBRUSH,
    entries: Vec<registry::VaultEntry>,

    // --- Animations (0.8.0) ---------------------------------------------
    /// Compteurs des cartes : valeurs cibles, progression 0..1, et valeurs
    /// affichées pendant le décompte.
    card_targets: [i32; 3],
    card_progress: f32,
    /// Survol des cartes (0 = repos, 1 = survolée), une entrée par carte.
    card_hover: [f32; 3],
    card_hover_target: [f32; 3],
    /// Indicateur d'onglet : position/largeur affichées et cibles, en pixels.
    tab_indicator_x: f32,
    tab_indicator_w: f32,
    tab_indicator_from_x: f32,
    tab_indicator_from_w: f32,
    tab_indicator_progress: f32,
    /// Onglet survolé, pour éclaircir son libellé.
    hovered_tab: Option<Tab>,
    /// Ligne de la ListView sous le curseur (index), pour l'éclaircir.
    hovered_row: i32,
    /// Bouton d'action survolé / enfoncé (identifiant de contrôle).
    hovered_button: Option<i32>,
    pressed_button: Option<i32>,
    /// Infobulle unique, réutilisée pour tous les boutons.
    tooltip: HWND,

    // --- Licence (1.0.0) --------------------------------------------------
    /// Photographie de la licence, relue après chaque action (voir
    /// `apply_license_status`). La barre de statut est repeinte à chaque
    /// frame d'animation : elle lit ce cache, jamais les fichiers.
    license: LicenseStatus,
    /// Zone cliquable « Passer à Pro → », mesurée au moment où la barre est
    /// peinte (sa position dépend de la largeur du texte qui précède). `Cell`
    /// car `WM_PAINT` n'a qu'un accès en lecture à l'état.
    status_link_rect: Cell<RECT>,
    /// « (Pro) » à côté du rappel de sécurité, vide en version Pro.
    hwnd_reminder_pro_badge: HWND,
    /// Onglet À propos : texte de licence et bouton d'achat.
    hwnd_about_license: HWND,
    hwnd_btn_license_key: HWND,
}

/// Texte de la barre de statut et présence du lien « Passer à Pro ».
/// Fonction pure, testée. (Version gratuite : le lien est toujours proposé.)
fn status_bar_text(status: &LicenseStatus) -> (String, bool) {
    let counter = |key: &'static str, used: u32, max: u32| {
        t(key)
            .replace("{used}", &used.min(max).to_string())
            .replace("{max}", &max.to_string())
    };
    (
        format!(
            "{}  |  {}  |  {}  |  ",
            t("license.status_free"),
            counter("license.locks_counter", status.usage.locks_used, license::FREE_LOCK_LIMIT),
            counter("license.encrypts_counter", status.usage.encrypts_used, license::FREE_ENCRYPT_LIMIT),
        ),
        !status.pro,
    )
}

/// Texte de la section Licence de l'onglet À propos. Fonction pure, testée.
fn about_license_text(status: &LicenseStatus) -> String {
    t("license.about_free")
        .replace("{locks_used}", &status.usage.locks_used.min(license::FREE_LOCK_LIMIT).to_string())
        .replace("{locks_max}", &license::FREE_LOCK_LIMIT.to_string())
        .replace("{encrypts_used}", &status.usage.encrypts_used.min(license::FREE_ENCRYPT_LIMIT).to_string())
        .replace("{encrypts_max}", &license::FREE_ENCRYPT_LIMIT.to_string())
}

/// Quota concerné par un bouton de re-protection, s'il y en a un.
fn button_quota(id: i32) -> Option<Quota> {
    match id {
        ID_BTN_LOCK => Some(Quota::Lock),
        ID_BTN_ENCRYPT => Some(Quota::Encrypt),
        _ => None,
    }
}

/// Valeur affichée par une carte pendant l'animation de décompte.
fn animated_count(target: i32, progress: f32) -> i32 {
    (target as f32 * gfx::ease_out_cubic(progress)).round() as i32
}

/// Curseur sablier pendant une opération longue, restauré à la destruction.
///
/// Le chiffrement d'un gros dossier ou un déverrouillage forcé multiple
/// bloquent la boucle de messages plusieurs secondes : sans retour visuel,
/// l'utilisateur croit l'application figée et reclique.
struct WaitCursor {
    previous: windows::Win32::UI::WindowsAndMessaging::HCURSOR,
}

impl WaitCursor {
    unsafe fn new() -> Self {
        let wait = LoadCursorW(None, IDC_WAIT).unwrap_or_default();
        WaitCursor { previous: SetCursor(wait) }
    }
}

impl Drop for WaitCursor {
    fn drop(&mut self) {
        // Restauré par `Drop` : les chemins d'erreur sont nombreux
        // (`?`, `return` anticipé), les oublier laisserait un sablier
        // permanent.
        unsafe {
            SetCursor(self.previous);
        }
    }
}

fn to_wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Décrit un contrôle enfant simple (statique/bouton), même technique que
/// `ui::mod::ChildSpec` (module distinct, pas de dépendance croisée).
struct ChildSpec<'a> {
    class: PCWSTR,
    text: &'a str,
    style: WINDOW_STYLE,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: i32,
}

unsafe fn create_child(parent: HWND, hinstance: HINSTANCE, spec: ChildSpec<'_>) -> Result<HWND> {
    let text = HSTRING::from(spec.text);
    CreateWindowExW(
        WINDOW_EX_STYLE(0),
        spec.class,
        &text,
        WS_CHILD | WS_VISIBLE | spec.style,
        spec.x,
        spec.y,
        spec.w,
        spec.h,
        parent,
        HMENU(spec.id as isize as *mut c_void),
        hinstance,
        None,
    )
    .map_err(|e| SecureVaultError::Crypto(format!("création de contrôle Win32 échouée: {e}")))
}


fn draw_centered_text(hdc: HDC, rect: RECT, text: &str, color: u32, font: HFONT) {
    use windows::Win32::Graphics::Gdi::{DrawTextW, SelectObject, DT_CENTER, DT_SINGLELINE, DT_VCENTER};
    unsafe {
        let old_font = SelectObject(hdc, font);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, COLORREF(color));
        let mut wide: Vec<u16> = text.encode_utf16().collect();
        let mut rc = rect;
        DrawTextW(hdc, &mut wide, &mut rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        SelectObject(hdc, old_font);
    }
}

/// Dessine un bouton owner-draw : fond plein (rouge pour les actions
/// standard, orange pour la zone de déverrouillage forcé) ou grisé quand le
/// bouton est désactivé (rien de sélectionné / action non applicable).
unsafe fn draw_button(item: &DRAWITEMSTRUCT, state: &DashboardState, orange: bool) {
    let rc = item.rcItem;
    let enabled = IsWindowEnabled(item.hwndItem).as_bool();
    let label = match item.CtlID as i32 {
        ID_BTN_UNLOCK => t("dashboard.btn.unlock"),
        ID_BTN_DECRYPT => t("dashboard.btn.decrypt"),
        ID_BTN_REMOVE => t("dashboard.btn.remove"),
        ID_BTN_FORCE_ONE => t("dashboard.btn.force"),
        ID_BTN_FORCE_ALL => t("dashboard.btn.force_all"),
        ID_BTN_EXPORT => t("dashboard.btn.export"),
        ID_BTN_REFRESH => t("dashboard.btn.refresh"),
        ID_BTN_LOCK => t("dashboard.btn.lock"),
        ID_BTN_ENCRYPT => t("dashboard.btn.encrypt"),
        _ => "",
    };

    let id = item.CtlID as i32;
    // Quota gratuit épuisé : dessiné comme désactivé, suffixé « (Pro) », mais
    // RESTE cliquable. Un bouton réellement désactivé ne reçoit aucun
    // événement souris — ni infobulle « Limite atteinte », ni proposition de
    // passer à Pro au clic (voir `on_reprotect`).
    let quota_blocked = button_quota(id).is_some_and(|q| !state.license.allows(q, 1));
    let blocked_label;
    let label = if quota_blocked {
        blocked_label = format!("{label} {}", t("license.pro_only"));
        blocked_label.as_str()
    } else {
        label
    };
    let kind = if orange { ButtonKind::Danger } else { button_kind(id) };
    let hovered = state.hovered_button == Some(id);
    let pressed = state.pressed_button == Some(id);

    // Le fond du bouton doit se fondre dans le dégradé de la fenêtre : on
    // échantillonne la teinte à sa hauteur plutôt que de supposer une couleur
    // fixe (le bouton a des coins arrondis, les angles laissent voir le fond).
    let mut client = RECT::default();
    let _ = GetClientRect(GetParent(item.hwndItem).unwrap_or_default(), &mut client);
    let t = (rc.top + rc.bottom) as f32 / 2.0 / (client.bottom - client.top).max(1) as f32;
    let window_bg = gfx::lerp_color(theme::COLOR_BACKGROUND, theme::COLOR_BACKGROUND_BOTTOM, t);
    gfx::fill_rect(item.hDC, rc, window_bg);

    if !enabled || quota_blocked {
        // Désactivé : couleur mélangée au fond plutôt qu'une teinte grise
        // arbitraire — le bouton s'efface sans disparaître.
        let base = match kind {
            ButtonKind::Primary => theme::accent_end(),
            ButtonKind::Danger => theme::COLOR_DANGER,
            ButtonKind::Secondary => theme::COLOR_BTN_SECONDARY_BORDER,
        };
        let faded = gfx::over(base, window_bg, 0.25);
        if kind == ButtonKind::Secondary {
            gfx::stroke_round_rect(item.hDC, rc, faded, BTN_RADIUS, 1);
        } else {
            gfx::fill_round_rect(item.hDC, rc, faded, BTN_RADIUS);
        }
        draw_centered_text(
            item.hDC,
            rc,
            label,
            gfx::over(theme::COLOR_TEXT, window_bg, 0.35),
            state.font,
        );
        return;
    }

    // `lighten` de 15 % au survol, 8 % de plus en appui.
    let boost = if pressed {
        -0.08
    } else if hovered {
        0.15
    } else {
        0.0
    };
    let shade = |c: u32| -> u32 {
        if boost >= 0.0 {
            gfx::lighten(c, boost)
        } else {
            gfx::darken(c, -boost)
        }
    };

    match kind {
        ButtonKind::Primary => {
            gfx::fill_round_rect_gradient(
                item.hDC,
                rc,
                shade(theme::accent_start()),
                shade(theme::accent_end()),
                BTN_RADIUS,
                true,
            );
            draw_button_label(item.hDC, rc, label, theme::COLOR_WHITE, state.font, pressed);
        }
        ButtonKind::Danger => {
            gfx::fill_round_rect(item.hDC, rc, shade(theme::COLOR_DANGER), BTN_RADIUS);
            draw_button_label(item.hDC, rc, label, theme::COLOR_WHITE, state.font, pressed);
        }
        ButtonKind::Secondary => {
            if hovered || pressed {
                // Voile très léger : un bouton secondaire ne doit pas devenir
                // aussi présent qu'un bouton primaire au survol.
                gfx::fill_round_rect(
                    item.hDC,
                    rc,
                    gfx::over(theme::COLOR_WHITE, window_bg, 0.07),
                    BTN_RADIUS,
                );
            }
            gfx::stroke_round_rect(
                item.hDC,
                rc,
                shade(theme::COLOR_BTN_SECONDARY_BORDER),
                BTN_RADIUS,
                1,
            );
            let text = if hovered {
                theme::COLOR_TEXT
            } else {
                theme::COLOR_BTN_SECONDARY_TEXT
            };
            draw_button_label(item.hDC, rc, label, text, state.font, pressed);
        }
    }
}

/// Libellé d'un bouton, décalé d'1 px vers le bas à l'appui (même effet que
/// dans la popup mot de passe).
unsafe fn draw_button_label(
    hdc: HDC,
    rc: RECT,
    label: &str,
    color: u32,
    font: HFONT,
    pressed: bool,
) {
    let mut text_rc = rc;
    if pressed {
        text_rc.top += 1;
        text_rc.bottom += 1;
    }
    draw_centered_text(hdc, text_rc, label, color, font);
}

/// Dessine un onglet : fond `#c0392b` (accent rouge) si actif, `#2d2d2d`
/// sinon — pas de coins arrondis ni de dégradé, contrairement aux boutons
/// d'action (une barre d'onglets reste plate par convention).
/// Bandeau de titre dessiné par l'application : dégradé horizontal dans la
/// couleur d'accent, bouclier + nom du produit à gauche. Les trois boutons de
/// fenêtre à droite sont des contrôles enfants owner-draw (voir
/// `draw_window_button`).
/// Crée la fenêtre d'infobulles, unique et partagée par tous les boutons.
///
/// `TTF_SUBCLASS` fait intercepter les messages souris par l'infobulle
/// elle-même : sans lui il faudrait relayer manuellement chaque `WM_MOUSEMOVE`
/// via `TTM_RELAYEVENT`.
unsafe fn create_tooltip(parent: HWND, hinstance: HINSTANCE) -> HWND {
    CreateWindowExW(
        WINDOW_EX_STYLE(0),
        TOOLTIPS_CLASSW,
        PCWSTR::null(),
        WINDOW_STYLE(TTS_ALWAYSTIP),
        0,
        0,
        0,
        0,
        parent,
        None,
        hinstance,
        None,
    )
    .unwrap_or_default()
}

/// Associe une infobulle à un bouton.
///
/// Le texte doit rester vivant pendant tout l'appel : `TTM_ADDTOOLW` copie la
/// chaîne, mais le pointeur passé doit être valide à cet instant — d'où le
/// `Vec` local conservé jusqu'au `SendMessageW`.
unsafe fn add_tooltip(tooltip: HWND, parent: HWND, control: HWND, text: &str) {
    if tooltip.is_invalid() {
        return;
    }
    let mut wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let info = TTTOOLINFOW {
        cbSize: size_of::<TTTOOLINFOW>() as u32,
        uFlags: TTF_IDISHWND | TTF_SUBCLASS,
        hwnd: parent,
        uId: control.0 as usize,
        lpszText: PWSTR(wide.as_mut_ptr()),
        ..Default::default()
    };
    SendMessageW(
        tooltip,
        TTM_ADDTOOLW,
        WPARAM(0),
        LPARAM(&info as *const TTTOOLINFOW as isize),
    );
}

/// Fait avancer une progression vers sa cible ; `false` si elle y était déjà.
fn step_towards(current: &mut f32, target: f32, step: f32) -> bool {
    if (*current - target).abs() < f32::EPSILON {
        return false;
    }
    if *current < target {
        *current = (*current + step).min(target);
    } else {
        *current = (*current - step).max(target);
    }
    true
}

/// Repeint uniquement la bande des cartes — invalider toute la fenêtre à
/// 60 fps repeindrait aussi la ListView et ses dizaines de lignes.
unsafe fn invalidate_cards(hwnd: HWND, state: &DashboardState) {
    let mut zone = state.card_rects[0];
    for rc in &state.card_rects[1..] {
        zone.right = zone.right.max(rc.right);
        zone.bottom = zone.bottom.max(rc.bottom);
    }
    // `BOOL(0)` : pas d'effacement, `WM_PAINT` repeint déjà le fond.
    let _ = InvalidateRect(hwnd, Some(&zone), BOOL(0));
}

unsafe fn draw_header(hdc: HDC, client_w: i32, state: &DashboardState) {
    let rc = RECT { left: 0, top: 0, right: client_w, bottom: HEADER_H };
    gfx::fill_gradient_h(hdc, rc, theme::accent_start(), theme::accent_end());

    const PADDING: i32 = 16;
    const ICON: i32 = 26;
    let icon_rc = RECT {
        left: PADDING,
        top: (HEADER_H - ICON) / 2,
        right: PADDING + ICON,
        bottom: (HEADER_H - ICON) / 2 + ICON,
    };
    // Fond échantillonné au centre de l'icône : le dégradé est horizontal, la
    // teinte sous une icône de 26 px est donc quasi constante.
    let t = (icon_rc.left + ICON / 2) as f32 / client_w.max(1) as f32;
    let background = gfx::lerp_color(theme::accent_start(), theme::accent_end(), t);
    gfx::draw_icon(hdc, icon_rc, gfx::Icon::Shield, theme::COLOR_WHITE, background);

    let text_rc = RECT {
        left: PADDING + ICON + 10,
        top: 0,
        right: client_w - WINDOW_BTN_W * 3,
        bottom: HEADER_H,
    };
    gfx::draw_text_in(
        hdc,
        text_rc,
        "SecureVault",
        theme::COLOR_WHITE,
        state.font_header,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );
}

/// Boutons ─ □ ✕ du bandeau : glyphes dessinés au trait plutôt qu'en texte
/// (les caractères Unicode correspondants rendent mal selon la police).
unsafe fn draw_window_button(item: &DRAWITEMSTRUCT, state: &DashboardState) {
    let rc = item.rcItem;
    let id = item.CtlID as i32;
    let hovered = state.hovered_button == Some(id);

    // Fond : dégradé du bandeau au repos, voile clair au survol (rouge pour
    // la fermeture, convention universelle).
    let mut client = RECT::default();
    let _ = GetClientRect(GetParent(item.hwndItem).unwrap_or_default(), &mut client);
    let client_w = (client.right - client.left).max(1);
    let t0 = rc.left as f32 / client_w as f32;
    let t1 = rc.right as f32 / client_w as f32;
    let from = gfx::lerp_color(theme::accent_start(), theme::accent_end(), t0);
    let to = gfx::lerp_color(theme::accent_start(), theme::accent_end(), t1);
    gfx::fill_gradient_h(item.hDC, rc, from, to);

    if hovered {
        let veil = if id == ID_BTN_CLOSE {
            0x003030d0
        } else {
            theme::COLOR_WHITE
        };
        let blended = gfx::over(veil, gfx::lerp_color(from, to, 0.5), 0.28);
        gfx::fill_rect(item.hDC, rc, blended);
    }

    let cx = (rc.left + rc.right) / 2;
    let cy = (rc.top + rc.bottom) / 2;
    let pen = CreatePen(PS_SOLID, 1, COLORREF(theme::COLOR_WHITE));
    let old_pen = SelectObject(item.hDC, pen);
    match id {
        ID_BTN_MINIMIZE => {
            let _ = MoveToEx(item.hDC, cx - 5, cy, None);
            let _ = LineTo(item.hDC, cx + 6, cy);
        }
        ID_BTN_MAXIMIZE => {
            let old_brush = SelectObject(item.hDC, GetStockObject(NULL_BRUSH));
            let _ = Rectangle(item.hDC, cx - 5, cy - 5, cx + 6, cy + 6);
            SelectObject(item.hDC, old_brush);
        }
        ID_BTN_CLOSE => {
            let _ = MoveToEx(item.hDC, cx - 5, cy - 5, None);
            let _ = LineTo(item.hDC, cx + 6, cy + 6);
            let _ = MoveToEx(item.hDC, cx + 5, cy - 5, None);
            let _ = LineTo(item.hDC, cx - 6, cy + 6);
        }
        _ => {}
    }
    SelectObject(item.hDC, old_pen);
    let _ = DeleteObject(pen);
}

unsafe fn draw_tab_button(item: &DRAWITEMSTRUCT, state: &DashboardState) {
    let rc = item.rcItem;
    let (tab, label) = match item.CtlID as i32 {
        ID_TAB_FILES => (Tab::Files, t("dashboard.tab.files")),
        ID_TAB_SETTINGS => (Tab::Settings, t("dashboard.tab.settings")),
        ID_TAB_ABOUT => (Tab::About, t("dashboard.tab.about")),
        _ => return,
    };
    let active = state.current_tab == tab;

    // Plus de fond plein coloré : un onglet actif se signale par son libellé
    // blanc et par la ligne indicatrice qui glisse sous lui (peinte par la
    // fenêtre parente, voir `draw_tab_indicator`).
    gfx::fill_rect(item.hDC, rc, theme::COLOR_BACKGROUND);

    let text_color = if active {
        theme::COLOR_WHITE
    } else if state.hovered_tab == Some(tab) {
        theme::COLOR_TEXT_HOVER
    } else {
        theme::COLOR_TEXT_MUTED
    };
    draw_centered_text(item.hDC, rc, label, text_color, state.font);
}

/// Ligne de 3 px sous l'onglet actif. Peinte par la fenêtre parente et non par
/// le bouton lui-même : pendant le glissement elle chevauche deux onglets, et
/// un contrôle enfant ne peut pas déborder de son rectangle.
/// Peint une carte statistique complète (cadre arrondi + valeur + libellé).
///
/// Les cartes étaient trois STATIC empilés (cadre, intérieur, nombre,
/// libellé) colorés par `WM_CTLCOLORSTATIC`. Pour le survol animé il fallait
/// une couleur par frame : on les peint désormais d'un bloc, depuis le
/// parent, ce qui supprime aussi trois contrôles par carte.
unsafe fn draw_card(hdc: HDC, rc: RECT, value: i32, label: &str, hover: f32, state: &DashboardState) {
    let bg = gfx::lerp_color(
        theme::COLOR_CARD_BG,
        theme::COLOR_CARD_HOVER,
        gfx::ease_out_cubic(hover),
    );
    gfx::fill_round_rect(hdc, rc, bg, 8);
    gfx::stroke_round_rect(hdc, rc, theme::COLOR_CARD_BORDER, 8, 1);

    let number_rc = RECT {
        left: rc.left + 8,
        top: rc.top + 6,
        right: rc.right - 8,
        bottom: rc.top + 40,
    };
    gfx::draw_text_in(
        hdc,
        number_rc,
        &value.to_string(),
        theme::COLOR_WHITE,
        state.font_bold,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );

    let label_rc = RECT {
        left: rc.left + 8,
        top: rc.top + 42,
        right: rc.right - 8,
        bottom: rc.bottom - 6,
    };
    gfx::draw_text_in(
        hdc,
        label_rc,
        label,
        theme::COLOR_TEXT_MUTED,
        state.font_small,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );
}

/// Encadré de la zone de déverrouillage forcé : fond très sombre légèrement
/// chaud, bordure orange arrondie, triangle d'alerte dessiné en GDI.
unsafe fn draw_force_zone(hdc: HDC, rc: RECT, state: &DashboardState) {
    gfx::fill_round_rect(hdc, rc, theme::COLOR_DANGER_ZONE_BG, 8);
    gfx::stroke_round_rect(hdc, rc, theme::COLOR_DANGER, 8, 1);

    const PADDING: i32 = 12;
    const ICON: i32 = 16;
    let icon_rc = RECT {
        left: rc.left + PADDING,
        top: rc.top + PADDING,
        right: rc.left + PADDING + ICON,
        bottom: rc.top + PADDING + ICON,
    };
    gfx::draw_icon(
        hdc,
        icon_rc,
        gfx::Icon::Warning,
        theme::COLOR_DANGER,
        theme::COLOR_DANGER_ZONE_BG,
    );

    let text_rc = RECT {
        left: icon_rc.right + 8,
        top: rc.top + PADDING,
        right: rc.right - PADDING,
        bottom: rc.top + PADDING + ICON,
    };
    gfx::draw_text_in(
        hdc,
        text_rc,
        t("dashboard.force_section"),
        theme::COLOR_DANGER,
        state.font_small,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );
}

unsafe fn draw_tab_indicator(hdc: HDC, state: &DashboardState) {
    let rc = RECT {
        left: state.tab_indicator_x.round() as i32,
        top: HEADER_H + TAB_BAR_H - TAB_INDICATOR_H,
        right: (state.tab_indicator_x + state.tab_indicator_w).round() as i32,
        bottom: HEADER_H + TAB_BAR_H,
    };
    gfx::fill_rect(hdc, rc, theme::accent_end());
}

/// Géométrie de l'indicateur pour un onglet donné, en coordonnées client.
fn tab_indicator_geometry(tab: Tab, client_w: i32) -> (f32, f32) {
    let tab_w = client_w / 3;
    let index = match tab {
        Tab::Files => 0,
        Tab::Settings => 1,
        Tab::About => 2,
    };
    // Le dernier onglet absorbe l'arrondi de la division.
    let width = if index == 2 { client_w - tab_w * 2 } else { tab_w };
    ((tab_w * index) as f32, width as f32)
}

unsafe fn set_lv_item_text(listview: HWND, item: i32, subitem: i32, text: &str) {
    let mut wide = to_wide_z(text);
    let mut lv = LVITEMW::default();
    lv.mask = LVIF_TEXT;
    lv.iItem = item;
    lv.iSubItem = subitem;
    lv.pszText = PWSTR(wide.as_mut_ptr());
    SendMessageW(
        listview,
        windows::Win32::UI::Controls::LVM_SETITEMTEXTW,
        WPARAM(item as usize),
        LPARAM(&lv as *const _ as isize),
    );
}

unsafe fn insert_lv_item(listview: HWND, item: i32, text: &str) {
    let mut wide = to_wide_z(text);
    let mut lv = LVITEMW::default();
    lv.mask = LVIF_TEXT;
    lv.iItem = item;
    lv.iSubItem = 0;
    lv.pszText = PWSTR(wide.as_mut_ptr());
    SendMessageW(
        listview,
        windows::Win32::UI::Controls::LVM_INSERTITEMW,
        WPARAM(0),
        LPARAM(&lv as *const _ as isize),
    );
}

unsafe fn insert_lv_column(listview: HWND, index: i32, text: &str, width: i32) {
    let mut wide = to_wide_z(text);
    let col = LVCOLUMNW {
        mask: LVCF_TEXT | LVCF_WIDTH,
        cx: width,
        pszText: PWSTR(wide.as_mut_ptr()),
        ..Default::default()
    };
    SendMessageW(
        listview,
        windows::Win32::UI::Controls::LVM_INSERTCOLUMNW,
        WPARAM(index as usize),
        LPARAM(&col as *const _ as isize),
    );
}

/// Sous-classe l'en-tête natif (`SysHeader32`) de la ListView pour le
/// peindre en thème sombre : les notifications `NM_CUSTOMDRAW` de l'en-tête
/// ne remontent pas de façon fiable via `WM_NOTIFY` sur ce contrôle (constaté
/// à l'exécution — un seul `NM_CUSTOMDRAW` reçu pour toute la fenêtre,
/// toujours `hwndFrom == listview`), donc l'en-tête est peint directement en
/// interceptant son propre `WM_ERASEBKGND`/`WM_PAINT`, même technique de
/// Sous-classe la ListView pour suivre la ligne survolée.
///
/// La ListView n'expose pas cette information : `LVS_EX_TRACKSELECT`
/// sélectionnerait la ligne au survol (comportement intrusif), on se contente
/// donc d'un `LVM_HITTEST` sur chaque déplacement de souris.
unsafe fn subclass_listview(hwnd: HWND) {
    let old = SetWindowLongPtrW(hwnd, GWLP_WNDPROC, listview_proc as *const () as usize as isize);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, old);
}

unsafe extern "system" fn listview_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let parent = GetParent(hwnd).unwrap_or_default();
    let state_ptr = GetWindowLongPtrW(parent, GWLP_USERDATA) as *mut DashboardState;

    if !state_ptr.is_null() {
        let state = &mut *state_ptr;
        match msg {
            WM_MOUSEMOVE => {
                let mut hit = LVHITTESTINFO {
                    pt: windows::Win32::Foundation::POINT {
                        x: (lparam.0 & 0xFFFF) as i16 as i32,
                        y: ((lparam.0 >> 16) & 0xFFFF) as i16 as i32,
                    },
                    ..Default::default()
                };
                SendMessageW(
                    hwnd,
                    LVM_HITTEST,
                    WPARAM(0),
                    LPARAM(&mut hit as *mut LVHITTESTINFO as isize),
                );
                if state.hovered_row != hit.iItem {
                    state.hovered_row = hit.iItem;
                    let _ = InvalidateRect(hwnd, None, BOOL(0));
                    let mut tme = TRACKMOUSEEVENT {
                        cbSize: size_of::<TRACKMOUSEEVENT>() as u32,
                        dwFlags: TME_LEAVE,
                        hwndTrack: hwnd,
                        dwHoverTime: 0,
                    };
                    let _ = TrackMouseEvent(&mut tme);
                }
            }
            WM_MOUSELEAVE => {
                if state.hovered_row != -1 {
                    state.hovered_row = -1;
                    let _ = InvalidateRect(hwnd, None, BOOL(0));
                }
            }
            _ => {}
        }
    }

    let old_proc = GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if old_proc != 0 {
        let f: unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT =
            std::mem::transmute(old_proc);
        return f(hwnd, msg, wparam, lparam);
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

/// Sous-classe un bouton owner-draw pour suivre le survol et l'appui.
///
/// Les `BS_OWNERDRAW` ne reçoivent pas d'état de survol de Windows : sans ça,
/// impossible de distinguer « la souris est dessus » de « au repos » au moment
/// de peindre.
unsafe fn subclass_action_button(hwnd: HWND) {
    let old = SetWindowLongPtrW(
        hwnd,
        GWLP_WNDPROC,
        action_button_proc as *const () as usize as isize,
    );
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, old);
}

unsafe extern "system" fn action_button_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let parent = GetParent(hwnd).unwrap_or_default();
    let state_ptr = GetWindowLongPtrW(parent, GWLP_USERDATA) as *mut DashboardState;

    if !state_ptr.is_null() {
        let state = &mut *state_ptr;
        let id = GetDlgCtrlID(hwnd);
        let tab = match id {
            ID_TAB_FILES => Some(Tab::Files),
            ID_TAB_SETTINGS => Some(Tab::Settings),
            ID_TAB_ABOUT => Some(Tab::About),
            _ => None,
        };

        match msg {
            WM_MOUSEMOVE => {
                let already = if tab.is_some() {
                    state.hovered_tab == tab
                } else {
                    state.hovered_button == Some(id)
                };
                if !already {
                    match tab {
                        Some(t) => state.hovered_tab = Some(t),
                        None => state.hovered_button = Some(id),
                    }
                    let mut tme = TRACKMOUSEEVENT {
                        cbSize: size_of::<TRACKMOUSEEVENT>() as u32,
                        dwFlags: TME_LEAVE,
                        hwndTrack: hwnd,
                        dwHoverTime: 0,
                    };
                    let _ = TrackMouseEvent(&mut tme);
                    let _ = InvalidateRect(hwnd, None, BOOL(1));
                }
            }
            WM_MOUSELEAVE => {
                if tab.is_some() {
                    state.hovered_tab = None;
                } else {
                    state.hovered_button = None;
                    state.pressed_button = None;
                }
                let _ = InvalidateRect(hwnd, None, BOOL(1));
            }
            WM_LBUTTONDOWN => {
                state.pressed_button = Some(id);
                let _ = InvalidateRect(hwnd, None, BOOL(1));
            }
            WM_LBUTTONUP => {
                state.pressed_button = None;
                let _ = InvalidateRect(hwnd, None, BOOL(1));
            }
            _ => {}
        }
    }

    let old_proc = GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if old_proc != 0 {
        let f: unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT =
            std::mem::transmute(old_proc);
        return f(hwnd, msg, wparam, lparam);
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

/// sous-classement que `ui::mod::subclass_child`.
unsafe fn subclass_header(hwnd: HWND) {
    let old = SetWindowLongPtrW(hwnd, GWLP_WNDPROC, header_subclass_proc as *const () as usize as isize);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, old);
}

unsafe extern "system" fn header_subclass_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_ERASEBKGND => {
            let hdc = HDC(wparam.0 as *mut c_void);
            let mut rc = RECT::default();
            let _ = GetClientRect(hwnd, &mut rc);
            let brush = CreateSolidBrush(COLORREF(HEADER_BG));
            FillRect(hdc, &rc, brush);
            let _ = DeleteObject(brush);
            return LRESULT(1);
        }
        windows::Win32::UI::WindowsAndMessaging::WM_PAINT => {
            let mut ps = PAINTSTRUCT::default();
            let hdc = BeginPaint(hwnd, &mut ps);

            let mut client_rc = RECT::default();
            let _ = GetClientRect(hwnd, &mut client_rc);
            let bg_brush = CreateSolidBrush(COLORREF(HEADER_BG));
            FillRect(hdc, &client_rc, bg_brush);
            let _ = DeleteObject(bg_brush);

            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, COLORREF(HEADER_TEXT));

            let count = SendMessageW(hwnd, HDM_GETITEMCOUNT, WPARAM(0), LPARAM(0)).0;
            for i in 0..count {
                let mut item_rc = RECT::default();
                SendMessageW(hwnd, HDM_GETITEMRECT, WPARAM(i as usize), LPARAM(&mut item_rc as *mut _ as isize));

                let mut buf = [0u16; 128];
                let mut item = HDITEMW {
                    mask: HDI_TEXT,
                    pszText: PWSTR(buf.as_mut_ptr()),
                    cchTextMax: buf.len() as i32,
                    ..Default::default()
                };
                SendMessageW(hwnd, HDM_GETITEMW, WPARAM(i as usize), LPARAM(&mut item as *mut _ as isize));
                let len = buf.iter().position(|&c| c == 0).unwrap_or(0);
                let mut text: Vec<u16> = buf[..len].to_vec();

                let mut text_rc = RECT {
                    left: item_rc.left + 8,
                    top: item_rc.top,
                    right: (item_rc.right - 4).max(item_rc.left + 8),
                    bottom: item_rc.bottom,
                };
                DrawTextW(hdc, &mut text, &mut text_rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
            }

            let _ = EndPaint(hwnd, &ps);
            return LRESULT(0);
        }
        _ => {}
    }

    let old_proc = GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if old_proc != 0 {
        let f: unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT = std::mem::transmute(old_proc);
        return f(hwnd, msg, wparam, lparam);
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

/// Index de la ligne sélectionnée dans la ListView, ou `None`.
unsafe fn selected_index(listview: HWND) -> Option<usize> {
    let result = SendMessageW(
        listview,
        windows::Win32::UI::Controls::LVM_GETNEXTITEM,
        WPARAM(usize::MAX),
        LPARAM(LVNI_SELECTED as isize),
    )
    .0;
    if result < 0 {
        None
    } else {
        Some(result as usize)
    }
}

/// Index de toutes les lignes sélectionnées (sélection multiple : Ctrl+clic,
/// Shift+clic, ou glisser — la ListView le supporte nativement dès lors que
/// `LVS_SINGLESEL` n'est pas posé sur le contrôle).
unsafe fn selected_indices(listview: HWND) -> Vec<usize> {
    let mut indices = Vec::new();
    let mut start: isize = -1;
    loop {
        let result = SendMessageW(
            listview,
            windows::Win32::UI::Controls::LVM_GETNEXTITEM,
            WPARAM(start as usize),
            LPARAM(LVNI_SELECTED as isize),
        )
        .0;
        if result < 0 {
            break;
        }
        indices.push(result as usize);
        start = result;
    }
    indices
}

fn mode_label(entry: &registry::VaultEntry) -> &'static str {
    if entry.mode == "encrypted" {
        t("dashboard.mode.strong")
    } else {
        t("dashboard.mode.quick")
    }
}

/// Pastille de statut. Un simple rond coloré remplace les emojis 🔓🛡️🔒 :
/// à la taille d'une ligne de ListView, trois emojis différents se
/// distinguaient mal, alors qu'une couleur se lit instantanément.
///
/// La ListView n'accepte que du texte par colonne, d'où le caractère « ● »
/// (présent dans toutes les polices système) colorié via `NM_CUSTOMDRAW`.
fn status_glyph(_entry: &registry::VaultEntry) -> &'static str {
    "●"
}

/// Couleur de la pastille : orange = verrouillé (Rapide), rouge = chiffré
/// (Fort), vert = exposé.
fn status_color(entry: &registry::VaultEntry) -> u32 {
    if entry.status != "locked" {
        theme::COLOR_STATUS_UNLOCKED
    } else if entry.mode == "encrypted" {
        theme::COLOR_STATUS_ENCRYPTED
    } else {
        theme::COLOR_STATUS_ACL
    }
}

fn display_name(entry: &registry::VaultEntry) -> String {
    let path = Path::new(&entry.original_path);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&entry.original_path)
        .to_string();
    if entry.is_directory {
        format!("{name}/")
    } else {
        name
    }
}

fn display_date(entry: &registry::VaultEntry) -> String {
    match chrono::DateTime::parse_from_rfc3339(&entry.protected_at) {
        Ok(dt) => dt.format("%d/%m").to_string(),
        Err(_) => String::new(),
    }
}

/// Recharge le registre, met à jour les compteurs et repeuple la ListView.
/// Met à jour l'infobulle d'un bouton.
unsafe fn update_tooltip(tooltip: HWND, parent: HWND, control: HWND, text: &str) {
    if tooltip.is_invalid() {
        return;
    }
    let mut wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let info = TTTOOLINFOW {
        cbSize: size_of::<TTTOOLINFOW>() as u32,
        uFlags: TTF_IDISHWND | TTF_SUBCLASS,
        hwnd: parent,
        uId: control.0 as usize,
        lpszText: PWSTR(wide.as_mut_ptr()),
        ..Default::default()
    };
    SendMessageW(tooltip, TTM_UPDATETIPTEXTW, WPARAM(0), LPARAM(&info as *const TTTOOLINFOW as isize));
}

/// Relit la licence et répercute son état partout où il est visible :
/// boutons Verrouiller/Chiffrer et leurs infobulles, rappel de sécurité
/// (Pro), onglet À propos, barre de statut.
unsafe fn apply_license_status(hwnd: HWND, state: &mut DashboardState) {
    state.license = license::status();
    let pro = state.license.pro;

    for (control, quota, tip) in [
        (state.hwnd_btn_lock, Quota::Lock, "tip.lock"),
        (state.hwnd_btn_encrypt, Quota::Encrypt, "tip.encrypt"),
    ] {
        let text = if state.license.allows(quota, 1) { t(tip) } else { t("license.limit_tip") };
        update_tooltip(state.tooltip, hwnd, control, text);
        let _ = InvalidateRect(control, None, BOOL(1));
    }

    // Rappel de sécurité : fonctionnalité Pro. Le réglage enregistré n'est pas
    // modifié, il reprend effet à l'activation.
    let _ = EnableWindow(state.hwnd_chk_reminder_enabled, BOOL::from(pro));
    let _ = EnableWindow(state.hwnd_updown_reminder_hours, BOOL::from(pro));
    // Texte vidé plutôt que contrôle masqué : `set_active_tab` réaffiche tous
    // les contrôles de l'onglet, il écraserait un `SW_HIDE`.
    let badge = if pro { "" } else { t("license.pro_only") };
    ui_set_text(state.hwnd_reminder_pro_badge, badge);

    ui_set_text(state.hwnd_about_license, &about_license_text(&state.license));
    sync_license_button_visibility(state);

    let mut client = RECT::default();
    let _ = GetClientRect(hwnd, &mut client);
    let bar = RECT { left: 0, top: client.bottom - STATUS_H, right: client.right, bottom: client.bottom };
    let _ = InvalidateRect(hwnd, Some(&bar), BOOL(0));
}

/// Le bouton d'achat n'est affiché que sur l'onglet À propos. Rappelé après
/// chaque changement d'onglet, qui réaffiche tous les contrôles.
unsafe fn sync_license_button_visibility(state: &DashboardState) {
    let visible = state.current_tab == Tab::About && !state.license.pro;
    let _ = ShowWindow(state.hwnd_btn_license_key, if visible { SW_SHOW } else { SW_HIDE });
}

/// Barre de statut de licence, peinte par le parent en bas de l'onglet
/// Fichiers. Mémorise la zone du lien « Passer à Pro » pour le clic.
unsafe fn draw_status_bar(hdc: HDC, client: RECT, state: &DashboardState) {
    let bar = RECT { left: 0, top: client.bottom - STATUS_H, right: client.right, bottom: client.bottom };
    gfx::fill_rect(hdc, bar, theme::COLOR_STATUS_BAR_BG);

    const PADDING: i32 = 16;
    let (text, show_link) = status_bar_text(&state.license);
    let text_rc = RECT { left: PADDING, ..bar };
    gfx::draw_text_in(hdc, text_rc, &text, theme::COLOR_TEXT_MUTED, state.font_small, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    if !show_link {
        state.status_link_rect.set(RECT::default());
        return;
    }

    // Le lien commence juste après le texte : on mesure sa largeur réelle
    // avec la même police.
    let old_font = SelectObject(hdc, state.font_small);
    let measure = |s: &str| {
        let wide: Vec<u16> = s.encode_utf16().collect();
        let mut size = windows::Win32::Foundation::SIZE::default();
        let _ = GetTextExtentPoint32W(hdc, &wide, &mut size);
        size.cx
    };
    let text_w = measure(&text);
    let link = t("license.go_pro");
    let link_w = measure(link);
    SelectObject(hdc, old_font);

    let link_rc = RECT { left: PADDING + text_w, top: bar.top, right: PADDING + text_w + link_w, bottom: bar.bottom };
    gfx::draw_text_in(hdc, link_rc, link, theme::accent_end(), state.font_small, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    state.status_link_rect.set(link_rc);
}

unsafe fn point_in(rc: RECT, x: i32, y: i32) -> bool {
    x >= rc.left && x < rc.right && y >= rc.top && y < rc.bottom
}

unsafe fn refresh_entries(hwnd: HWND, state: &mut DashboardState) {
    state.entries = registry::list_entries().unwrap_or_default();

    let total = state.entries.len();
    let quick = state.entries.iter().filter(|e| e.mode == "acl_locked").count();
    let strong = state.entries.iter().filter(|e| e.mode == "encrypted").count();

    // Les compteurs remontent de 0 à leur valeur (voir `TIMER_COUNTERS`).
    state.card_targets = [total as i32, quick as i32, strong as i32];
    state.card_progress = 0.0;
    SetTimer(hwnd, TIMER_COUNTERS, ANIM_INTERVAL_MS, None);

    SendMessageW(state.hwnd_listview, windows::Win32::UI::Controls::LVM_DELETEALLITEMS, WPARAM(0), LPARAM(0));
    for (i, entry) in state.entries.iter().enumerate() {
        let idx = i as i32;
        insert_lv_item(state.hwnd_listview, idx, &display_name(entry));
        set_lv_item_text(state.hwnd_listview, idx, 1, &entry.original_path);
        set_lv_item_text(state.hwnd_listview, idx, 2, mode_label(entry));
        set_lv_item_text(state.hwnd_listview, idx, 3, &display_date(entry));
        set_lv_item_text(state.hwnd_listview, idx, 4, status_glyph(entry));
    }

    update_button_states(state);
    apply_license_status(hwnd, state);
    invalidate_cards(hwnd, state);
}

fn ui_set_text(hwnd: HWND, text: &str) {
    let wide = HSTRING::from(text);
    unsafe {
        let _ = windows::Win32::UI::WindowsAndMessaging::SetWindowTextW(hwnd, &wide);
    }
}

fn get_window_text(hwnd: HWND) -> String {
    use windows::Win32::UI::WindowsAndMessaging::{GetWindowTextLengthW, GetWindowTextW};
    unsafe {
        let len = GetWindowTextLengthW(hwnd);
        if len <= 0 {
            return String::new();
        }
        let mut buf = vec![0u16; len as usize + 1];
        let copied = GetWindowTextW(hwnd, &mut buf);
        String::from_utf16_lossy(&buf[..copied as usize])
    }
}

unsafe fn update_button_states(state: &DashboardState) {
    let selected: Vec<&registry::VaultEntry> = selected_indices(state.hwnd_listview)
        .into_iter()
        .filter_map(|i| state.entries.get(i))
        .collect();

    let can_unlock = selected.iter().any(|e| e.mode == "acl_locked" && e.status == "locked");
    let can_decrypt = selected.iter().any(|e| e.mode == "encrypted" && e.status == "locked");
    // Symétrique : une entrée déverrouillée doit pouvoir être re-protégée
    // depuis le dashboard. Avant la 0.7.0 elle n'y offrait AUCUNE action —
    // tous les boutons grisés — et il fallait retourner dans l'Explorateur.
    let can_lock = selected.iter().any(|e| e.mode == "acl_locked" && e.status == "unlocked");
    let can_encrypt = selected.iter().any(|e| e.mode == "encrypted" && e.status == "unlocked");
    let can_remove = !selected.is_empty();
    let can_force_selected = can_unlock;
    // "Tout déverrouiller" agit sur TOUT le registre, indépendamment de la
    // sélection : actif dès qu'il existe au moins un élément acl_locked+locked.
    let can_force_all = state.entries.iter().any(|e| e.mode == "acl_locked" && e.status == "locked");
    let can_export = state.entries.iter().any(|e| e.recovery_key.is_some());

    let _ = EnableWindow(state.hwnd_btn_unlock, BOOL::from(can_unlock));
    let _ = EnableWindow(state.hwnd_btn_decrypt, BOOL::from(can_decrypt));
    let _ = EnableWindow(state.hwnd_btn_lock, BOOL::from(can_lock));
    let _ = EnableWindow(state.hwnd_btn_encrypt, BOOL::from(can_encrypt));
    let _ = EnableWindow(state.hwnd_btn_remove, BOOL::from(can_remove));
    let _ = EnableWindow(state.hwnd_btn_force_one, BOOL::from(can_force_selected));
    let _ = EnableWindow(state.hwnd_btn_force_all, BOOL::from(can_force_all));
    let _ = EnableWindow(state.hwnd_btn_export, BOOL::from(can_export));

    for hwnd in [
        state.hwnd_btn_unlock,
        state.hwnd_btn_decrypt,
        state.hwnd_btn_lock,
        state.hwnd_btn_encrypt,
        state.hwnd_btn_remove,
        state.hwnd_btn_force_one,
        state.hwnd_btn_force_all,
        state.hwnd_btn_export,
    ] {
        let _ = windows::Win32::Graphics::Gdi::InvalidateRect(hwnd, None, BOOL(1));
    }
}

/// Bascule l'onglet actif : montre les contrôles du groupe ciblé, cache ceux
/// des deux autres, et force le repaint de la barre d'onglets (couleurs
/// actif/inactif).
unsafe fn set_active_tab(hwnd: HWND, state: &mut DashboardState, tab: Tab) {
    if state.current_tab != tab {
        // L'indicateur repart de sa position AFFICHÉE : changer d'onglet en
        // plein glissement enchaîne les deux mouvements au lieu de sauter.
        state.tab_indicator_from_x = state.tab_indicator_x;
        state.tab_indicator_from_w = state.tab_indicator_w;
        state.tab_indicator_progress = 0.0;
        SetTimer(hwnd, TIMER_TAB_INDICATOR, ANIM_INTERVAL_MS, None);
    }
    state.current_tab = tab;
    for &hwnd in &state.files_tab_controls {
        let _ = ShowWindow(hwnd, if tab == Tab::Files { SW_SHOW } else { SW_HIDE });
    }
    for &hwnd in &state.settings_tab_controls {
        let _ = ShowWindow(hwnd, if tab == Tab::Settings { SW_SHOW } else { SW_HIDE });
    }
    for &hwnd in &state.about_tab_controls {
        let _ = ShowWindow(hwnd, if tab == Tab::About { SW_SHOW } else { SW_HIDE });
    }
    for tab_hwnd in [state.hwnd_tab_files, state.hwnd_tab_settings, state.hwnd_tab_about] {
        let _ = windows::Win32::Graphics::Gdi::InvalidateRect(tab_hwnd, None, BOOL(1));
    }
    // Les cartes et l'encadré de forçage n'existent que dans l'onglet
    // Fichiers : la zone doit être repeinte au changement d'onglet.
    let _ = InvalidateRect(hwnd, None, BOOL(1));
    sync_license_button_visibility(state);
}

/// Ouvre le sélecteur de dossier natif (`SHBrowseForFolderW`). Retourne
/// `None` si l'utilisateur annule ou en cas d'échec.
unsafe fn browse_for_folder(owner: HWND, title: &str) -> Option<String> {
    let title_w = HSTRING::from(title);
    let mut display_name = [0u16; 260];
    let bi = BROWSEINFOW {
        hwndOwner: owner,
        pidlRoot: std::ptr::null_mut(),
        pszDisplayName: PWSTR(display_name.as_mut_ptr()),
        lpszTitle: PCWSTR(title_w.as_ptr()),
        ulFlags: BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE,
        lpfn: None,
        lParam: LPARAM(0),
        iImage: 0,
    };

    let pidl = SHBrowseForFolderW(&bi);
    if pidl.is_null() {
        return None;
    }

    let mut path_buf = [0u16; 260];
    let ok = SHGetPathFromIDListW(pidl, &mut path_buf).as_bool();
    CoTaskMemFree(Some(pidl as *const ITEMIDLIST as *const c_void));

    if !ok {
        return None;
    }
    let len = path_buf.iter().position(|&c| c == 0).unwrap_or(0);
    Some(String::from_utf16_lossy(&path_buf[..len]))
}

/// Lit l'état courant des contrôles de l'onglet Paramètres, sauvegarde via
/// `settings::save_settings`, puis affiche la confirmation.
/// Ferme cette fenêtre du dashboard et en relance une nouvelle instance —
/// utilisé après un changement de thème ou de langue : ces deux réglages
/// sont lus une seule fois au démarrage du processus (`main()`), donc
/// repeindre la fenêtre existante ne suffirait pas à les appliquer. Un
/// simple redémarrage du dashboard est plus fiable qu'un `InvalidateRect`
/// global, qui exigerait de reconstruire tous les contrôles enfants.
unsafe fn relaunch_dashboard(hwnd: HWND) {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::process::Command::new(exe).arg("dashboard").spawn();
    }
    let _ = DestroyWindow(hwnd);
}

unsafe fn on_save_settings(hwnd: HWND, state: &DashboardState) {
    let is_checked =
        |hwnd: HWND| SendMessageW(hwnd, BM_GETCHECK, WPARAM(0), LPARAM(0)).0 as u32 == BST_CHECKED.0;

    let reminder_hours = SendMessageW(state.hwnd_updown_reminder_hours, UDM_GETPOS32, WPARAM(0), LPARAM(0)).0 as u32;

    let theme = if is_checked(state.hwnd_radio_theme_blue) {
        "blue"
    } else if is_checked(state.hwnd_radio_theme_green) {
        "green"
    } else {
        "red"
    };

    // La langue n'est plus réglable depuis la 1.0.2 (l'interface est en
    // français) : `language` est conservé tel quel dans `config.json`.
    let previous = settings::load_settings();
    let theme_changed = previous.theme != theme;

    let mut current = previous;
    current.security_reminder_enabled = is_checked(state.hwnd_chk_reminder_enabled);
    current.security_reminder_hours = reminder_hours.max(1);
    current.theme = theme.to_string();
    current.recovery_keys_export_path = get_window_text(state.hwnd_edit_export_path);

    match settings::save_settings(&current) {
        Ok(()) => {
            if theme_changed {
                ui::show_info(APP_TITLE, t("settings.saved_restart"));
                // Différé : voir `WM_APP_RELAUNCH`.
                let _ = PostMessageW(hwnd, WM_APP_RELAUNCH, WPARAM(0), LPARAM(0));
            } else {
                ui::show_info(APP_TITLE, t("settings.saved"));
            }
        }
        Err(e) => ui::show_error(APP_TITLE, &e.to_string()),
    }
}

unsafe fn on_browse_export_path(hwnd: HWND, state: &DashboardState) {
    if let Some(folder) = browse_for_folder(hwnd, t("settings.export_path")) {
        ui_set_text(state.hwnd_edit_export_path, &folder);
    }
}

/// Exporte les recovery keys de toutes les entrées chiffrées qui en ont une
/// enregistrée, dans un fichier `.txt` formaté. Protégé par le Master
/// Password : on ne veut pas que n'importe qui exporte ces clés.
unsafe fn on_export_recovery_keys(state: &DashboardState) {
    let has_keys = state.entries.iter().any(|e| e.recovery_key.is_some());
    if !has_keys {
        ui::show_info(APP_TITLE, t("export.no_keys"));
        return;
    }

    let Some(master) = prompt_master_password() else {
        return;
    };

    // Les clés héritées d'une version < 0.7.0 sont encore en clair dans le
    // JSON : c'est le moment idéal pour les sceller, on vient justement de
    // vérifier le Master Password.
    let _ = registry::migrate_plaintext_recovery_keys(&master);
    let entries_with_keys: Vec<registry::VaultEntry> = registry::list_entries()
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e.recovery_key.is_some())
        .collect();

    let cfg = settings::load_settings();
    let export_dir = if !cfg.recovery_keys_export_path.trim().is_empty() {
        PathBuf::from(cfg.recovery_keys_export_path.trim())
    } else {
        match browse_for_folder(HWND::default(), t("export.choose_folder")) {
            Some(folder) => PathBuf::from(folder),
            None => return,
        }
    };

    let today = chrono::Local::now().format("%Y-%m-%d").to_string();
    let file_name = format!("SecureVault_Recovery_Keys_{today}.txt");
    let export_path = export_dir.join(&file_name);

    const RULE: &str = "══════════════════════════════════════════════════════════════";

    // Le contenu du fichier d'export est lui-même un secret : `Zeroizing`
    // pour qu'il ne subsiste pas en mémoire après l'écriture.
    let mut content = Zeroizing::new(String::new());
    content.push_str(&format!("╔{RULE}╗\n"));
    content.push_str(&format!("  {}\n", t("export.header_title")));
    content.push_str(&format!("  {} {today}\n", t("export.header_generated")));
    content.push_str(&format!("╠{RULE}╣\n\n"));

    let mut unreadable = 0usize;
    for (i, entry) in entries_with_keys.iter().enumerate() {
        let name = display_name(entry);
        let protected_date = chrono::DateTime::parse_from_rfc3339(&entry.protected_at)
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_default();

        let key = match registry::get_recovery_key(entry, &master) {
            Ok(k) => k,
            Err(_) => {
                // Une clé illisible (scellée avec un ancien Master Password)
                // ne doit pas faire échouer tout l'export : on la signale.
                unreadable += 1;
                continue;
            }
        };

        content.push_str(&format!("  {}. {name}\n", i + 1));
        content.push_str(&format!("     {}\n", entry.protected_path));
        content.push_str(&format!("     {} {protected_date}\n", t("export.header_encrypted_on")));
        content.push_str(&format!("     Recovery key : {}\n\n", &*key));
    }

    content.push_str(&format!("╠{RULE}╣\n"));
    content.push_str(&format!("  ⚠️  {}\n", t("export.header_keep")));
    content.push_str(&format!("  {}\n", t("export.header_warning")));
    content.push_str(&format!("╚{RULE}╝\n"));

    match std::fs::write(&export_path, content.as_bytes()) {
        Ok(()) => {
            let mut message =
                t("export.done").replace("{path}", &export_path.display().to_string());
            if unreadable > 0 {
                message.push_str("\n\n");
                message
                    .push_str(&t("export.unreadable").replace("{count}", &unreadable.to_string()));
            }
            ui::show_info(APP_TITLE, &message)
        }
        Err(e) => ui::show_error(
            APP_TITLE,
            &t("export.failed").replace("{error}", &e.to_string()),
        ),
    }
}

fn is_elevated() -> bool {
    unsafe { IsUserAnAdmin().as_bool() }
}

/// Demande le Master Password via la popup standard et le RETOURNE, pour que
/// l'appelant puisse s'en servir comme clé (déchiffrement des recovery keys —
/// voir `registry::get_recovery_key`). `None` si l'utilisateur a annulé.
fn prompt_master_password() -> Option<Zeroizing<String>> {
    let validator: ui::PasswordValidator =
        Box::new(|candidate: &str| master::verify_master_password(candidate).unwrap_or(false));
    ui::show_password_prompt(t("password.master_required_title"), Some(validator))
        .ok()
        .map(|prompt| prompt.password)
}

/// Variante pour les actions qui ont seulement besoin d'une autorisation, pas
/// de la valeur (déverrouillage forcé).
fn confirm_master_password() -> bool {
    prompt_master_password().is_some()
}

/// Change le Master Password : ancien puis nouveau, puis re-chiffrement de
/// toutes les recovery keys enregistrées.
///
/// Les recovery keys sont scellées AVEC le Master Password : les oublier ici
/// les rendrait définitivement illisibles. Elles sont donc déchiffrées avec
/// l'ancien et re-scellées avec le nouveau, avant le changement lui-même —
/// si quoi que ce soit échoue, on n'a encore rien modifié.
unsafe fn on_change_master_password() {
    let Some(old) = ({
        let validator: ui::PasswordValidator =
            Box::new(|candidate: &str| master::verify_master_password(candidate).unwrap_or(false));
        ui::show_password_prompt(t("master.change_old"), Some(validator))
            .ok()
            .map(|p| p.password)
    }) else {
        return;
    };

    let Ok(new_prompt) =
        ui::show_password_confirm_prompt(t("master.change_title"), t("master.change_new"))
    else {
        return;
    };
    let new = new_prompt.password;

    match master::change_master_password(&old, &new) {
        Ok(()) => match registry::reseal_recovery_keys(&old, &new) {
            Ok(_) => ui::show_info(APP_TITLE, t("master.changed")),
            Err(e) => ui::show_error(APP_TITLE, &e.to_string()),
        },
        Err(e) => ui::show_error(APP_TITLE, &e.to_string()),
    }
}

/// Re-protège les entrées sélectionnées déjà déverrouillées : verrouillage
/// ACL pour `acl_locked`, chiffrement fort pour `encrypted`. Un seul mot de
/// passe (nouveau, donc popup avec confirmation) pour toute la sélection.
unsafe fn on_reprotect(hwnd: HWND, state: &mut DashboardState, encrypt_mode: bool) {
    let wanted_mode = if encrypt_mode { "encrypted" } else { "acl_locked" };
    let targets = selected_entries(state, |e| e.mode == wanted_mode && e.status == "unlocked");
    if targets.is_empty() {
        ui::show_info(APP_TITLE, t("dashboard.nothing_selected"));
        return;
    }

    // Quota vérifié AVANT la saisie du mot de passe. Refuser après l'avoir
    // fait taper serait une mauvaise surprise.
    let quota = if encrypt_mode { Quota::Encrypt } else { Quota::Lock };
    if !ui::license_prompt::offer_upgrade(quota, targets.len() as u32) {
        return;
    }
    // L'utilisateur a pu activer Pro dans la foulée : rafraîchir boutons,
    // barre de statut et onglet À propos avant de continuer.
    apply_license_status(hwnd, state);

    let (title, label) = if encrypt_mode {
        (t("password.title.encrypt"), t("password.choose_encrypt"))
    } else {
        (t("password.title.lock"), t("password.choose_lock"))
    };
    let Ok(prompt) = ui::show_password_confirm_prompt(title, label) else {
        return;
    };

    // Le Master Password n'est demandé que s'il y a effectivement une
    // recovery key à sceller (chiffrement), et l'annuler ne bloque pas
    // l'opération — voir `main::ask_master_for_recovery`.
    let master_key = if encrypt_mode {
        prompt_master_password()
    } else {
        None
    };

    let _wait = WaitCursor::new();
    let mut ok_count = 0usize;
    let mut failures: Vec<(String, String)> = Vec::new();

    for entry in &targets {
        let original = PathBuf::from(&entry.original_path);
        let result: Result<()> = if encrypt_mode {
            crypto::encrypt_path(&original, &prompt.password).and_then(|(vault_path, recovery)| {
                let vault_str = vault_path.display().to_string();
                registry::add_entry(
                    &entry.original_path,
                    &vault_str,
                    "encrypted",
                    entry.is_directory,
                    Some(&recovery),
                    master_key.as_ref().map(|m| m.as_str()),
                )
            })
        } else {
            acl::lock(&original, &prompt.password)
                .and_then(|()| registry::update_status(&entry.original_path, "locked"))
        };

        match result {
            Ok(()) => ok_count += 1,
            Err(e) => failures.push((entry.original_path.clone(), e.to_string())),
        }
    }

    // Décompte best-effort, uniquement des réussites.
    let _ = license::record(quota, ok_count as u32);

    let mut message = t("dashboard.relock_done").replace("{ok}", &ok_count.to_string());
    if !failures.is_empty() {
        message.push('\n');
        message.push_str(&t("batch.failures").replace("{count}", &failures.len().to_string()));
        for (path, err) in &failures {
            message.push_str(&format!("\n  • {path} : {err}"));
        }
    }
    ui::show_info(APP_TITLE, &message);

    refresh_entries(hwnd, state);
}

/// Entrées sélectionnées dans la ListView, filtrées par prédicat.
unsafe fn selected_entries(
    state: &DashboardState,
    predicate: impl Fn(&registry::VaultEntry) -> bool,
) -> Vec<registry::VaultEntry> {
    selected_indices(state.hwnd_listview)
        .into_iter()
        .filter_map(|i| state.entries.get(i))
        .filter(|e| predicate(e))
        .cloned()
        .collect()
}

unsafe fn on_unlock(hwnd: HWND, state: &mut DashboardState) {
    let targets = selected_entries(state, |e| e.mode == "acl_locked" && e.status == "locked");
    if targets.is_empty() {
        return;
    }

    if targets.len() == 1 {
        let entry = &targets[0];
        let target = PathBuf::from(&entry.original_path);
        let validator: ui::PasswordValidator = {
            let target = target.clone();
            Box::new(move |candidate: &str| acl::verify_password(&target, candidate).unwrap_or(false))
        };
        let Ok(prompt) = ui::show_password_prompt(t("password.title.unlock"),Some(validator)) else {
            return;
        };
        match acl::unlock(&target, &prompt.password) {
            Ok(()) => {
                let _ = registry::update_status(&entry.original_path, "unlocked");
                ui::show_info(
                    APP_TITLE,
                    if entry.is_directory {
                        t("success.unlocked.dir")
                    } else {
                        t("success.unlocked.file")
                    },
                );
            }
            Err(e) => ui::show_error(APP_TITLE, &e.to_string()),
        }
    } else {
        // Sélection multiple : un mot de passe différent par fichier est
        // possible, donc un seul essai est proposé (pas de retry-en-place
        // ciblé sur un fichier précis) et les échecs sont comptabilisés.
        let Ok(prompt) = ui::show_password_prompt(t("password.title.unlock"),None) else {
            return;
        };
        let mut ok_count = 0usize;
        for entry in &targets {
            let target = PathBuf::from(&entry.original_path);
            match acl::unlock(&target, &prompt.password) {
                Ok(()) => {
                    let _ = registry::update_status(&entry.original_path, "unlocked");
                    ok_count += 1;
                }
                Err(_) => {}
            }
        }
        let fail_count = targets.len() - ok_count;
        ui::show_info(
            APP_TITLE,
            &t("batch.unlocked_summary")
                .replace("{ok}", &ok_count.to_string())
                .replace("{fail}", &fail_count.to_string()),
        );
    }
    refresh_entries(hwnd, state);
}

unsafe fn on_decrypt(hwnd: HWND, state: &mut DashboardState) {
    let targets = selected_entries(state, |e| e.mode == "encrypted" && e.status == "locked");
    if targets.is_empty() {
        return;
    }

    if targets.len() == 1 {
        let entry = &targets[0];
        let vault_path = PathBuf::from(&entry.protected_path);
        let validator: ui::PasswordValidator = {
            let vault_path = vault_path.clone();
            Box::new(move |candidate: &str| crypto::verify_password(&vault_path, candidate).unwrap_or(false))
        };
        // Mot de passe OU recovery key, détectés par `crypto::decrypt_path`.
        let legacy = crypto::is_legacy_vault(&vault_path);
        let Ok(prompt) = ui::show_decrypt_prompt(t("password.title.decrypt"), legacy, Some(validator)) else {
            return;
        };
        // Déchiffrer un gros dossier bloque la boucle de messages plusieurs
        // secondes : sans sablier l'application paraît figée.
        let _wait = WaitCursor::new();
        match crypto::decrypt_path(&vault_path, &prompt.password) {
            Ok(outcome) => {
                let _ = registry::update_status(&entry.protected_path, "unlocked");
                let mut message = t("success.decrypted")
                    .replace("{path}", &outcome.output_path.display().to_string());
                if outcome.legacy_format {
                    message.push_str("\n\n");
                    message.push_str(t("decrypt.legacy_warning"));
                }
                ui::show_info(APP_TITLE, &message);
            }
            Err(e) => ui::show_error(APP_TITLE, &e.to_string()),
        }
    } else {
        // Un seul prompt, tenté sur tous les fichiers sélectionnés ; ceux
        // dont le mot de passe diffère échouent et sont comptabilisés.
        let Ok(prompt) = ui::show_decrypt_prompt(t("password.title.decrypt"), false, None) else {
            return;
        };
        let _wait = WaitCursor::new();
        let mut ok_count = 0usize;
        let mut legacy_count = 0usize;
        for entry in &targets {
            let vault_path = PathBuf::from(&entry.protected_path);
            if let Ok(outcome) = crypto::decrypt_path(&vault_path, &prompt.password) {
                let _ = registry::update_status(&entry.protected_path, "unlocked");
                ok_count += 1;
                if outcome.legacy_format {
                    legacy_count += 1;
                }
            }
        }
        let fail_count = targets.len() - ok_count;
        let mut message = t("batch.decrypted_summary")
            .replace("{ok}", &ok_count.to_string())
            .replace("{fail}", &fail_count.to_string());
        if legacy_count > 0 {
            message.push_str("\n\n");
            message.push_str(&t("decrypt.legacy_batch").replace("{count}", &legacy_count.to_string()));
        }
        ui::show_info(APP_TITLE, &message);
    }
    refresh_entries(hwnd, state);
}

unsafe fn on_remove(hwnd: HWND, state: &mut DashboardState) {
    let targets = selected_entries(state, |_| true);
    if targets.is_empty() {
        return;
    }
    if targets.len() > 1
        && !ui::show_confirm(
            APP_TITLE,
            &t("dashboard.remove_confirm").replace("{count}", &targets.len().to_string()),
        )
    {
        return;
    }
    for entry in &targets {
        if let Err(e) = registry::remove_entry(&entry.id) {
            ui::show_error(APP_TITLE, &e.to_string());
        }
    }
    refresh_entries(hwnd, state);
}

/// Lance `"<exe>" <args>` avec élévation (`runas`) et ATTEND que le
/// processus élevé se termine (`SEE_MASK_NOCLOSEPROCESS` +
/// `WaitForSingleObject`), pour que l'appelant puisse rafraîchir son état
/// juste après — plutôt que d'afficher un message vague et de laisser le
/// dashboard non élevé dans un état périmé.
unsafe fn relaunch_elevated_and_wait(args: &str) -> Result<()> {
    let exe = std::env::current_exe()?;
    let exe_w = HSTRING::from(exe.as_os_str());
    let args_w = HSTRING::from(args);

    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(exe_w.as_ptr()),
        lpParameters: PCWSTR(args_w.as_ptr()),
        nShow: SW_SHOWNORMAL.0,
        ..Default::default()
    };

    ShellExecuteExW(&mut info)
        .map_err(|e| SecureVaultError::Acl(format!("l'élévation des privilèges a échoué: {e}")))?;
    if info.hProcess.is_invalid() {
        return Err(SecureVaultError::Acl(
            t("force.elevation_failed").into(),
        ));
    }
    WaitForSingleObject(info.hProcess, INFINITE);
    let _ = CloseHandle(info.hProcess);
    Ok(())
}

fn build_force_unlock_args(entries: &[registry::VaultEntry]) -> String {
    let mut args = String::from("force-unlock");
    for entry in entries {
        args.push_str(&format!(" \"{}\"", entry.original_path));
    }
    args
}

unsafe fn on_force_selected(hwnd: HWND, state: &mut DashboardState) {
    let selected = selected_entries(state, |_| true);
    if selected.is_empty() {
        return;
    }

    let (candidates, ignored): (Vec<_>, Vec<_>) =
        selected.into_iter().partition(|e| e.mode == "acl_locked");
    if candidates.is_empty() {
        ui::show_error(
            APP_TITLE,
            t("force.encrypted_blocked"),
        );
        return;
    }
    if !confirm_master_password() {
        return;
    }

    if is_elevated() {
        let _wait = WaitCursor::new();
        let results: Vec<(String, Result<()>)> = candidates
            .iter()
            .map(|e| {
                (
                    e.original_path.clone(),
                    force_unlock::force_unlock_path(Path::new(&e.original_path)),
                )
            })
            .collect();
        let ok_count = results.iter().filter(|(_, r)| r.is_ok()).count();
        let fail_count = results.len() - ok_count;
        let mut message = t("force.summary")
            .replace("{ok}", &ok_count.to_string())
            .replace("{fail}", &fail_count.to_string());
        if !ignored.is_empty() {
            message.push_str(&t("force.skipped").replace("{count}", &ignored.len().to_string()));
        }
        ui::show_info(APP_TITLE, &message);
        refresh_entries(hwnd, state);
    } else {
        match relaunch_elevated_and_wait(&build_force_unlock_args(&candidates)) {
            Ok(()) => refresh_entries(hwnd, state),
            Err(e) => ui::show_error(APP_TITLE, &e.to_string()),
        }
    }
}

unsafe fn on_force_all(hwnd: HWND, state: &mut DashboardState) {
    let candidates = registry::find_locked_acl_entries().unwrap_or_default();
    if candidates.is_empty() {
        ui::show_info(APP_TITLE, t("force.none_locked"));
        return;
    }
    if !confirm_master_password() {
        return;
    }
    if !ui::show_confirm(
        APP_TITLE,
        &t("force.confirm").replace("{count}", &candidates.len().to_string()),
    ) {
        return;
    }

    if is_elevated() {
        let _wait = WaitCursor::new();
        match force_unlock::force_unlock_all(&candidates) {
            Ok(results) => {
                let ok_count = results.iter().filter(|(_, r)| r.is_ok()).count();
                let fail_count = results.len() - ok_count;
                ui::show_info(
                    APP_TITLE,
                    &t("force.summary")
                        .replace("{ok}", &ok_count.to_string())
                        .replace("{fail}", &fail_count.to_string()),
                );
            }
            Err(e) => ui::show_error(APP_TITLE, &e.to_string()),
        }
        refresh_entries(hwnd, state);
    } else {
        // Le processus élevé (`force-unlock-all`) exécute le déverrouillage
        // et affiche lui-même le résumé ; le dashboard non élevé attend sa
        // fin puis se contente de rafraîchir sa liste.
        match relaunch_elevated_and_wait("force-unlock-all") {
            Ok(()) => refresh_entries(hwnd, state),
            Err(e) => ui::show_error(APP_TITLE, &e.to_string()),
        }
    }
}

unsafe fn on_double_click(state: &DashboardState) {
    let Some(entry) = selected_index(state.hwnd_listview).and_then(|i| state.entries.get(i)) else {
        return;
    };
    let Some(parent) = Path::new(&entry.original_path).parent() else {
        return;
    };
    let parent_w = HSTRING::from(parent.as_os_str());
    ShellExecuteW(None, w!("open"), &parent_w, PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL);
}

/// Recalcule la position/taille de tous les contrôles en fonction de la
/// taille client courante — appelé après création puis à chaque `WM_SIZE`
/// (fenêtre redimensionnable).
unsafe fn layout(state: &mut DashboardState, client_w: i32, client_h: i32) {
    let content_w = (client_w - MARGIN * 2).max(200);

    // Boutons de la barre de titre custom, collés à droite du bandeau.
    for (index, &btn) in [
        state.hwnd_btn_minimize,
        state.hwnd_btn_maximize,
        state.hwnd_btn_close,
    ]
    .iter()
    .enumerate()
    {
        let x = client_w - WINDOW_BTN_W * (3 - index as i32);
        let _ = MoveWindow(btn, x, 0, WINDOW_BTN_W, HEADER_H, BOOL(1));
    }

    // Barre d'onglets, pleine largeur, sous le bandeau.
    //
    // Les boutons s'arrêtent `TAB_INDICATOR_H` pixels avant le bas : c'est la
    // fenêtre parente qui y peint la ligne indicatrice, et `WS_CLIPCHILDREN`
    // l'empêcherait de dessiner sous un contrôle enfant. Cette bande libre
    // permet aussi à l'indicateur de chevaucher deux onglets pendant son
    // glissement.
    let tab_w = client_w / 3;
    let tab_h = TAB_BAR_H - TAB_INDICATOR_H;
    let _ = MoveWindow(state.hwnd_tab_files, 0, HEADER_H, tab_w, tab_h, BOOL(1));
    let _ = MoveWindow(state.hwnd_tab_settings, tab_w, HEADER_H, tab_w, tab_h, BOOL(1));
    let _ = MoveWindow(
        state.hwnd_tab_about,
        tab_w * 2,
        HEADER_H,
        client_w - tab_w * 2,
        tab_h,
        BOOL(1),
    );

    // Tout le contenu de l'onglet "Fichiers protégés" est décalé sous le
    // bandeau ET la barre d'onglets.
    let top = HEADER_H + TAB_BAR_H + MARGIN;

    // Cartes statistiques (haut) : simples rectangles mémorisés, peints par
    // le `WM_PAINT` du parent.
    let card_w = (content_w - CARD_GAP * 2) / 3;
    for i in 0..3 {
        let x = MARGIN + i as i32 * (card_w + CARD_GAP);
        state.card_rects[i] = RECT {
            left: x,
            top,
            right: x + card_w,
            bottom: top + CARD_H,
        };
    }

    // Zone basse : boutons de déverrouillage forcé, séparateur, boutons
    // standards, calculés du bas vers le haut pour rester ancrés en bas
    // quel que soit le redimensionnement.
    // La barre de statut de licence occupe les `STATUS_H` derniers pixels.
    let row2_y = (client_h - STATUS_H - MARGIN - 12 - ROW2_H).max(top + CARD_H + 240);
    let label_y = row2_y - 10 - 20;
    // Deux rangées d'actions depuis la 0.7.0 : les quatre transitions d'état
    // (Verrouiller/Déverrouiller/Chiffrer/Déchiffrer) sur la première, les
    // trois actions de gestion (Retirer/Exporter/Rafraîchir) sur la seconde.
    // Sept boutons sur une seule ligne devenaient illisibles en dessous de
    // 900 px de large.
    let rowb_y = label_y - 12 - 14 - ROW1_H;
    let rowa_y = rowb_y - 10 - ROW1_H;
    let listview_y = top + CARD_H + MARGIN;
    let listview_h = (rowa_y - 15 - listview_y).max(80);

    let _ = MoveWindow(state.hwnd_listview, MARGIN, listview_y, content_w, listview_h, BOOL(1));

    let btn_a_w = (content_w - BTN_GAP * 3) / 4;
    for (i, &btn) in [
        state.hwnd_btn_unlock,
        state.hwnd_btn_decrypt,
        state.hwnd_btn_lock,
        state.hwnd_btn_encrypt,
    ]
    .iter()
    .enumerate()
    {
        let _ = MoveWindow(
            btn,
            MARGIN + i as i32 * (btn_a_w + BTN_GAP),
            rowa_y,
            btn_a_w,
            ROW1_H,
            BOOL(1),
        );
    }

    let btn_b_w = (content_w - BTN_GAP * 2) / 3;
    for (i, &btn) in [
        state.hwnd_btn_remove,
        state.hwnd_btn_export,
        state.hwnd_btn_refresh,
    ]
    .iter()
    .enumerate()
    {
        let _ = MoveWindow(
            btn,
            MARGIN + i as i32 * (btn_b_w + BTN_GAP),
            rowb_y,
            btn_b_w,
            ROW1_H,
            BOOL(1),
        );
    }

    // Encadré de la zone dangereuse : englobe le titre et les deux boutons,
    // avec 12 px de marge interne.
    const ZONE_PADDING: i32 = 12;
    state.force_zone_rect = RECT {
        left: MARGIN,
        top: label_y - ZONE_PADDING,
        right: MARGIN + content_w,
        bottom: row2_y + ROW2_H + ZONE_PADDING,
    };

    let inner_w = content_w - ZONE_PADDING * 2;
    let btn2_w = (inner_w - BTN_GAP) / 2;
    let btn_x = MARGIN + ZONE_PADDING;
    let _ = MoveWindow(state.hwnd_btn_force_one, btn_x, row2_y, btn2_w, ROW2_H, BOOL(1));
    let _ = MoveWindow(
        state.hwnd_btn_force_all,
        btn_x + btn2_w + BTN_GAP,
        row2_y,
        btn2_w,
        ROW2_H,
        BOOL(1),
    );
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let state_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut DashboardState;

    match msg {
        // Rien à effacer : tout le fond est peint dans `WM_PAINT`, via un
        // tampon mémoire. Effacer ici puis repeindre ferait scintiller le
        // dégradé à chaque frame d'animation.
        WM_ERASEBKGND => LRESULT(1),
        WM_PAINT => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &*state_ptr;
            let mut ps = PAINTSTRUCT::default();
            let hdc = BeginPaint(hwnd, &mut ps);
            let mut client = RECT::default();
            let _ = GetClientRect(hwnd, &mut client);

            // Double tampon : le parent peint le fond, le bandeau, les cartes
            // animées et l'indicateur d'onglet. `WS_CLIPCHILDREN` exclut déjà
            // les zones des contrôles enfants.
            if let Some(buffer) = gfx::BackBuffer::new(hdc, client) {
                let local = buffer.local();
                gfx::fill_gradient_v(
                    buffer.dc,
                    local,
                    theme::COLOR_BACKGROUND,
                    theme::COLOR_BACKGROUND_BOTTOM,
                );
                draw_header(buffer.dc, local.right, state);
                draw_tab_indicator(buffer.dc, state);

                if state.current_tab == Tab::Files {
                    let labels = [
                        t("dashboard.stats.total"),
                        t("dashboard.stats.quick"),
                        t("dashboard.stats.encrypted"),
                    ];
                    for i in 0..3 {
                        let value = animated_count(state.card_targets[i], state.card_progress);
                        draw_card(
                            buffer.dc,
                            state.card_rects[i],
                            value,
                            labels[i],
                            state.card_hover[i],
                            state,
                        );
                    }
                    draw_force_zone(buffer.dc, state.force_zone_rect, state);
                    draw_status_bar(buffer.dc, local, state);
                }

                buffer.present();
            }

            let _ = EndPaint(hwnd, &ps);
            LRESULT(0)
        }
        // Le bandeau tient lieu de barre de titre : y glisser déplace la
        // fenêtre, et un double-clic l'agrandit — deux comportements fournis
        // par `DefWindowProc` dès qu'on lui répond `HTCAPTION`.
        //
        // On interroge `DefWindowProc` EN PREMIER pour ne pas court-circuiter
        // les bords de redimensionnement (`WS_THICKFRAME`), qui priment.
        WM_NCHITTEST => {
            let hit = DefWindowProcW(hwnd, msg, wparam, lparam);
            if hit.0 as u32 != HTCLIENT {
                return hit;
            }
            let y = ((lparam.0 >> 16) & 0xFFFF) as i16 as i32;
            let x = (lparam.0 & 0xFFFF) as i16 as i32;
            let mut point = windows::Win32::Foundation::POINT { x, y };
            let _ = ScreenToClient(hwnd, &mut point);
            if point.y >= 0 && point.y < HEADER_H {
                return LRESULT(HTCAPTION as isize);
            }
            hit
        }
        WM_CTLCOLORSTATIC => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &*state_ptr;
            let hdc = HDC(wparam.0 as *mut c_void);
            let ctrl = HWND(lparam.0 as *mut c_void);

            if ctrl == state.hwnd_reminder_pro_badge {
                SetTextColor(hdc, COLORREF(theme::accent_end()));
                windows::Win32::Graphics::Gdi::SetBkColor(hdc, COLORREF(theme::COLOR_BACKGROUND));
                return LRESULT(state.brush_background.0 as isize);
            }
            SetTextColor(hdc, COLORREF(theme::COLOR_TEXT));
            windows::Win32::Graphics::Gdi::SetBkColor(hdc, COLORREF(theme::COLOR_BACKGROUND));
            LRESULT(state.brush_background.0 as isize)
        }
        WM_CTLCOLORBTN => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &*state_ptr;
            LRESULT(state.brush_background.0 as isize)
        }
        WM_CTLCOLOREDIT => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &*state_ptr;
            let hdc = HDC(wparam.0 as *mut c_void);
            SetTextColor(hdc, COLORREF(theme::COLOR_TEXT));
            SetBkColor(hdc, COLORREF(theme::COLOR_FIELD_BACKGROUND));
            LRESULT(state.brush_card_bg.0 as isize)
        }
        WM_TIMER => {
            if wparam.0 == TIMER_SECURITY_CHECK {
                notifier::check_and_notify();
                return LRESULT(0);
            }
            if state_ptr.is_null() {
                return LRESULT(0);
            }
            let state = &mut *state_ptr;
            match wparam.0 {
                TIMER_COUNTERS => {
                    state.card_progress = (state.card_progress + COUNTER_STEP).min(1.0);
                    invalidate_cards(hwnd, state);
                    if state.card_progress >= 1.0 {
                        let _ = KillTimer(hwnd, TIMER_COUNTERS);
                    }
                }
                TIMER_CARD_HOVER => {
                    let mut moving = false;
                    for i in 0..3 {
                        let target = state.card_hover_target[i];
                        let mut current = state.card_hover[i];
                        if step_towards(&mut current, target, CARD_HOVER_STEP) {
                            state.card_hover[i] = current;
                            moving = true;
                        }
                    }
                    if moving {
                        invalidate_cards(hwnd, state);
                    } else {
                        let _ = KillTimer(hwnd, TIMER_CARD_HOVER);
                    }
                }
                TIMER_TAB_INDICATOR => {
                    state.tab_indicator_progress =
                        (state.tab_indicator_progress + TAB_INDICATOR_STEP).min(1.0);
                    let t = gfx::ease_out_cubic(state.tab_indicator_progress);
                    let mut client = RECT::default();
                    let _ = GetClientRect(hwnd, &mut client);
                    let (target_x, target_w) =
                        tab_indicator_geometry(state.current_tab, client.right - client.left);
                    state.tab_indicator_x =
                        state.tab_indicator_from_x + (target_x - state.tab_indicator_from_x) * t;
                    state.tab_indicator_w =
                        state.tab_indicator_from_w + (target_w - state.tab_indicator_from_w) * t;

                    let strip = RECT {
                        left: 0,
                        top: HEADER_H + TAB_BAR_H - TAB_INDICATOR_H,
                        right: client.right,
                        bottom: HEADER_H + TAB_BAR_H,
                    };
                    let _ = InvalidateRect(hwnd, Some(&strip), BOOL(0));
                    if state.tab_indicator_progress >= 1.0 {
                        let _ = KillTimer(hwnd, TIMER_TAB_INDICATOR);
                    }
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_DRAWITEM => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &*state_ptr;
            let item = &*(lparam.0 as *const DRAWITEMSTRUCT);
            match item.CtlID as i32 {
                ID_BTN_MINIMIZE | ID_BTN_MAXIMIZE | ID_BTN_CLOSE => {
                    draw_window_button(item, state);
                    return LRESULT(1);
                }
                _ => {}
            }
            if matches!(item.CtlID as i32, ID_TAB_FILES | ID_TAB_SETTINGS | ID_TAB_ABOUT) {
                draw_tab_button(item, state);
            } else {
                let orange = matches!(item.CtlID as i32, ID_BTN_FORCE_ONE | ID_BTN_FORCE_ALL);
                draw_button(item, state, orange);
            }
            LRESULT(1)
        }
        WM_NOTIFY => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &mut *state_ptr;
            let nmhdr = &*(lparam.0 as *const NMHDR);

            match nmhdr.code {
                NM_CUSTOMDRAW => {
                    if nmhdr.hwndFrom == state.hwnd_listview {
                        let cd = &mut *(lparam.0 as *mut NMLVCUSTOMDRAW);
                        return match cd.nmcd.dwDrawStage {
                            windows::Win32::UI::Controls::CDDS_PREPAINT => {
                                LRESULT(windows::Win32::UI::Controls::CDRF_NOTIFYITEMDRAW as isize)
                            }
                            // Sous-élément : seule la colonne Statut change de
                            // couleur de texte (la pastille).
                            stage if stage.0
                                == windows::Win32::UI::Controls::CDDS_ITEMPREPAINT.0
                                    | windows::Win32::UI::Controls::CDDS_SUBITEM.0 =>
                            {
                                const STATUS_COLUMN: i32 = 4;
                                if cd.iSubItem == STATUS_COLUMN {
                                    if let Some(entry) =
                                        state.entries.get(cd.nmcd.dwItemSpec as usize)
                                    {
                                        cd.clrText = COLORREF(status_color(entry));
                                    }
                                }
                                LRESULT(windows::Win32::UI::Controls::CDRF_NEWFONT as isize)
                            }
                            windows::Win32::UI::Controls::CDDS_ITEMPREPAINT => {
                                let index = cd.nmcd.dwItemSpec as i32;
                                let selected = SendMessageW(
                                    state.hwnd_listview,
                                    LVM_GETITEMSTATE,
                                    WPARAM(index as usize),
                                    LPARAM(LVIS_SELECTED.0 as isize),
                                )
                                .0 as u32
                                    & LVIS_SELECTED.0
                                    != 0;

                                let base = if index % 2 == 0 {
                                    theme::COLOR_ROW_EVEN
                                } else {
                                    theme::COLOR_ROW_ODD
                                };
                                // Sélection : accent mélangé au fond plutôt
                                // qu'un aplat — GDI n'ayant pas d'alpha sur la
                                // ListView, on pré-mélange (voir `gfx::over`).
                                let (bg, fg) = if selected {
                                    (
                                        gfx::over(theme::accent_end(), base, 0.55),
                                        theme::COLOR_WHITE,
                                    )
                                } else if index == state.hovered_row {
                                    (theme::COLOR_ROW_HOVER, theme::COLOR_TEXT)
                                } else {
                                    (base, theme::COLOR_TEXT)
                                };
                                cd.clrTextBk = COLORREF(bg);
                                cd.clrText = COLORREF(fg);
                                LRESULT(
                                    windows::Win32::UI::Controls::CDRF_NEWFONT as isize
                                        | windows::Win32::UI::Controls::CDRF_NOTIFYSUBITEMDRAW
                                            as isize,
                                )
                            }
                            _ => LRESULT(windows::Win32::UI::Controls::CDRF_DODEFAULT as isize),
                        };
                    }
                    LRESULT(windows::Win32::UI::Controls::CDRF_DODEFAULT as isize)
                }
                NM_DBLCLK if nmhdr.hwndFrom == state.hwnd_listview => {
                    on_double_click(state);
                    LRESULT(0)
                }
                LVN_ITEMCHANGED if nmhdr.hwndFrom == state.hwnd_listview => {
                    update_button_states(state);
                    LRESULT(0)
                }
                _ => LRESULT(0),
            }
        }
        WM_COMMAND => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &mut *state_ptr;
            let control_id = (wparam.0 & 0xFFFF) as i32;
            let notify_code = ((wparam.0 >> 16) & 0xFFFF) as u32;
            if notify_code == BN_CLICKED {
                match control_id {
                    ID_BTN_UNLOCK => on_unlock(hwnd, state),
                    ID_BTN_DECRYPT => on_decrypt(hwnd, state),
                    ID_BTN_REMOVE => on_remove(hwnd, state),
                    ID_BTN_FORCE_ONE => on_force_selected(hwnd, state),
                    ID_BTN_FORCE_ALL => on_force_all(hwnd, state),
                    ID_BTN_EXPORT => on_export_recovery_keys(state),
                    ID_BTN_REFRESH => refresh_entries(hwnd, state),
                    ID_BTN_LOCK => on_reprotect(hwnd, state, false),
                    ID_BTN_ENCRYPT => on_reprotect(hwnd, state, true),
                    ID_BTN_CHANGE_MASTER => on_change_master_password(),
                    ID_BTN_LICENSE_KEY => ui::license_prompt::open_buy_page(),
                    ID_BTN_MINIMIZE => {
                        let _ = ShowWindow(hwnd, SW_MINIMIZE);
                    }
                    ID_BTN_MAXIMIZE => {
                        // Bascule agrandi/restauré, comme un double-clic sur
                        // la barre de titre.
                        let restore = IsZoomed(hwnd).as_bool();
                        let _ = ShowWindow(hwnd, if restore { SW_RESTORE } else { SW_MAXIMIZE });
                    }
                    ID_BTN_CLOSE => {
                        let _ = PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0));
                    }
                    ID_TAB_FILES => set_active_tab(hwnd, state, Tab::Files),
                    ID_TAB_SETTINGS => set_active_tab(hwnd, state, Tab::Settings),
                    ID_TAB_ABOUT => set_active_tab(hwnd, state, Tab::About),
                    ID_BTN_BROWSE_EXPORT_PATH => on_browse_export_path(hwnd, state),
                    ID_BTN_SAVE_SETTINGS => on_save_settings(hwnd, state),
                    ID_BTN_OPEN_DOCS => {
                        if let Ok(exe) = std::env::current_exe() {
                            if let Some(dir) = exe.parent() {
                                open_with_shell(&dir.join("docs").join("guide.html"));
                            }
                        }
                    }
                    ID_BTN_OPEN_INSTALL_DIR => {
                        if let Ok(exe) = std::env::current_exe() {
                            if let Some(dir) = exe.parent() {
                                open_with_shell(dir);
                            }
                        }
                    }
                    ID_BTN_OPEN_LOCAL_DATA => {
                        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
                            open_with_shell(&PathBuf::from(local_app_data).join("SecureVault"));
                        }
                    }
                    _ => {}
                }
            }
            LRESULT(0)
        }
        // Posté par `on_save_settings` : à ce stade le `WM_COMMAND` qui l'a
        // déclenché est terminé, donc plus aucune référence à
        // `DashboardState` n'est vivante quand `WM_DESTROY` le libère.
        WM_APP_RELAUNCH => {
            relaunch_dashboard(hwnd);
            LRESULT(0)
        }
        WM_MOUSEMOVE => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &mut *state_ptr;
            // Les cartes ne sont plus des contrôles : c'est le parent qui
            // reçoit les mouvements au-dessus d'elles.
            let x = (lparam.0 & 0xFFFF) as i16 as i32;
            let y = ((lparam.0 >> 16) & 0xFFFF) as i16 as i32;
            let mut changed = false;
            for i in 0..3 {
                let rc = state.card_rects[i];
                let inside = state.current_tab == Tab::Files
                    && x >= rc.left
                    && x < rc.right
                    && y >= rc.top
                    && y < rc.bottom;
                let target = if inside { 1.0 } else { 0.0 };
                if state.card_hover_target[i] != target {
                    state.card_hover_target[i] = target;
                    changed = true;
                }
            }
            if changed {
                SetTimer(hwnd, TIMER_CARD_HOVER, ANIM_INTERVAL_MS, None);
                let mut tme = TRACKMOUSEEVENT {
                    cbSize: size_of::<TRACKMOUSEEVENT>() as u32,
                    dwFlags: TME_LEAVE,
                    hwndTrack: hwnd,
                    dwHoverTime: 0,
                };
                let _ = TrackMouseEvent(&mut tme);
            }
            LRESULT(0)
        }
        WM_LBUTTONUP => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &mut *state_ptr;
            let x = (lparam.0 & 0xFFFF) as i16 as i32;
            let y = ((lparam.0 >> 16) & 0xFFFF) as i16 as i32;
            if state.current_tab == Tab::Files
                && !state.license.pro
                && point_in(state.status_link_rect.get(), x, y)
            {
                ui::license_prompt::open_buy_page();
            }
            LRESULT(0)
        }
        WM_SETCURSOR => {
            // Main sur le lien « Passer à Pro » : sans elle, rien n'indique
            // qu'un texte de barre de statut est cliquable.
            if !state_ptr.is_null() && (lparam.0 & 0xFFFF) as u32 == HTCLIENT {
                let state = &*state_ptr;
                let mut pt = windows::Win32::Foundation::POINT::default();
                if windows::Win32::UI::WindowsAndMessaging::GetCursorPos(&mut pt).is_ok() {
                    let _ = ScreenToClient(hwnd, &mut pt);
                    if state.current_tab == Tab::Files && point_in(state.status_link_rect.get(), pt.x, pt.y) {
                        SetCursor(LoadCursorW(None, IDC_HAND).unwrap_or_default());
                        return LRESULT(1);
                    }
                }
            }
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        WM_MOUSELEAVE => {
            if !state_ptr.is_null() {
                let state = &mut *state_ptr;
                state.card_hover_target = [0.0; 3];
                SetTimer(hwnd, TIMER_CARD_HOVER, ANIM_INTERVAL_MS, None);
            }
            LRESULT(0)
        }
        WM_SIZE => {
            if !state_ptr.is_null() {
                let state = &mut *state_ptr;
                // Le bandeau et l'indicateur dépendent de la largeur : les
                // repositionner sans attendre la prochaine animation.
                let mut client = RECT::default();
                let _ = GetClientRect(hwnd, &mut client);
                let (x, w) = tab_indicator_geometry(state.current_tab, client.right - client.left);
                state.tab_indicator_x = x;
                state.tab_indicator_w = w;
                state.tab_indicator_from_x = x;
                state.tab_indicator_from_w = w;
                state.tab_indicator_progress = 1.0;
                let _ = InvalidateRect(hwnd, None, BOOL(0));
            }
            if !state_ptr.is_null() {
                let state = &mut *state_ptr;
                let mut rc = RECT::default();
                let _ = GetClientRect(hwnd, &mut rc);
                layout(state, rc.right - rc.left, rc.bottom - rc.top);
            }
            LRESULT(0)
        }
        WM_GETMINMAXINFO => {
            let info = &mut *(lparam.0 as *mut windows::Win32::UI::WindowsAndMessaging::MINMAXINFO);
            info.ptMinTrackSize.x = MIN_WIDTH;
            info.ptMinTrackSize.y = MIN_HEIGHT;

            // Sans `WS_CAPTION`, Windows agrandit une `WS_POPUP` sur l'écran
            // ENTIER, barre des tâches comprise. On borne donc nous-mêmes à la
            // zone de travail du moniteur courant.
            let monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
            let mut mi = MONITORINFO {
                cbSize: size_of::<MONITORINFO>() as u32,
                ..Default::default()
            };
            if GetMonitorInfoW(monitor, &mut mi).as_bool() {
                let work = mi.rcWork;
                info.ptMaxPosition.x = work.left - mi.rcMonitor.left;
                info.ptMaxPosition.y = work.top - mi.rcMonitor.top;
                info.ptMaxSize.x = work.right - work.left;
                info.ptMaxSize.y = work.bottom - work.top;
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            let _ = KillTimer(hwnd, TIMER_SECURITY_CHECK);
            if !state_ptr.is_null() {
                let state = Box::from_raw(state_ptr);
                let _ = DeleteObject(state.font);
                let _ = DeleteObject(state.font_bold);
                let _ = DeleteObject(state.font_small);
                let _ = DeleteObject(state.font_header);
                // L'infobulle est une fenêtre, pas un objet GDI.
                if !state.tooltip.is_invalid() {
                    let _ = DestroyWindow(state.tooltip);
                }
                let _ = DeleteObject(state.brush_background);
                let _ = DeleteObject(state.brush_card_bg);
                let _ = DeleteObject(state.brush_card_border);
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            }
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn register_class_once() -> Result<()> {
    use std::sync::Once;
    static REGISTER: Once = Once::new();
    // `OnceLock` plutôt que `static mut` : même sémantique « enregistrer la
    // classe une seule fois », sans `unsafe` et sans le warning de
    // dépréciation de l'édition 2024.
    static REGISTER_OK: OnceLock<bool> = OnceLock::new();

    unsafe {
        REGISTER.call_once(|| {
            let hinstance = match GetModuleHandleW(PCWSTR::null()) {
                Ok(h) => HINSTANCE::from(h),
                Err(_) => return,
            };
            let cursor = LoadCursorW(None, IDC_ARROW).unwrap_or_default();
            let class = WNDCLASSW {
                style: CS_HREDRAW | CS_VREDRAW,
                lpfnWndProc: Some(wnd_proc),
                hInstance: hinstance,
                hCursor: cursor,
                lpszClassName: CLASS_NAME,
                ..Default::default()
            };
            REGISTER_OK.get_or_init(|| RegisterClassW(&class) != 0);
        });

        if *REGISTER_OK.get().unwrap_or(&false) {
            Ok(())
        } else {
            Err(SecureVaultError::Crypto(
                "impossible d'enregistrer la classe de fenêtre du dashboard".into(),
            ))
        }
    }
}

/// Crée un contrôle EDIT numérique et son buddy `UPDOWN_CLASS` (spinbox),
/// avec la plage `[min, max]` et la valeur initiale `initial`.
unsafe fn create_spinbox(
    hwnd: HWND,
    hinstance: HINSTANCE,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id_edit: i32,
    min: i32,
    max: i32,
    initial: i32,
) -> Result<(HWND, HWND)> {
    let edit = create_child(
        hwnd,
        hinstance,
        ChildSpec {
            class: w!("EDIT"),
            text: "",
            style: WINDOW_STYLE(ES_AUTOHSCROLL as u32) | WS_TABSTOP,
            x,
            y,
            w,
            h,
            id: id_edit,
        },
    )?;
    let updown = create_child(
        hwnd,
        hinstance,
        ChildSpec {
            class: UPDOWN_CLASS,
            text: "",
            style: WINDOW_STYLE(UDS_SETBUDDYINT | UDS_ALIGNRIGHT | UDS_ARROWKEYS),
            x: x + w,
            y,
            w: 18,
            h,
            id: 0,
        },
    )?;
    SendMessageW(updown, UDM_SETBUDDY, WPARAM(edit.0 as usize), LPARAM(0));
    SendMessageW(updown, UDM_SETRANGE32, WPARAM(min as usize), LPARAM(max as isize));
    SendMessageW(updown, UDM_SETPOS32, WPARAM(0), LPARAM(initial as isize));
    Ok((edit, updown))
}

/// Crée tous les contrôles de l'onglet "Paramètres" (positions fixes,
/// indépendantes du redimensionnement de la fenêtre — contrairement à
/// l'onglet "Fichiers protégés"), pré-remplis avec les valeurs actuelles.
struct SettingsControls {
    controls: Vec<HWND>,
    reminder_pro_badge: HWND,
    chk_reminder_enabled: HWND,
    updown_reminder_hours: HWND,
    radio_theme_blue: HWND,
    radio_theme_green: HWND,
    edit_export_path: HWND,
}

unsafe fn create_settings_tab(hwnd: HWND, hinstance: HINSTANCE, font: HFONT) -> Result<SettingsControls> {
    let cfg = settings::load_settings();
    let x0 = MARGIN;
    let y0 = HEADER_H + TAB_BAR_H + MARGIN;
    let mut controls = Vec::new();

    macro_rules! label {
        ($text:expr, $x:expr, $y:expr, $w:expr, $h:expr) => {{
            let h_ = create_child(
                hwnd,
                hinstance,
                ChildSpec { class: w!("STATIC"), text: $text, style: WINDOW_STYLE(0), x: $x, y: $y, w: $w, h: $h, id: 0 },
            )?;
            SendMessageW(h_, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
            controls.push(h_);
            h_
        }};
    }

    label!(t("settings.title"), x0, y0, 400, 30);
    let security_section = format!("── {} ──", t("settings.security"));
    label!(security_section.as_str(), x0, y0 + 40, 400, 20);

    let reminder_text = format!("{} {}", t("settings.reminder"), t("settings.enabled"));
    let chk_reminder_enabled = create_child(
        hwnd,
        hinstance,
        ChildSpec {
            class: w!("BUTTON"),
            text: &reminder_text,
            style: WINDOW_STYLE(BS_AUTOCHECKBOX as u32) | WS_TABSTOP,
            x: x0,
            y: y0 + 70,
            w: 220,
            h: 24,
            id: ID_CHK_REMINDER_ENABLED,
        },
    )?;
    SendMessageW(chk_reminder_enabled, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    SendMessageW(
        chk_reminder_enabled,
        BM_SETCHECK,
        WPARAM(if cfg.security_reminder_enabled { BST_CHECKED.0 } else { BST_UNCHECKED.0 } as usize),
        LPARAM(0),
    );
    controls.push(chk_reminder_enabled);

    label!(t("settings.delay"), x0 + 230, y0 + 70, 50, 24);
    let (edit_reminder_hours, updown_reminder_hours) = create_spinbox(
        hwnd, hinstance, x0 + 285, y0 + 70, 50, 24, ID_EDIT_REMINDER_HOURS, 1, 72,
        cfg.security_reminder_hours as i32,
    )?;
    SendMessageW(edit_reminder_hours, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    controls.push(edit_reminder_hours);
    // Seul le contrôle up-down est relu au moment de sauvegarder
    // (`UDM_GETPOS32`) : l'EDIT jumelé n'a pas besoin d'être conservé.
    controls.push(updown_reminder_hours);
    label!(t("settings.hours"), x0 + 355, y0 + 70, 80, 24);
    // Rappel de sécurité réservé au Pro : badge vidé une fois Pro activé
    // (voir `apply_license_status`).
    let reminder_pro_badge = label!(t("license.pro_only"), x0 + 440, y0 + 70, 80, 24);

    // Le bouton de changement du Master Password vit dans la section
    // Sécurité : c'est le seul endroit de l'UI d'où `change_master_password`
    // est atteignable (la fonction existait depuis la 0.3.0 mais n'était
    // câblée à rien).
    let btn_change_master = create_child(
        hwnd,
        hinstance,
        ChildSpec {
            class: w!("BUTTON"),
            text: t("settings.change_master"),
            style: WINDOW_STYLE(0) | WS_TABSTOP,
            x: x0,
            y: y0 + 104,
            w: 260,
            h: 28,
            id: ID_BTN_CHANGE_MASTER,
        },
    )?;
    SendMessageW(btn_change_master, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    controls.push(btn_change_master);

    let appearance_section = format!("── {} ──", t("settings.appearance"));
    label!(appearance_section.as_str(), x0, y0 + 148, 400, 20);
    label!(t("settings.theme"), x0, y0 + 178, 70, 24);

    let radio_theme_red = create_child(
        hwnd,
        hinstance,
        ChildSpec {
            class: w!("BUTTON"),
            text: t("settings.theme.red"),
            style: WINDOW_STYLE(BS_AUTORADIOBUTTON as u32) | WS_TABSTOP | WS_GROUP,
            x: x0 + 80,
            y: y0 + 178,
            w: 80,
            h: 24,
            id: ID_RADIO_THEME_RED,
        },
    )?;
    let radio_theme_blue = create_child(
        hwnd,
        hinstance,
        ChildSpec { class: w!("BUTTON"), text: t("settings.theme.blue"), style: WINDOW_STYLE(BS_AUTORADIOBUTTON as u32) | WS_TABSTOP, x: x0 + 170, y: y0 + 178, w: 80, h: 24, id: ID_RADIO_THEME_BLUE },
    )?;
    let radio_theme_green = create_child(
        hwnd,
        hinstance,
        ChildSpec { class: w!("BUTTON"), text: t("settings.theme.green"), style: WINDOW_STYLE(BS_AUTORADIOBUTTON as u32) | WS_TABSTOP, x: x0 + 260, y: y0 + 178, w: 80, h: 24, id: ID_RADIO_THEME_GREEN },
    )?;
    for radio in [radio_theme_red, radio_theme_blue, radio_theme_green] {
        SendMessageW(radio, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
        controls.push(radio);
    }
    let checked_theme = match cfg.theme.as_str() {
        "blue" => radio_theme_blue,
        "green" => radio_theme_green,
        _ => radio_theme_red,
    };
    SendMessageW(checked_theme, BM_SETCHECK, WPARAM(BST_CHECKED.0 as usize), LPARAM(0));

    // Le sélecteur de langue (1.0.0–1.0.1) occupait la ligne suivante : la
    // section Sauvegarde remonte de 34 px depuis son retrait en 1.0.2.
    let backup_section = format!("── {} ──", t("settings.backup"));
    label!(backup_section.as_str(), x0, y0 + 218, 400, 20);
    label!(t("settings.export_path"), x0, y0 + 248, 400, 20);
    let edit_export_path = create_child(
        hwnd,
        hinstance,
        ChildSpec {
            class: w!("EDIT"),
            text: &cfg.recovery_keys_export_path,
            style: WINDOW_STYLE(ES_AUTOHSCROLL as u32) | WS_TABSTOP,
            x: x0,
            y: y0 + 270,
            w: 560,
            h: 26,
            id: ID_EDIT_EXPORT_PATH,
        },
    )?;
    SendMessageW(edit_export_path, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    controls.push(edit_export_path);

    let btn_browse = create_child(
        hwnd,
        hinstance,
        ChildSpec {
            class: w!("BUTTON"),
            text: t("settings.browse"),
            style: WINDOW_STYLE(0),
            x: x0 + 570,
            y: y0 + 270,
            w: 110,
            h: 26,
            id: ID_BTN_BROWSE_EXPORT_PATH,
        },
    )?;
    SendMessageW(btn_browse, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    controls.push(btn_browse);

    let btn_save = create_child(
        hwnd,
        hinstance,
        ChildSpec {
            class: w!("BUTTON"),
            text: t("settings.save"),
            style: WINDOW_STYLE(0),
            x: x0,
            y: y0 + 314,
            w: 160,
            h: 36,
            id: ID_BTN_SAVE_SETTINGS,
        },
    )?;
    SendMessageW(btn_save, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    controls.push(btn_save);

    Ok(SettingsControls {
        controls,
        reminder_pro_badge,
        chk_reminder_enabled,
        updown_reminder_hours,
        radio_theme_blue,
        radio_theme_green,
        edit_export_path,
    })
}

/// Crée les contrôles (statiques) de l'onglet "À propos".
/// Contrôles de l'onglet À propos, dont ceux de la section licence que
/// `apply_license_status` met à jour.
struct AboutControls {
    controls: Vec<HWND>,
    license_text: HWND,
    license_button: HWND,
}

unsafe fn create_about_tab(hwnd: HWND, hinstance: HINSTANCE, font: HFONT, font_bold: HFONT) -> Result<AboutControls> {
    let x0 = MARGIN;
    let y0 = HEADER_H + TAB_BAR_H + MARGIN;
    let mut controls = Vec::new();

    macro_rules! label {
        ($text:expr, $x:expr, $y:expr, $w:expr, $h:expr, $font:expr) => {{
            let h_ = create_child(
                hwnd,
                hinstance,
                ChildSpec { class: w!("STATIC"), text: $text, style: WINDOW_STYLE(0), x: $x, y: $y, w: $w, h: $h, id: 0 },
            )?;
            SendMessageW(h_, WM_SETFONT, WPARAM($font.0 as usize), LPARAM(1));
            controls.push(h_);
            h_
        }};
    }

    label!("🛡️ SecureVault", x0, y0, 400, 34, font_bold);
    let version_text = t("about.version").replace("{version}", env!("CARGO_PKG_VERSION"));
    label!(version_text.as_str(), x0, y0 + 38, 300, 22, font);

    let sep1 = create_child(hwnd, hinstance, ChildSpec { class: w!("STATIC"), text: "", style: WINDOW_STYLE(0), x: x0, y: y0 + 68, w: 600, h: 1, id: 0 })?;
    controls.push(sep1);

    label!(t("about.description"), x0, y0 + 82, 500, 20, font);
    label!(t("about.developer"), x0, y0 + 106, 500, 20, font);
    label!(t("about.copyright"), x0, y0 + 128, 500, 20, font);

    label!(t("about.docs"), x0, y0 + 164, 300, 20, font);
    let btn_docs = create_child(
        hwnd, hinstance,
        ChildSpec { class: w!("BUTTON"), text: t("about.docs_btn"), style: WINDOW_STYLE(0), x: x0, y: y0 + 186, w: 220, h: 28, id: ID_BTN_OPEN_DOCS },
    )?;
    SendMessageW(btn_docs, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    controls.push(btn_docs);

    label!(t("about.install_dir"), x0, y0 + 224, 300, 20, font);
    let btn_install_dir = create_child(
        hwnd, hinstance,
        ChildSpec { class: w!("BUTTON"), text: t("about.open"), style: WINDOW_STYLE(0), x: x0, y: y0 + 246, w: 120, h: 28, id: ID_BTN_OPEN_INSTALL_DIR },
    )?;
    SendMessageW(btn_install_dir, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    controls.push(btn_install_dir);

    label!(t("about.local_data"), x0, y0 + 284, 400, 20, font);
    label!("%LOCALAPPDATA%\\SecureVault\\", x0, y0 + 304, 400, 20, font);
    let btn_local_data = create_child(
        hwnd, hinstance,
        ChildSpec { class: w!("BUTTON"), text: t("about.open"), style: WINDOW_STYLE(0), x: x0, y: y0 + 328, w: 120, h: 28, id: ID_BTN_OPEN_LOCAL_DATA },
    )?;
    SendMessageW(btn_local_data, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    controls.push(btn_local_data);

    let sep2 = create_child(hwnd, hinstance, ChildSpec { class: w!("STATIC"), text: "", style: WINDOW_STYLE(0), x: x0, y: y0 + 368, w: 600, h: 1, id: 0 })?;
    controls.push(sep2);

    label!(t("about.built_with"), x0, y0 + 382, 400, 20, font);
    label!(t("about.crypto"), x0, y0 + 404, 400, 20, font);

    // Section licence, colonne de droite (entre les deux séparateurs).
    let col = x0 + 430;
    // Même police que les autres intitulés de section de l'onglet
    // (« 📖 Documentation : »…) — la police de titre de 24 px était coupée.
    label!(t("license.about_title"), col, y0 + 82, 320, 22, font);
    // Texte réel posé par `apply_license_status` dès l'ouverture.
    let license_text = label!("", col, y0 + 108, 320, 64, font);
    let license_button = create_child(
        hwnd, hinstance,
        ChildSpec { class: w!("BUTTON"), text: t("license.buy"), style: WINDOW_STYLE(0), x: col, y: y0 + 180, w: 240, h: 30, id: ID_BTN_LICENSE_KEY },
    )?;
    SendMessageW(license_button, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    controls.push(license_button);

    Ok(AboutControls { controls, license_text, license_button })
}

/// Ouvre `path` dans l'Explorateur (dossier) ou l'application associée
/// (fichier), via `ShellExecuteW "open"`. Best-effort : une erreur affiche
/// juste une popup, ne remonte pas plus loin.
unsafe fn open_with_shell(path: &std::path::Path) {
    if !path.exists() {
        ui::show_error(APP_TITLE, &t("error.not_found").replace("{path}", &path.display().to_string()));
        return;
    }
    let path_w = HSTRING::from(path.as_os_str());
    ShellExecuteW(None, w!("open"), &path_w, PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL);
}


/// Ouvre le Centre d'administration SecureVault : liste des fichiers/dossiers
/// protégés (registre JSON), actions de déverrouillage/déchiffrement/retrait,
/// et zone de déverrouillage forcé (Master Password + admin requis). Bloque
/// jusqu'à la fermeture de la fenêtre.
pub fn show() -> Result<()> {
    unsafe {
        // `SHBrowseForFolderW` avec `BIF_NEWDIALOGSTYLE` EXIGE que le thread
        // appelant soit en appartement cloisonné (STA). Sans ça le dialogue
        // de choix de dossier des Paramètres retombe silencieusement sur
        // l'ancien style — ou échoue — selon la machine. Ça marchait jusqu'ici
        // par effet de bord d'une autre initialisation COM, pas par contrat.
        //
        // Le `HRESULT` est ignoré volontairement : `S_FALSE` (déjà initialisé
        // dans ce mode) est un succès, et `RPC_E_CHANGED_MODE` signifie qu'un
        // autre composant a déjà choisi MTA — dans les deux cas on continue.
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);

        let icc = INITCOMMONCONTROLSEX {
            dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES | ICC_UPDOWN_CLASS,
        };
        let _ = InitCommonControlsEx(&icc);
    }

    register_class_once()?;

    let hinstance: HINSTANCE = unsafe { GetModuleHandleW(PCWSTR::null()) }
        .map_err(|e| SecureVaultError::Crypto(format!("GetModuleHandleW échoué: {e}")))?
        .into();

    let window_style = window_style();
    let mut window_rect = RECT { left: 0, top: 0, right: WINDOW_WIDTH, bottom: WINDOW_HEIGHT };
    unsafe {
        let _ = windows::Win32::UI::WindowsAndMessaging::AdjustWindowRectEx(
            &mut window_rect,
            window_style,
            false,
            WINDOW_EX_STYLE(0),
        );
    }
    let outer_w = window_rect.right - window_rect.left;
    let outer_h = window_rect.bottom - window_rect.top;
    let (screen_w, screen_h) = unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
    let x = ((screen_w - outer_w) / 2).max(0);
    let y = ((screen_h - outer_h) / 2).max(0);

    let title = HSTRING::from(t("dashboard.title"));
    let hwnd = unsafe {
        CreateWindowExW(
            // `WS_EX_APPWINDOW` : une `WS_POPUP` n'apparaît pas d'office dans
            // la barre des tâches, alors que c'est la fenêtre principale.
            WS_EX_APPWINDOW,
            CLASS_NAME,
            &title,
            window_style,
            x,
            y,
            outer_w,
            outer_h,
            None,
            None,
            hinstance,
            None,
        )
    }
    .map_err(|e| SecureVaultError::Crypto(format!("création de la fenêtre échouée: {e}")))?;

    let font = unsafe {
        CreateFontW(-theme::FONT_SIZE_PX, 0, 0, 0, FW_NORMAL.0 as i32, 0, 0, 0, 0, 0, 0, 0, 0, &HSTRING::from(theme::FONT_FACE))
    };
    let font_bold = unsafe {
        CreateFontW(-24, 0, 0, 0, FW_BOLD.0 as i32, 0, 0, 0, 0, 0, 0, 0, 0, &HSTRING::from(theme::FONT_FACE))
    };
    let font_small = unsafe {
        CreateFontW(-12, 0, 0, 0, FW_NORMAL.0 as i32, 0, 0, 0, 0, 0, 0, 0, 0, &HSTRING::from(theme::FONT_FACE))
    };
    // Titre du bandeau : 16 px semi-gras (600) — `FW_SEMIBOLD` n'a pas de
    // constante dédiée dans les bindings, c'est simplement le poids 600.
    let font_header = unsafe {
        CreateFontW(-16, 0, 0, 0, 600, 0, 0, 0, 0, 0, 0, 0, 0, &HSTRING::from(theme::FONT_FACE))
    };

    let hwnd_tab_files = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("BUTTON"), text: "", style: WINDOW_STYLE(BS_OWNERDRAW as u32) | WS_TABSTOP, x: 0, y: 0, w: 8, h: TAB_BAR_H, id: ID_TAB_FILES })?
    };
    let hwnd_tab_settings = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("BUTTON"), text: "", style: WINDOW_STYLE(BS_OWNERDRAW as u32) | WS_TABSTOP, x: 0, y: 0, w: 8, h: TAB_BAR_H, id: ID_TAB_SETTINGS })?
    };
    let hwnd_tab_about = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("BUTTON"), text: "", style: WINDOW_STYLE(BS_OWNERDRAW as u32) | WS_TABSTOP, x: 0, y: 0, w: 8, h: TAB_BAR_H, id: ID_TAB_ABOUT })?
    };

    // Créée plus bas, une fois tous les boutons existants.
    let tooltip;

    // Boutons de la barre de titre custom.
    let mut window_buttons = Vec::new();
    for id in [ID_BTN_MINIMIZE, ID_BTN_MAXIMIZE, ID_BTN_CLOSE] {
        window_buttons.push(unsafe {
            create_child(
                hwnd,
                hinstance,
                ChildSpec {
                    class: w!("BUTTON"),
                    text: "",
                    style: WINDOW_STYLE(BS_OWNERDRAW as u32),
                    x: 0,
                    y: 0,
                    w: WINDOW_BTN_W,
                    h: HEADER_H,
                    id,
                },
            )?
        });
    }
    let hwnd_btn_minimize = window_buttons[0];
    let hwnd_btn_maximize = window_buttons[1];
    let hwnd_btn_close = window_buttons[2];


    let hwnd_btn_unlock = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("BUTTON"), text: "", style: WINDOW_STYLE(BS_OWNERDRAW as u32) | WS_TABSTOP, x: 0, y: 0, w: 8, h: 8, id: ID_BTN_UNLOCK })?
    };
    let hwnd_btn_decrypt = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("BUTTON"), text: "", style: WINDOW_STYLE(BS_OWNERDRAW as u32) | WS_TABSTOP, x: 0, y: 0, w: 8, h: 8, id: ID_BTN_DECRYPT })?
    };
    let hwnd_btn_remove = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("BUTTON"), text: "", style: WINDOW_STYLE(BS_OWNERDRAW as u32) | WS_TABSTOP, x: 0, y: 0, w: 8, h: 8, id: ID_BTN_REMOVE })?
    };
    let hwnd_btn_force_one = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("BUTTON"), text: "", style: WINDOW_STYLE(BS_OWNERDRAW as u32) | WS_TABSTOP, x: 0, y: 0, w: 8, h: 8, id: ID_BTN_FORCE_ONE })?
    };
    let hwnd_btn_force_all = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("BUTTON"), text: "", style: WINDOW_STYLE(BS_OWNERDRAW as u32) | WS_TABSTOP, x: 0, y: 0, w: 8, h: 8, id: ID_BTN_FORCE_ALL })?
    };
    let hwnd_btn_export = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("BUTTON"), text: "", style: WINDOW_STYLE(BS_OWNERDRAW as u32) | WS_TABSTOP, x: 0, y: 0, w: 8, h: 8, id: ID_BTN_EXPORT })?
    };
    let hwnd_btn_refresh = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("BUTTON"), text: "", style: WINDOW_STYLE(BS_OWNERDRAW as u32) | WS_TABSTOP, x: 0, y: 0, w: 8, h: 8, id: ID_BTN_REFRESH })?
    };
    let hwnd_btn_lock = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("BUTTON"), text: "", style: WINDOW_STYLE(BS_OWNERDRAW as u32) | WS_TABSTOP, x: 0, y: 0, w: 8, h: 8, id: ID_BTN_LOCK })?
    };
    let hwnd_btn_encrypt = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("BUTTON"), text: "", style: WINDOW_STYLE(BS_OWNERDRAW as u32) | WS_TABSTOP, x: 0, y: 0, w: 8, h: 8, id: ID_BTN_ENCRYPT })?
    };

    let hwnd_listview = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            WC_LISTVIEWW,
            &HSTRING::new(),
            WS_CHILD | WS_VISIBLE | WINDOW_STYLE(LVS_REPORT),
            0,
            0,
            8,
            8,
            hwnd,
            None,
            hinstance,
            None,
        )
    }
    .map_err(|e| SecureVaultError::Crypto(format!("création de la ListView échouée: {e}")))?;

    unsafe {
        let _ = SetWindowTheme(hwnd_listview, w!(""), w!(""));
        SendMessageW(
            hwnd_listview,
            windows::Win32::UI::Controls::LVM_SETEXTENDEDLISTVIEWSTYLE,
            WPARAM(LVS_EX_FULLROWSELECT as usize),
            LPARAM(LVS_EX_FULLROWSELECT as isize),
        );
        SendMessageW(hwnd_listview, windows::Win32::UI::Controls::LVM_SETBKCOLOR, WPARAM(0), LPARAM(CARD_BG as isize));
        SendMessageW(hwnd_listview, windows::Win32::UI::Controls::LVM_SETTEXTBKCOLOR, WPARAM(0), LPARAM(CARD_BG as isize));
        SendMessageW(hwnd_listview, windows::Win32::UI::Controls::LVM_SETTEXTCOLOR, WPARAM(0), LPARAM(theme::COLOR_TEXT as isize));

        insert_lv_column(hwnd_listview, 0, t("dashboard.col.name"), 200);
        insert_lv_column(hwnd_listview, 1, t("dashboard.col.path"), 250);
        insert_lv_column(hwnd_listview, 2, t("dashboard.col.mode"), 80);
        insert_lv_column(hwnd_listview, 3, t("dashboard.col.date"), 100);
        insert_lv_column(hwnd_listview, 4, t("dashboard.col.status"), 80);
    }

    let hwnd_header = unsafe {
        HWND(SendMessageW(hwnd_listview, windows::Win32::UI::Controls::LVM_GETHEADER, WPARAM(0), LPARAM(0)).0 as *mut c_void)
    };
    unsafe {
        subclass_header(hwnd_header);
        subclass_listview(hwnd_listview);
    }

    let settings_controls = unsafe { create_settings_tab(hwnd, hinstance, font)? };
    let about_controls = unsafe { create_about_tab(hwnd, hinstance, font, font_bold)? };

    unsafe {
        for child in [
            hwnd_btn_unlock, hwnd_btn_decrypt, hwnd_btn_remove, hwnd_btn_force_one, hwnd_btn_force_all,
            hwnd_btn_export, hwnd_btn_refresh, hwnd_btn_lock, hwnd_btn_encrypt,
            hwnd_tab_files, hwnd_tab_settings, hwnd_tab_about,
        ] {
            SendMessageW(child, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
        }

        // Survol/appui : les `BS_OWNERDRAW` ne reçoivent pas d'état de Windows.
        for child in [
            hwnd_btn_unlock, hwnd_btn_decrypt, hwnd_btn_lock, hwnd_btn_encrypt,
            hwnd_btn_remove, hwnd_btn_export, hwnd_btn_refresh,
            hwnd_btn_force_one, hwnd_btn_force_all,
            hwnd_tab_files, hwnd_tab_settings, hwnd_tab_about,
            hwnd_btn_minimize, hwnd_btn_maximize, hwnd_btn_close,
        ] {
            subclass_action_button(child);
        }

        // Infobulles : expliquent ce que fait chaque action AVANT de cliquer,
        // là où les libellés doivent rester courts pour tenir dans le bouton.
        tooltip = create_tooltip(hwnd, hinstance);
        for (control, key) in [
            (hwnd_btn_lock, "tip.lock"),
            (hwnd_btn_unlock, "tip.unlock"),
            (hwnd_btn_encrypt, "tip.encrypt"),
            (hwnd_btn_decrypt, "tip.decrypt"),
            (hwnd_btn_remove, "tip.remove"),
            (hwnd_btn_export, "tip.export"),
            (hwnd_btn_refresh, "tip.refresh"),
            (hwnd_btn_force_one, "tip.force"),
            (hwnd_btn_force_all, "tip.force_all"),
        ] {
            add_tooltip(tooltip, hwnd, control, t(key));
        }
        SendMessageW(hwnd_listview, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    }

    let files_tab_controls = vec![
        hwnd_btn_unlock, hwnd_btn_decrypt, hwnd_btn_remove, hwnd_btn_force_one, hwnd_btn_force_all,
        hwnd_btn_export, hwnd_btn_refresh, hwnd_btn_lock, hwnd_btn_encrypt, hwnd_listview,
    ];

    let state = Box::new(DashboardState {
        hwnd_listview,
        card_rects: [RECT::default(); 3],
        force_zone_rect: RECT::default(),
        hwnd_btn_unlock,
        hwnd_btn_decrypt,
        hwnd_btn_remove,
        hwnd_btn_force_one,
        hwnd_btn_force_all,
        hwnd_btn_export,
        hwnd_btn_refresh,
        hwnd_btn_lock,
        hwnd_btn_encrypt,
        hwnd_btn_minimize,
        hwnd_btn_maximize,
        hwnd_btn_close,
        hwnd_tab_files,
        hwnd_tab_settings,
        hwnd_tab_about,
        current_tab: Tab::Files,
        files_tab_controls,
        settings_tab_controls: settings_controls.controls,
        about_tab_controls: about_controls.controls,
        hwnd_chk_reminder_enabled: settings_controls.chk_reminder_enabled,
        hwnd_updown_reminder_hours: settings_controls.updown_reminder_hours,
        hwnd_radio_theme_blue: settings_controls.radio_theme_blue,
        hwnd_radio_theme_green: settings_controls.radio_theme_green,
        hwnd_edit_export_path: settings_controls.edit_export_path,
        font,
        font_bold,
        font_small,
        font_header,
        brush_background: unsafe { CreateSolidBrush(COLORREF(theme::COLOR_BACKGROUND)) },
        brush_card_bg: unsafe { CreateSolidBrush(COLORREF(CARD_BG)) },
        brush_card_border: unsafe { CreateSolidBrush(COLORREF(CARD_BORDER)) },
        entries: Vec::new(),

        card_targets: [0; 3],
        card_progress: 1.0,
        card_hover: [0.0; 3],
        card_hover_target: [0.0; 3],
        tab_indicator_x: 0.0,
        tab_indicator_w: 0.0,
        tab_indicator_from_x: 0.0,
        tab_indicator_from_w: 0.0,
        tab_indicator_progress: 1.0,
        hovered_tab: None,
        hovered_row: -1,
        hovered_button: None,
        pressed_button: None,
        tooltip,
        license: license::status(),
        status_link_rect: Cell::new(RECT::default()),
        hwnd_reminder_pro_badge: settings_controls.reminder_pro_badge,
        hwnd_about_license: about_controls.license_text,
        hwnd_btn_license_key: about_controls.license_button,
    });
    let state_ptr = Box::into_raw(state);

    unsafe {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_ptr as isize);

        let mut rc = RECT::default();
        let _ = GetClientRect(hwnd, &mut rc);
        layout(&mut *state_ptr, rc.right - rc.left, rc.bottom - rc.top);

        // Position initiale de l'indicateur d'onglet : `set_active_tab`
        // n'anime QUE les changements, et l'onglet Fichiers est déjà celui
        // par défaut — sans cette initialisation l'indicateur resterait de
        // largeur nulle jusqu'au premier changement d'onglet.
        let (indicator_x, indicator_w) =
            tab_indicator_geometry(Tab::Files, rc.right - rc.left);
        (*state_ptr).tab_indicator_x = indicator_x;
        (*state_ptr).tab_indicator_w = indicator_w;
        (*state_ptr).tab_indicator_from_x = indicator_x;
        (*state_ptr).tab_indicator_from_w = indicator_w;

        refresh_entries(hwnd, &mut *state_ptr);
        set_active_tab(hwnd, &mut *state_ptr, Tab::Files);

        ui::apply_app_icon(hwnd);
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetFocus(hwnd_listview);

        SetTimer(hwnd, TIMER_SECURITY_CHECK, SECURITY_CHECK_INTERVAL_MS, None);
    }

    unsafe {
        let mut msg = MSG::default();
        loop {
            let ret = GetMessageW(&mut msg, None, 0, 0).0;
            if ret <= 0 {
                break;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        // Après la boucle, pas dans `WM_DESTROY` : à ce moment-là la fenêtre
        // est encore en cours de destruction et des messages continuent d'être
        // distribués, dont certains peuvent toucher COM (shell, ListView).
        CoUninitialize();
    }

    Ok(())
}

#[cfg(test)]
mod license_ui_tests {
    use super::*;
    use crate::license::UsageCounters;

    fn status(locks: u32, encrypts: u32) -> LicenseStatus {
        LicenseStatus {
            pro: false,
            usage: UsageCounters { locks_used: locks, encrypts_used: encrypts },
        }
    }

    #[test]
    fn free_status_bar_shows_counters_and_link() {
        let (text, link) = status_bar_text(&status(12, 1));
        assert!(link, "le lien Passer à Pro doit être proposé en gratuit");
        assert!(text.contains("12/20"), "{text}");
        assert!(text.contains("1/3"), "{text}");
        assert!(!text.contains('{'), "marqueur non remplacé : {text}");
    }

    /// Des compteurs au-delà de la limite (fichier modifié à la main,
    /// ancienne version) ne doivent pas afficher « 25/20 ».
    #[test]
    fn counters_are_capped_at_the_limit() {
        let (text, _) = status_bar_text(&status(25, 9));
        assert!(text.contains("20/20") && text.contains("3/3"), "{text}");
    }

    #[test]
    fn about_text_for_free_shows_usage() {
        let text = about_license_text(&status(12, 1));
        assert!(text.contains("12/20") && text.contains("1/3"), "{text}");
        assert!(!text.contains('{'), "marqueur non remplacé : {text}");
    }
}

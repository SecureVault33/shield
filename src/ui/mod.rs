pub mod gfx;
pub mod license_prompt;
pub mod theme;

use crate::errors::{Result, SecureVaultError};
use std::ffi::c_void;
use std::mem::size_of;
use std::sync::OnceLock;
use zeroize::Zeroizing;

use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::Foundation::{BOOL, COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreatePen, CreateRoundRectRgn, CreateSolidBrush, DeleteObject,
    DrawTextW, EndPaint, FillRect, GradientFill, InvalidateRect, RoundRect, SelectClipRgn,
    SelectObject, SetBkColor, SetBkMode, SetTextColor, DT_CENTER, DT_SINGLELINE, DT_VCENTER,
    DT_LEFT, FW_NORMAL, GRADIENT_FILL_RECT_H, GRADIENT_RECT, HBRUSH, HDC, HFONT, PAINTSTRUCT, PS_NULL,
    TRANSPARENT, TRIVERTEX,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{DRAWITEMSTRUCT, EM_SETPASSWORDCHAR};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SetFocus, TrackMouseEvent, TME_LEAVE, TRACKMOUSEEVENT,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, GetParent,
    GetSystemMetrics, GetWindowLongPtrW, GetWindowTextLengthW, GetWindowTextW, IsDialogMessageW,
    LoadCursorW, PostQuitMessage, RegisterClassW, SendMessageW, SetWindowLongPtrW, SetWindowTextW,
    KillTimer, LoadImageW, SetLayeredWindowAttributes, SetTimer, ShowWindow, TranslateMessage,
    BN_CLICKED,
    BS_OWNERDRAW, CS_HREDRAW, CS_VREDRAW, EN_CHANGE, ES_AUTOHSCROLL, ES_PASSWORD, GWLP_USERDATA,
    GWLP_WNDPROC, HMENU, ICON_BIG, ICON_SMALL, IDC_ARROW, IDYES, IMAGE_ICON, LR_LOADFROMFILE,
    LWA_ALPHA, MSG, MB_ICONERROR, MB_ICONINFORMATION,
    MB_ICONWARNING, MB_OK, MB_YESNO, MessageBoxW, SM_CXSCREEN, SM_CYSCREEN, SW_SHOW, WM_CLOSE,
    WM_COMMAND, WM_CTLCOLORBTN, WM_CTLCOLORDLG, WM_CTLCOLOREDIT, WM_CTLCOLORSTATIC, WM_DESTROY,
    WM_DRAWITEM, WM_ERASEBKGND, WM_KILLFOCUS, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MOUSEMOVE,
    WM_PAINT, WM_SETFOCUS, WM_SETFONT, WM_SETICON, WM_TIMER, WNDCLASSW, WS_CAPTION, WS_CHILD, WS_EX_LAYERED,
    WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE, WINDOW_STYLE,
};

use gfx::{ease_out_cubic, lerp_color as gfx_lerp};

/// `WM_MOUSELEAVE` n'est pas exposé par la crate `windows` (absent des
/// bindings générés) ; valeur stable et documentée depuis `winuser.h`.
const WM_MOUSELEAVE: u32 = 0x02A3;

const CLASS_NAME: PCWSTR = w!("SecureVaultDialogClass");

// --- Animations (0.8.0) -----------------------------------------------------
// Toutes suivent le même schéma : un timer, une progression 0..1 stockée dans
// `DialogState`, et un repaint ciblé sur le seul contrôle concerné.

/// Fondu d'ouverture/fermeture de la fenêtre.
const TIMER_FADE: usize = 1;
const FADE_INTERVAL_MS: u32 = 10;
/// 255 / 15 ≈ 17 pas × 10 ms ≈ 170 ms à l'ouverture.
const FADE_IN_STEP: i32 = 15;
/// Fermeture plus rapide (~100 ms) : faire attendre l'utilisateur APRÈS son
/// clic est bien plus perceptible qu'une apparition progressive.
const FADE_OUT_STEP: i32 = 26;

/// Transition de la bordure des champs au focus (~200 ms à 16 ms/frame).
const TIMER_FOCUS: usize = 2;
const ANIM_INTERVAL_MS: u32 = 16;
const FOCUS_STEP: f32 = 1.0 / 12.0;

/// Barre de force : largeur ET couleur interpolées (~150 ms).
const TIMER_STRENGTH: usize = 3;
const STRENGTH_STEP: f32 = 1.0 / 9.0;

/// Survol du bouton Valider, lissé sur 4 frames au lieu d'un saut brutal.
const TIMER_HOVER: usize = 4;
const HOVER_STEP: f32 = 0.25;

/// Taille de l'icône « incognito » dessinée en GDI.
const ICON_SIZE: i32 = 52;

const ID_LABEL_MAIN: i32 = 100;
const ID_LABEL_PASSWORD: i32 = 101;
const ID_LABEL_CONFIRM: i32 = 102;
const ID_EDIT_PASSWORD: i32 = 103;
const ID_EDIT_CONFIRM: i32 = 104;
const ID_TOGGLE: i32 = 105;
const ID_STRENGTH: i32 = 106;
const ID_ERROR: i32 = 107;
const ID_FRAME_PASSWORD: i32 = 108;
const ID_FRAME_CONFIRM: i32 = 109;
const ID_STRENGTH_LABEL: i32 = 110;
const ID_ICON: i32 = 111;
const ID_SEPARATOR: i32 = 112;
const ID_FRAME_PASSWORD_INNER: i32 = 113;
const ID_FRAME_CONFIRM_INNER: i32 = 114;
const ID_OK: i32 = 1; // IDOK, pour qu'Entrée valide via IsDialogMessageW
const ID_CANCEL: i32 = 2; // IDCANCEL, pour qu'Échap annule via IsDialogMessageW

/// Force estimée d'un mot de passe, en 5 niveaux.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordStrength {
    VeryWeak,
    Weak,
    Medium,
    Strong,
    VeryStrong,
}

impl PasswordStrength {
    pub fn from_password(password: &str) -> Self {
        let len = password.chars().count();
        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());
        let full_mix = has_upper && has_digit && has_special;

        if len >= 16 && full_mix {
            PasswordStrength::VeryStrong
        } else if len >= 12 && full_mix {
            PasswordStrength::Strong
        } else if len >= 8 {
            PasswordStrength::Medium
        } else if len >= 6 {
            PasswordStrength::Weak
        } else {
            PasswordStrength::VeryWeak
        }
    }

    pub fn color(self) -> u32 {
        match self {
            PasswordStrength::VeryWeak => theme::COLOR_STRENGTH_VERY_WEAK,
            PasswordStrength::Weak => theme::COLOR_STRENGTH_WEAK,
            PasswordStrength::Medium => theme::COLOR_STRENGTH_MEDIUM,
            PasswordStrength::Strong => theme::COLOR_STRENGTH_STRONG,
            PasswordStrength::VeryStrong => theme::COLOR_STRENGTH_VERY_STRONG,
        }
    }

    pub fn percent(self) -> i32 {
        match self {
            PasswordStrength::VeryWeak => 20,
            PasswordStrength::Weak => 40,
            PasswordStrength::Medium => 60,
            PasswordStrength::Strong => 80,
            PasswordStrength::VeryStrong => 100,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            PasswordStrength::VeryWeak => crate::i18n::t("strength.very_weak"),
            PasswordStrength::Weak => crate::i18n::t("strength.weak"),
            PasswordStrength::Medium => crate::i18n::t("strength.medium"),
            PasswordStrength::Strong => crate::i18n::t("strength.strong"),
            PasswordStrength::VeryStrong => crate::i18n::t("strength.very_strong"),
        }
    }
}

/// Résultat de la popup mot de passe simple (verrouillage/déverrouillage/déchiffrement).
pub struct PasswordPromptResult {
    pub password: Zeroizing<String>,
}

/// Résultat de la popup avec confirmation (chiffrement).
pub struct PasswordConfirmPromptResult {
    pub password: Zeroizing<String>,
}

/// Fonction de validation appelée quand l'utilisateur clique "Valider" sur la
/// popup simple : si elle retourne `false`, la popup reste ouverte (champ
/// vidé, message d'erreur affiché, focus repris) au lieu de se fermer. Voir
/// `show_password_prompt`.
pub type PasswordValidator = Box<dyn Fn(&str) -> bool>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DialogMode {
    Simple,
    Confirm,
}

/// État partagé du dialogue, stocké via `GWLP_USERDATA` et manipulé par le `WndProc`.
/// Le pointeur brut est possédé par la fonction appelante (`run_dialog`), qui le
/// libère après la boucle de messages : le `WndProc` ne fait que le déréférencer.
struct DialogState {
    mode: DialogMode,
    hwnd_edit_password: HWND,
    hwnd_edit_confirm: HWND,
    hwnd_toggle: HWND,
    hwnd_strength: HWND,
    hwnd_strength_label: HWND,
    hwnd_error: HWND,
    hwnd_frame_password: HWND,
    hwnd_frame_password_inner: HWND,
    hwnd_frame_confirm: HWND,
    hwnd_frame_confirm_inner: HWND,
    hwnd_separator: HWND,
    hwnd_icon: HWND,
    hwnd_ok: HWND,
    font: HFONT,
    icon_font: HFONT,
    brush_background: HBRUSH,
    brush_field: HBRUSH,
    brush_accent: HBRUSH,
    brush_border_inner: HBRUSH,
    brush_separator: HBRUSH,
    brush_strength: HBRUSH,
    password_visible: bool,
    strength: PasswordStrength,
    ok_hovering: bool,

    // --- État d'animation (0.8.0) ---
    /// Opacité courante de la fenêtre (0..255) et sens du fondu.
    fade_alpha: i32,
    fade_closing: bool,
    /// Progression du focus par champ : `[mot de passe, confirmation]`.
    focus_anim: [f32; 2],
    focus_target: [f32; 2],
    /// Brosses de bordure recréées à chaque frame du fondu de focus.
    brush_border: [HBRUSH; 2],
    /// Barre de force : pourcentage et couleur affichés (≠ valeurs cibles
    /// tant que l'animation n'est pas terminée), plus le point de départ de
    /// l'interpolation en cours et sa progression.
    strength_shown_percent: f32,
    strength_shown_color: u32,
    strength_from_percent: f32,
    strength_from_color: u32,
    strength_anim: f32,
    /// Géométrie nécessaire pour échantillonner le dégradé de fond sous
    /// l'icône (voir `background_at`).
    icon_center_y: i32,
    window_height: i32,
    /// Survol du bouton Valider, 0 = repos, 1 = pleinement survolé.
    hover_anim: f32,
    /// Bouton Valider enfoncé (texte décalé + fond assombri).
    ok_pressed: bool,

    accepted: bool,
    result_password: Zeroizing<String>,
    validator: Option<PasswordValidator>,
    /// Textes propres à la variante de popup (voir `PromptTexts`).
    texts: PromptTexts,
}

/// Textes qui varient d'une popup de saisie à l'autre. Le placeholder et le
/// message d'erreur étaient figés sur « mot de passe » ; la popup de
/// déchiffrement accepte aussi une recovery key depuis la 1.0.1 et doit le
/// dire, sans quoi personne ne penserait à l'y coller.
#[derive(Clone, Copy)]
struct PromptTexts {
    placeholder: &'static str,
    wrong: &'static str,
}

impl PromptTexts {
    fn password() -> Self {
        PromptTexts {
            placeholder: crate::i18n::t("password.placeholder"),
            wrong: crate::i18n::t("password.wrong"),
        }
    }
}

/// Applique l'opacité courante à la fenêtre. `WS_EX_LAYERED` est posé à la
/// création : sans lui, `SetLayeredWindowAttributes` échoue silencieusement.
unsafe fn apply_alpha(hwnd: HWND, alpha: i32) {
    let _ = SetLayeredWindowAttributes(
        hwnd,
        COLORREF(0),
        alpha.clamp(0, 255) as u8,
        LWA_ALPHA,
    );
}

/// Démarre la fermeture : fondu de sortie puis `DestroyWindow`.
///
/// Le résultat (`accepted`, mot de passe) est déjà posé dans l'état par
/// l'appelant — la fenêtre est donc logiquement fermée dès maintenant, seul
/// l'affichage s'attarde. Les clics suivants ne peuvent plus rien changer
/// puisque `WM_COMMAND` sort immédiatement quand `fade_closing` est vrai.
unsafe fn begin_close(hwnd: HWND, state: &mut DialogState) {
    if state.fade_closing {
        return;
    }
    state.fade_closing = true;
    SetTimer(hwnd, TIMER_FADE, FADE_INTERVAL_MS, None);
}

/// Fait avancer une progression vers sa cible et indique si elle a bougé.
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

/// Couleur de bordure d'un champ selon sa progression de focus : accent au
/// repos, version plus lumineuse (`accent_end`) une fois actif.
fn focus_border_color(progress: f32) -> u32 {
    gfx_lerp(theme::field_border(), theme::accent_end(), ease_out_cubic(progress))
}

/// Recrée la brosse de bordure d'un champ pour la frame courante.
unsafe fn refresh_border_brush(state: &mut DialogState, index: usize) {
    let color = focus_border_color(state.focus_anim[index]);
    if !state.brush_border[index].is_invalid() {
        let _ = DeleteObject(state.brush_border[index]);
    }
    state.brush_border[index] = CreateSolidBrush(COLORREF(color));
}

/// Couleur du fond de la popup à la hauteur `y` — nécessaire pour que
/// l'icône dessinée en GDI se fonde dans le dégradé (le DC mémoire du
/// suréchantillonnage est opaque, voir `gfx::draw_icon`).
fn background_at(y: i32, total_height: i32) -> u32 {
    let t = (y as f32 / total_height.max(1) as f32).clamp(0.0, 1.0);
    gfx_lerp(theme::COLOR_BACKGROUND, theme::COLOR_BACKGROUND_BOTTOM, t)
}

fn colorref_channels(colorref: u32) -> (u8, u8, u8) {
    (
        (colorref & 0xFF) as u8,
        ((colorref >> 8) & 0xFF) as u8,
        ((colorref >> 16) & 0xFF) as u8,
    )
}

fn lerp_color(from: u32, to: u32, t: f32) -> u32 {
    let (r1, g1, b1) = colorref_channels(from);
    let (r2, g2, b2) = colorref_channels(to);
    let lerp = |a: u8, b: u8| -> u8 { (a as f32 + (b as f32 - a as f32) * t).round() as u8 };
    let (r, g, b) = (lerp(r1, r2), lerp(g1, g2), lerp(b1, b2));
    (b as u32) << 16 | (g as u32) << 8 | r as u32
}

fn get_window_text(hwnd: HWND) -> String {
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

fn set_window_text(hwnd: HWND, text: &str) {
    let wide = HSTRING::from(text);
    unsafe {
        let _ = SetWindowTextW(hwnd, &wide);
    }
}

fn draw_centered_text(hdc: HDC, rect: RECT, text: &str, color: u32, font: HFONT) {
    unsafe {
        let old_font = SelectObject(hdc, font);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, COLORREF(color));
        let mut wide: Vec<u16> = text.encode_utf16().collect();
        let mut rc = rect;
        DrawTextW(
            hdc,
            &mut wide,
            &mut rc,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE,
        );
        SelectObject(hdc, old_font);
    }
}

/// Dessine la barre de force : piste de fond pleine largeur, puis portion
/// remplie en coins arrondis.
///
/// `percent` et `color` sont les valeurs ANIMÉES (voir `TIMER_STRENGTH`), pas
/// celles du niveau courant : la barre glisse vers sa nouvelle taille au lieu
/// de sauter, et la couleur se fond d'un palier au suivant.
unsafe fn draw_strength_bar(hdc: HDC, rc: RECT, percent: f32, color: u32) {
    let track_brush = CreateSolidBrush(COLORREF(theme::COLOR_FIELD_BACKGROUND));
    FillRect(hdc, &rc, track_brush);
    let _ = DeleteObject(track_brush);

    let width = rc.right - rc.left;
    let height = rc.bottom - rc.top;
    let fill_width = (width as f32 * percent.clamp(0.0, 100.0) / 100.0).round() as i32;
    if fill_width <= 0 || height <= 0 {
        return;
    }

    let brush = CreateSolidBrush(COLORREF(color));
    let pen = CreatePen(PS_NULL, 0, COLORREF(0));
    let old_brush = SelectObject(hdc, brush);
    let old_pen = SelectObject(hdc, pen);
    let radius = height;
    let _ = RoundRect(hdc, rc.left, rc.top, rc.left + fill_width, rc.bottom, radius, radius);
    SelectObject(hdc, old_brush);
    SelectObject(hdc, old_pen);
    let _ = DeleteObject(brush);
    let _ = DeleteObject(pen);
}

/// Placeholder grisé du champ mot de passe.
///
/// `EM_SETCUEBANNER` est ignoré par les EDIT en `ES_PASSWORD` sans manifeste
/// common-controls v6 — on le peint donc nous-mêmes après le rendu par défaut.
///
/// Affiché tant que le champ est VIDE, avec ou sans focus : le champ reçoit le
/// focus dès l'ouverture de la popup, donc le masquer au focus reviendrait à
/// ne jamais le montrer.
unsafe fn draw_placeholder(hwnd: HWND, font: HFONT, text: &str) {
    if GetWindowTextLengthW(hwnd) > 0 {
        return;
    }
    let hdc = windows::Win32::Graphics::Gdi::GetDC(hwnd);
    if hdc.is_invalid() {
        return;
    }
    let mut rc = RECT::default();
    let _ = windows::Win32::UI::WindowsAndMessaging::GetClientRect(hwnd, &mut rc);
    // Mêmes marges que le texte réel de l'EDIT, pour que le placeholder ne
    // saute pas au moment où l'utilisateur commence à taper.
    rc.left += 2;
    let old_font = SelectObject(hdc, font);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, COLORREF(theme::COLOR_TEXT_MUTED));
    let mut wide: Vec<u16> = text.encode_utf16().collect();
    DrawTextW(hdc, &mut wide, &mut rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, old_font);
    windows::Win32::Graphics::Gdi::ReleaseDC(hwnd, hdc);
}

/// Dessine un bouton owner-draw : dégradé accent (coins arrondis, plus clair
/// au survol) pour "Valider", fond transparent pour "Annuler", pastille
/// sombre pour le toggle 👁.
unsafe fn draw_button(item: &DRAWITEMSTRUCT, state: &DialogState) {
    let rc = item.rcItem;
    match item.CtlID as i32 {
        ID_OK => {
            // Survol interpolé (0.8.0) : `hover_anim` glisse entre repos et
            // survol sur 4 frames au lieu de basculer d'un coup.
            let t = ease_out_cubic(state.hover_anim);
            let mut start = gfx_lerp(theme::accent_start(), theme::accent_hover_start(), t);
            let mut end = gfx_lerp(theme::accent_end(), theme::accent_hover_end(), t);
            if state.ok_pressed {
                // Effet d'enfoncement : 10 % plus sombre.
                start = gfx::darken(start, 0.10);
                end = gfx::darken(end, 0.10);
            }
            let (r1, g1, b1) = colorref_channels(start);
            let (r2, g2, b2) = colorref_channels(end);

            // Coins arrondis : on limite le dégradé à une région arrondie, le
            // reste du rectangle garde le fond du dialogue (posé juste avant
            // par WM_CTLCOLORBTN), ce qui donne l'illusion de coins arrondis.
            let region = CreateRoundRectRgn(rc.left, rc.top, rc.right + 1, rc.bottom + 1, 12, 12);
            let _ = SelectClipRgn(item.hDC, region);

            let vertices = [
                TRIVERTEX {
                    x: rc.left,
                    y: rc.top,
                    Red: (r1 as u16) << 8,
                    Green: (g1 as u16) << 8,
                    Blue: (b1 as u16) << 8,
                    Alpha: 0,
                },
                TRIVERTEX {
                    x: rc.right,
                    y: rc.bottom,
                    Red: (r2 as u16) << 8,
                    Green: (g2 as u16) << 8,
                    Blue: (b2 as u16) << 8,
                    Alpha: 0,
                },
            ];
            let mesh = [GRADIENT_RECT {
                UpperLeft: 0,
                LowerRight: 1,
            }];
            let _ = GradientFill(
                item.hDC,
                &vertices,
                mesh.as_ptr() as *const c_void,
                1,
                GRADIENT_FILL_RECT_H,
            );

            let _ = SelectClipRgn(item.hDC, windows::Win32::Graphics::Gdi::HRGN::default());
            let _ = DeleteObject(region);

            // Texte décalé de 1 px vers le bas quand le bouton est enfoncé :
            // c'est ce micro-déplacement, plus que l'assombrissement, qui
            // donne la sensation physique d'appui.
            let mut text_rc = rc;
            if state.ok_pressed {
                text_rc.top += 1;
                text_rc.bottom += 1;
            }
            draw_centered_text(
                item.hDC,
                text_rc,
                crate::i18n::t("password.validate"),
                theme::COLOR_WHITE,
                state.font,
            );
        }
        ID_CANCEL => {
            FillRect(item.hDC, &rc, state.brush_background);
            draw_centered_text(item.hDC, rc, crate::i18n::t("password.cancel"), theme::COLOR_TEXT, state.font);
        }
        ID_TOGGLE => {
            FillRect(item.hDC, &rc, state.brush_field);
            let glyph = if state.password_visible {
                "🙈"
            } else {
                "👁"
            };
            draw_centered_text(item.hDC, rc, glyph, theme::COLOR_TEXT, state.font);
        }
        _ => {}
    }
}

/// Repart de la valeur AFFICHÉE, pas de la précédente cible : si l'utilisateur
/// tape vite, l'animation en cours est reprise en route au lieu de sauter.
unsafe fn restart_strength_animation(hwnd_parent: HWND, state: &mut DialogState) {
    state.strength_from_percent = state.strength_shown_percent;
    state.strength_from_color = state.strength_shown_color;
    state.strength_anim = 0.0;
    SetTimer(hwnd_parent, TIMER_STRENGTH, ANIM_INTERVAL_MS, None);
}

unsafe fn compute_strength_and_apply(hwnd_parent: HWND, state: &mut DialogState) {
    let password = get_window_text(state.hwnd_edit_password);
    let previous = state.strength;
    state.strength = PasswordStrength::from_password(&password);
    set_window_text(state.hwnd_strength_label, state.strength.label());

    // N'animer que si le niveau change réellement : sinon chaque frappe
    // relancerait un timer pour aboutir à la même image.
    if previous != state.strength {
        restart_strength_animation(hwnd_parent, state);
    }

    let _ = InvalidateRect(state.hwnd_strength, None, BOOL(1));
    let _ = InvalidateRect(state.hwnd_strength_label, None, BOOL(1));
}

/// Sous-classe un contrôle enfant : la procédure d'origine est conservée
/// dans son propre `GWLP_USERDATA` (chaque HWND a son slot indépendant, donc
/// ceci ne rentre pas en conflit avec le `DialogState` stocké sur la
/// fenêtre PARENTE). Utilisé pour la barre de force (peinture personnalisée)
/// et le bouton Valider (détection du survol souris).
unsafe fn subclass_child(hwnd: HWND) {
    let old = SetWindowLongPtrW(hwnd, GWLP_WNDPROC, child_subclass_proc as *const () as usize as isize);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, old);
}

unsafe extern "system" fn child_subclass_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let parent = GetParent(hwnd).unwrap_or_default();
    let state_ptr = GetWindowLongPtrW(parent, GWLP_USERDATA) as *mut DialogState;

    if !state_ptr.is_null() {
        let state = &mut *state_ptr;

        if hwnd == state.hwnd_strength && msg == WM_PAINT {
            let mut ps = PAINTSTRUCT::default();
            let hdc = BeginPaint(hwnd, &mut ps);
            let mut rc = RECT::default();
            let _ = windows::Win32::UI::WindowsAndMessaging::GetClientRect(hwnd, &mut rc);
            draw_strength_bar(hdc, rc, state.strength_shown_percent, state.strength_shown_color);
            let _ = EndPaint(hwnd, &ps);
            return LRESULT(0);
        }

        // Icône « incognito » : dessin GDI suréchantillonné (voir `gfx`) à la
        // place de l'emoji 🕵️, dont le rendu dépendait de la police emoji
        // installée et détonnait avec le reste de l'interface.
        if hwnd == state.hwnd_icon && msg == WM_PAINT {
            let mut ps = PAINTSTRUCT::default();
            let hdc = BeginPaint(hwnd, &mut ps);
            let mut rc = RECT::default();
            let _ = windows::Win32::UI::WindowsAndMessaging::GetClientRect(hwnd, &mut rc);
            let background = background_at(state.icon_center_y, state.window_height);
            gfx::fill_rect(hdc, rc, background);
            gfx::draw_icon(hdc, rc, gfx::Icon::Detective, theme::COLOR_ICON, background);
            let _ = EndPaint(hwnd, &ps);
            return LRESULT(0);
        }

        // Bordure animée des champs : le focus fait glisser la couleur de
        // `accent_start` vers `accent_end` (et inversement au blur).
        let field_index = if hwnd == state.hwnd_edit_password {
            Some(0usize)
        } else if !state.hwnd_edit_confirm.is_invalid() && hwnd == state.hwnd_edit_confirm {
            Some(1usize)
        } else {
            None
        };
        if let Some(index) = field_index {
            match msg {
                WM_SETFOCUS | WM_KILLFOCUS => {
                    state.focus_target[index] = if msg == WM_SETFOCUS { 1.0 } else { 0.0 };
                    SetTimer(parent, TIMER_FOCUS, ANIM_INTERVAL_MS, None);
                    // Le placeholder n'est visible que sans focus : repeindre.
                    let _ = InvalidateRect(hwnd, None, BOOL(1));
                }
                WM_PAINT => {
                    // Laisser l'EDIT se peindre, PUIS superposer le
                    // placeholder — l'inverse serait effacé aussitôt.
                    let old_proc = GetWindowLongPtrW(hwnd, GWLP_USERDATA);
                    let result = if old_proc != 0 {
                        let f: unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT =
                            std::mem::transmute(old_proc);
                        f(hwnd, msg, wparam, lparam)
                    } else {
                        DefWindowProcW(hwnd, msg, wparam, lparam)
                    };
                    if index == 0 {
                        draw_placeholder(hwnd, state.font, state.texts.placeholder);
                    }
                    return result;
                }
                _ => {}
            }
        }

        if hwnd == state.hwnd_ok {
            match msg {
                WM_MOUSEMOVE if !state.ok_hovering => {
                    state.ok_hovering = true;
                    let mut tme = TRACKMOUSEEVENT {
                        cbSize: size_of::<TRACKMOUSEEVENT>() as u32,
                        dwFlags: TME_LEAVE,
                        hwndTrack: hwnd,
                        dwHoverTime: 0,
                    };
                    let _ = TrackMouseEvent(&mut tme);
                    SetTimer(parent, TIMER_HOVER, ANIM_INTERVAL_MS, None);
                }
                WM_MOUSELEAVE => {
                    state.ok_hovering = false;
                    // Un bouton relâché hors de sa surface ne doit pas rester
                    // visuellement enfoncé.
                    state.ok_pressed = false;
                    SetTimer(parent, TIMER_HOVER, ANIM_INTERVAL_MS, None);
                    let _ = InvalidateRect(hwnd, None, BOOL(1));
                }
                WM_LBUTTONDOWN => {
                    state.ok_pressed = true;
                    let _ = InvalidateRect(hwnd, None, BOOL(1));
                }
                WM_LBUTTONUP => {
                    // Retour instantané, sans animation : l'utilisateur vient
                    // d'agir, tout délai passerait pour de la latence.
                    state.ok_pressed = false;
                    let _ = InvalidateRect(hwnd, None, BOOL(1));
                }
                _ => {}
            }
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

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let state_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut DialogState;

    match msg {
        WM_ERASEBKGND | WM_CTLCOLORDLG => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let hdc = HDC(wparam.0 as *mut c_void);
            let mut rc = RECT::default();
            let _ = windows::Win32::UI::WindowsAndMessaging::GetClientRect(hwnd, &mut rc);

            // Dégradé vertical subtil (haut -> bas), peint par bandes fines.
            const BAND: i32 = 3;
            let height = (rc.bottom - rc.top).max(1);
            let mut y = rc.top;
            while y < rc.bottom {
                let t = (y - rc.top) as f32 / height as f32;
                let color = lerp_color(theme::COLOR_BACKGROUND, theme::COLOR_BACKGROUND_BOTTOM, t);
                let band = RECT {
                    left: rc.left,
                    top: y,
                    right: rc.right,
                    bottom: (y + BAND).min(rc.bottom),
                };
                let brush = CreateSolidBrush(COLORREF(color));
                FillRect(hdc, &band, brush);
                let _ = DeleteObject(brush);
                y += BAND;
            }
            LRESULT(1)
        }
        WM_CTLCOLOREDIT => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &*state_ptr;
            let hdc = HDC(wparam.0 as *mut c_void);
            SetTextColor(hdc, COLORREF(theme::COLOR_TEXT));
            SetBkColor(hdc, COLORREF(theme::COLOR_FIELD_BACKGROUND));
            LRESULT(state.brush_field.0 as isize)
        }
        WM_CTLCOLORSTATIC => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &*state_ptr;
            let hdc = HDC(wparam.0 as *mut c_void);
            let ctrl = HWND(lparam.0 as *mut c_void);

            // Bordure animée : la brosse est recréée à chaque frame du fondu
            // de focus (voir `TIMER_FOCUS`), `brush_accent` ne sert plus que
            // de repli avant la première frame.
            if ctrl == state.hwnd_frame_password {
                let color = focus_border_color(state.focus_anim[0]);
                SetBkColor(hdc, COLORREF(color));
                if !state.brush_border[0].is_invalid() {
                    return LRESULT(state.brush_border[0].0 as isize);
                }
                return LRESULT(state.brush_accent.0 as isize);
            }
            if ctrl == state.hwnd_frame_confirm {
                let color = focus_border_color(state.focus_anim[1]);
                SetBkColor(hdc, COLORREF(color));
                if !state.brush_border[1].is_invalid() {
                    return LRESULT(state.brush_border[1].0 as isize);
                }
                return LRESULT(state.brush_accent.0 as isize);
            }
            if ctrl == state.hwnd_frame_password_inner || ctrl == state.hwnd_frame_confirm_inner {
                SetBkColor(hdc, COLORREF(theme::COLOR_FIELD_BORDER_INNER));
                return LRESULT(state.brush_border_inner.0 as isize);
            }
            if ctrl == state.hwnd_separator {
                SetBkColor(hdc, COLORREF(theme::COLOR_SEPARATOR));
                return LRESULT(state.brush_separator.0 as isize);
            }
            if ctrl == state.hwnd_strength_label {
                SetTextColor(hdc, COLORREF(state.strength.color()));
                SetBkColor(hdc, COLORREF(theme::COLOR_BACKGROUND));
                return LRESULT(state.brush_background.0 as isize);
            }
            if ctrl == state.hwnd_icon {
                SetTextColor(hdc, COLORREF(theme::COLOR_ICON));
                SetBkColor(hdc, COLORREF(theme::COLOR_BACKGROUND));
                return LRESULT(state.brush_background.0 as isize);
            }
            if ctrl == state.hwnd_error {
                SetTextColor(hdc, COLORREF(theme::COLOR_ERROR));
                SetBkColor(hdc, COLORREF(theme::COLOR_BACKGROUND));
                return LRESULT(state.brush_background.0 as isize);
            }
            SetTextColor(hdc, COLORREF(theme::COLOR_TEXT));
            SetBkColor(hdc, COLORREF(theme::COLOR_BACKGROUND));
            LRESULT(state.brush_background.0 as isize)
        }
        WM_CTLCOLORBTN => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &*state_ptr;
            LRESULT(state.brush_background.0 as isize)
        }
        WM_DRAWITEM => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &*state_ptr;
            let item = &*(lparam.0 as *const DRAWITEMSTRUCT);
            draw_button(item, state);
            LRESULT(1)
        }
        WM_COMMAND => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &mut *state_ptr;
            // La fenêtre s'efface déjà : le résultat est figé, plus rien ne
            // doit pouvoir le modifier.
            if state.fade_closing {
                return LRESULT(0);
            }
            let control_id = (wparam.0 & 0xFFFF) as i32;
            let notify_code = ((wparam.0 >> 16) & 0xFFFF) as u32;

            match control_id {
                ID_TOGGLE if notify_code == BN_CLICKED => {
                    state.password_visible = !state.password_visible;
                    let ch: u16 = if state.password_visible { 0 } else { b'*' as u16 };
                    SendMessageW(
                        state.hwnd_edit_password,
                        EM_SETPASSWORDCHAR,
                        WPARAM(ch as usize),
                        LPARAM(0),
                    );
                    if !state.hwnd_edit_confirm.is_invalid() {
                        SendMessageW(
                            state.hwnd_edit_confirm,
                            EM_SETPASSWORDCHAR,
                            WPARAM(ch as usize),
                            LPARAM(0),
                        );
                        let _ = InvalidateRect(state.hwnd_edit_confirm, None, BOOL(1));
                    }
                    let _ = InvalidateRect(state.hwnd_edit_password, None, BOOL(1));
                    let _ = InvalidateRect(state.hwnd_toggle, None, BOOL(1));
                }
                ID_EDIT_PASSWORD if notify_code == EN_CHANGE => {
                    if state.mode == DialogMode::Confirm {
                        compute_strength_and_apply(hwnd, state);
                    } else if !state.hwnd_error.is_invalid() {
                        // On efface le message "mot de passe incorrect" dès
                        // que l'utilisateur retape quelque chose.
                        set_window_text(state.hwnd_error, "");
                    }
                }
                ID_OK if notify_code == BN_CLICKED => {
                    let password = get_window_text(state.hwnd_edit_password);

                    if password.is_empty() {
                        if !state.hwnd_error.is_invalid() {
                            set_window_text(state.hwnd_error, crate::i18n::t("password.empty"));
                        }
                        return LRESULT(0);
                    }

                    if state.mode == DialogMode::Confirm {
                        let confirm = get_window_text(state.hwnd_edit_confirm);
                        if confirm != password {
                            set_window_text(
                                state.hwnd_error,
                                crate::i18n::t("password.mismatch"),
                            );
                            return LRESULT(0);
                        }
                    }

                    if let Some(validator) = &state.validator {
                        if !validator(&password) {
                            // Vider le champ D'ABORD : `SetWindowTextW` sur
                            // l'edit déclenche un EN_CHANGE synchrone, qui
                            // efface le message d'erreur (voir le bloc
                            // ID_EDIT_PASSWORD ci-dessus) — le message ne
                            // doit donc être posé qu'APRÈS, sans quoi il
                            // s'efface lui-même aussitôt affiché.
                            set_window_text(state.hwnd_edit_password, "");
                            set_window_text(state.hwnd_error, state.texts.wrong);
                            let _ = SetFocus(state.hwnd_edit_password);
                            return LRESULT(0);
                        }
                    }

                    state.result_password = Zeroizing::new(password);
                    state.accepted = true;
                    begin_close(hwnd, state);
                }
                ID_CANCEL if notify_code == BN_CLICKED => {
                    state.accepted = false;
                    begin_close(hwnd, state);
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_TIMER => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &mut *state_ptr;
            match wparam.0 {
                TIMER_FADE => {
                    if state.fade_closing {
                        state.fade_alpha -= FADE_OUT_STEP;
                        if state.fade_alpha <= 0 {
                            let _ = KillTimer(hwnd, TIMER_FADE);
                            let _ = DestroyWindow(hwnd);
                            return LRESULT(0);
                        }
                    } else {
                        state.fade_alpha += FADE_IN_STEP;
                        if state.fade_alpha >= 255 {
                            state.fade_alpha = 255;
                            let _ = KillTimer(hwnd, TIMER_FADE);
                        }
                    }
                    apply_alpha(hwnd, state.fade_alpha);
                }
                TIMER_FOCUS => {
                    let mut moving = false;
                    for index in 0..2 {
                        let target = state.focus_target[index];
                        let mut current = state.focus_anim[index];
                        if step_towards(&mut current, target, FOCUS_STEP) {
                            state.focus_anim[index] = current;
                            refresh_border_brush(state, index);
                            moving = true;
                        }
                    }
                    if moving {
                        let _ = InvalidateRect(state.hwnd_frame_password, None, BOOL(1));
                        if !state.hwnd_frame_confirm.is_invalid() {
                            let _ = InvalidateRect(state.hwnd_frame_confirm, None, BOOL(1));
                        }
                    } else {
                        let _ = KillTimer(hwnd, TIMER_FOCUS);
                    }
                }
                TIMER_STRENGTH => {
                    let target_percent = state.strength.percent() as f32;
                    let target_color = state.strength.color();
                    let mut progress = state.strength_anim;
                    if step_towards(&mut progress, 1.0, STRENGTH_STEP) {
                        state.strength_anim = progress;
                        let t = ease_out_cubic(progress);
                        state.strength_shown_percent =
                            state.strength_from_percent + (target_percent - state.strength_from_percent) * t;
                        state.strength_shown_color =
                            gfx_lerp(state.strength_from_color, target_color, t);
                        let _ = InvalidateRect(state.hwnd_strength, None, BOOL(1));
                    } else {
                        state.strength_shown_percent = target_percent;
                        state.strength_shown_color = target_color;
                        let _ = InvalidateRect(state.hwnd_strength, None, BOOL(1));
                        let _ = KillTimer(hwnd, TIMER_STRENGTH);
                    }
                }
                TIMER_HOVER => {
                    let target = if state.ok_hovering { 1.0 } else { 0.0 };
                    let mut current = state.hover_anim;
                    if step_towards(&mut current, target, HOVER_STEP) {
                        state.hover_anim = current;
                        let _ = InvalidateRect(state.hwnd_ok, None, BOOL(1));
                    } else {
                        let _ = KillTimer(hwnd, TIMER_HOVER);
                    }
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            if !state_ptr.is_null() {
                let state = &mut *state_ptr;
                state.accepted = false;
                begin_close(hwnd, state);
            } else {
                let _ = DestroyWindow(hwnd);
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            if !state_ptr.is_null() {
                let state = &*state_ptr;
                let _ = DeleteObject(state.font);
                let _ = DeleteObject(state.icon_font);
                let _ = DeleteObject(state.brush_background);
                let _ = DeleteObject(state.brush_field);
                let _ = DeleteObject(state.brush_accent);
                let _ = DeleteObject(state.brush_border_inner);
                let _ = DeleteObject(state.brush_separator);
                if !state.brush_strength.is_invalid() {
                    let _ = DeleteObject(state.brush_strength);
                }
                for brush in state.brush_border {
                    if !brush.is_invalid() {
                        let _ = DeleteObject(brush);
                    }
                }
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
    // `OnceLock` plutôt que `static mut` : voir la note identique dans
    // `dashboard::window::register_class_once`.
    static REGISTER_OK: OnceLock<bool> = OnceLock::new();

    unsafe {
        REGISTER.call_once(|| {
            let hinstance = match GetModuleHandleW(PCWSTR::null()) {
                Ok(h) => windows::Win32::Foundation::HINSTANCE::from(h),
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
                "impossible d'enregistrer la classe de fenêtre Win32".into(),
            ))
        }
    }
}

struct ChildSpec<'a> {
    class: PCWSTR,
    text: &'a str,
    style: WINDOW_STYLE,
    ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: i32,
}

unsafe fn create_child(
    parent: HWND,
    hinstance: windows::Win32::Foundation::HINSTANCE,
    spec: ChildSpec<'_>,
) -> Result<HWND> {
    let text = HSTRING::from(spec.text);
    CreateWindowExW(
        spec.ex_style,
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


/// Applique l'icône de l'application à une fenêtre (barre des tâches et
/// Alt+Tab). Sans effet si l'icône n'a pas encore été générée — voir
/// `registry::app_icon_path`.
pub unsafe fn apply_app_icon(hwnd: HWND) {
    let Some(path) = crate::registry::app_icon_path() else {
        return;
    };
    let wide = HSTRING::from(path.as_os_str());
    // Deux tailles distinctes : Windows ne redimensionne pas correctement une
    // grande icône vers 16 px, le rendu de la barre de titre en pâtirait.
    for (size, which) in [(16, ICON_SMALL), (32, ICON_BIG)] {
        if let Ok(handle) = LoadImageW(
            None,
            &wide,
            IMAGE_ICON,
            size,
            size,
            LR_LOADFROMFILE,
        ) {
            SendMessageW(hwnd, WM_SETICON, WPARAM(which as usize), LPARAM(handle.0 as isize));
        }
    }
}

/// Décalage vertical ajouté à toute la mise en page "historique" pour faire
/// de la place à l'icône + séparateur ajoutés en haut de la popup.
const TOP_OFFSET: i32 = 48;

/// Affiche une popup mot de passe (thème sombre/rouge) et bloque jusqu'à ce
/// que l'utilisateur valide ou annule. `label` est le texte affiché
/// au-dessus du champ (ex: "Entrez le mot de passe pour déverrouiller").
/// `validator`, s'il est fourni, est appelé avec le mot de passe saisi
/// quand l'utilisateur clique "Valider" (mode `Simple` uniquement) : s'il
/// retourne `false`, la popup reste ouverte pour un nouvel essai.
fn run_dialog(
    title: &str,
    label: &str,
    texts: PromptTexts,
    mode: DialogMode,
    validator: Option<PasswordValidator>,
) -> Result<DialogState> {
    register_class_once()?;

    let hinstance: windows::Win32::Foundation::HINSTANCE =
        unsafe { GetModuleHandleW(PCWSTR::null()) }
            .map_err(|e| SecureVaultError::Crypto(format!("GetModuleHandleW échoué: {e}")))?
            .into();

    let width = theme::WINDOW_WIDTH;
    let height = match mode {
        DialogMode::Simple => theme::WINDOW_HEIGHT_SIMPLE,
        DialogMode::Confirm => theme::WINDOW_HEIGHT_CONFIRM,
    };
    let window_style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU;

    // `CreateWindowExW` prend la taille de la fenêtre *entière* (barre de titre
    // incluse), pas celle de la zone client : on calcule l'ajustement via
    // `AdjustWindowRectEx` pour que `width`x`height` restent la taille réelle
    // de la zone client où sont placés les contrôles.
    let mut window_rect = RECT {
        left: 0,
        top: 0,
        right: width,
        bottom: height,
    };
    unsafe {
        let _ = windows::Win32::UI::WindowsAndMessaging::AdjustWindowRectEx(
            &mut window_rect,
            window_style,
            false,
            WS_EX_LAYERED,
        );
    }
    let outer_width = window_rect.right - window_rect.left;
    let outer_height = window_rect.bottom - window_rect.top;

    let (screen_w, screen_h) = unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
    let x = ((screen_w - outer_width) / 2).max(0);
    let y = ((screen_h - outer_height) / 2).max(0);

    let window_title = HSTRING::from(title);
    let hwnd = unsafe {
        CreateWindowExW(
            // `WS_EX_LAYERED` est indispensable AU MOMENT DE LA CRÉATION :
            // `SetLayeredWindowAttributes` échoue en silence sur une fenêtre
            // qui ne l'a pas (voir `apply_alpha`).
            WS_EX_LAYERED,
            CLASS_NAME,
            &window_title,
            window_style,
            x,
            y,
            outer_width,
            outer_height,
            None,
            None,
            hinstance,
            None,
        )
    }
    .map_err(|e| SecureVaultError::Crypto(format!("création de la fenêtre échouée: {e}")))?;

    let font = unsafe {
        CreateFontW(
            -theme::FONT_SIZE_PX,
            0,
            0,
            0,
            FW_NORMAL.0 as i32,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            &HSTRING::from(theme::FONT_FACE),
        )
    };
    let icon_font = unsafe {
        CreateFontW(
            -theme::ICON_FONT_SIZE_PX,
            0,
            0,
            0,
            FW_NORMAL.0 as i32,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            &HSTRING::from(theme::FONT_FACE),
        )
    };

    let margin = theme::MARGIN;
    let field_w = width - margin * 2;

    // Icône "incognito" : STATIC vide, entièrement peinte par le
    // sous-classement (silhouette GDI, voir `gfx::Icon::Detective`). L'emoji
    // 🕵️ d'origine dépendait de la police emoji du système et détonnait avec
    // le reste de l'interface.
    const ICON_TOP: i32 = 6;
    let hwnd_icon = unsafe {
        create_child(
            hwnd,
            hinstance,
            ChildSpec {
                class: w!("STATIC"),
                text: "",
                style: WINDOW_STYLE(0),
                ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                x: (width - ICON_SIZE) / 2,
                y: ICON_TOP,
                w: ICON_SIZE,
                h: ICON_SIZE,
                id: ID_ICON,
            },
        )?
    };
    let hwnd_separator = unsafe {
        create_child(
            hwnd,
            hinstance,
            ChildSpec {
                class: w!("STATIC"),
                text: "",
                style: WINDOW_STYLE(0),
                ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                x: margin,
                y: 60,
                w: field_w,
                h: 1,
                id: ID_SEPARATOR,
            },
        )?
    };

    // Libellé principal.
    let hwnd_label_main = unsafe {
        create_child(
            hwnd,
            hinstance,
            ChildSpec {
                class: w!("STATIC"),
                text: label,
                // Deux lignes : plusieurs libellés (celui du Master Password
                // notamment) dépassent largement la largeur de la popup et
                // étaient coupés en plein milieu d'une phrase.
                style: WINDOW_STYLE(0),
                ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                x: margin,
                y: 20 + TOP_OFFSET,
                w: field_w,
                h: 40,
                id: ID_LABEL_MAIN,
            },
        )?
    };

    let (label_password_text, frame_password_y, edit_password_y) = match mode {
        DialogMode::Simple => ("", 68 + TOP_OFFSET, 68 + TOP_OFFSET),
        DialogMode::Confirm => (crate::i18n::t("password.label"), 82 + TOP_OFFSET, 82 + TOP_OFFSET),
    };

    if mode == DialogMode::Confirm {
        unsafe {
            create_child(
                hwnd,
                hinstance,
                ChildSpec {
                    class: w!("STATIC"),
                    text: label_password_text,
                    style: WINDOW_STYLE(0),
                    ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                    x: margin,
                    y: 64 + TOP_OFFSET,
                    w: field_w,
                    h: 16,
                    id: ID_LABEL_PASSWORD,
                },
            )?;
        }
    }

    // Triple cadre (bordure double) + champ mot de passe encastré :
    // extérieur (accent rouge, 1px) -> intérieur (#3d3d3d, 1px) -> champ.
    let hwnd_frame_password = unsafe {
        create_child(
            hwnd,
            hinstance,
            ChildSpec {
                class: w!("STATIC"),
                text: "",
                style: WINDOW_STYLE(0),
                ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                x: margin,
                y: frame_password_y,
                w: field_w,
                h: 34,
                id: ID_FRAME_PASSWORD,
            },
        )?
    };
    let hwnd_frame_password_inner = unsafe {
        create_child(
            hwnd,
            hinstance,
            ChildSpec {
                class: w!("STATIC"),
                text: "",
                style: WINDOW_STYLE(0),
                ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                x: margin + 1,
                y: frame_password_y + 1,
                w: field_w - 2,
                h: 32,
                id: ID_FRAME_PASSWORD_INNER,
            },
        )?
    };
    let hwnd_edit_password = unsafe {
        create_child(
            hwnd,
            hinstance,
            ChildSpec {
                class: w!("EDIT"),
                text: "",
                style: WINDOW_STYLE((ES_PASSWORD | ES_AUTOHSCROLL) as u32) | WS_TABSTOP,
                ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                x: margin + 2,
                y: edit_password_y + 2,
                w: field_w - 4 - 36,
                h: 30,
                id: ID_EDIT_PASSWORD,
            },
        )?
    };
    let hwnd_toggle = unsafe {
        create_child(
            hwnd,
            hinstance,
            ChildSpec {
                class: w!("BUTTON"),
                text: "",
                style: WINDOW_STYLE(BS_OWNERDRAW as u32) | WS_TABSTOP,
                ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                x: margin + field_w - 34,
                y: edit_password_y + 2,
                w: 34,
                h: 30,
                id: ID_TOGGLE,
            },
        )?
    };

    let mut hwnd_strength = HWND::default();
    let mut hwnd_strength_label = HWND::default();
    let mut hwnd_frame_confirm = HWND::default();
    let mut hwnd_frame_confirm_inner = HWND::default();
    let mut hwnd_edit_confirm = HWND::default();
    let hwnd_error;

    if mode == DialogMode::Confirm {
        let strength_bar_w = field_w - 90;
        hwnd_strength = unsafe {
            create_child(
                hwnd,
                hinstance,
                ChildSpec {
                    class: w!("STATIC"),
                    text: "",
                    style: WINDOW_STYLE(0),
                    ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                    x: margin,
                    y: 120 + TOP_OFFSET,
                    w: strength_bar_w,
                    h: 8,
                    id: ID_STRENGTH,
                },
            )?
        };
        hwnd_strength_label = unsafe {
            create_child(
                hwnd,
                hinstance,
                ChildSpec {
                    class: w!("STATIC"),
                    text: PasswordStrength::VeryWeak.label(),
                    style: WINDOW_STYLE(0),
                    ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                    x: margin + strength_bar_w + 10,
                    y: 120 + TOP_OFFSET - 6,
                    w: field_w - strength_bar_w - 10,
                    h: 18,
                    id: ID_STRENGTH_LABEL,
                },
            )?
        };

        unsafe {
            create_child(
                hwnd,
                hinstance,
                ChildSpec {
                    class: w!("STATIC"),
                    text: crate::i18n::t("password.confirm"),
                    style: WINDOW_STYLE(0),
                    ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                    x: margin,
                    y: 136 + TOP_OFFSET,
                    w: field_w,
                    h: 16,
                    id: ID_LABEL_CONFIRM,
                },
            )?;
        }

        hwnd_frame_confirm = unsafe {
            create_child(
                hwnd,
                hinstance,
                ChildSpec {
                    class: w!("STATIC"),
                    text: "",
                    style: WINDOW_STYLE(0),
                    ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                    x: margin,
                    y: 154 + TOP_OFFSET,
                    w: field_w,
                    h: 34,
                    id: ID_FRAME_CONFIRM,
                },
            )?
        };
        hwnd_frame_confirm_inner = unsafe {
            create_child(
                hwnd,
                hinstance,
                ChildSpec {
                    class: w!("STATIC"),
                    text: "",
                    style: WINDOW_STYLE(0),
                    ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                    x: margin + 1,
                    y: 154 + TOP_OFFSET + 1,
                    w: field_w - 2,
                    h: 32,
                    id: ID_FRAME_CONFIRM_INNER,
                },
            )?
        };
        hwnd_edit_confirm = unsafe {
            create_child(
                hwnd,
                hinstance,
                ChildSpec {
                    class: w!("EDIT"),
                    text: "",
                    style: WINDOW_STYLE((ES_PASSWORD | ES_AUTOHSCROLL) as u32) | WS_TABSTOP,
                    ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                    x: margin + 2,
                    y: 156 + TOP_OFFSET,
                    w: field_w - 4,
                    h: 30,
                    id: ID_EDIT_CONFIRM,
                },
            )?
        };

        hwnd_error = unsafe {
            create_child(
                hwnd,
                hinstance,
                ChildSpec {
                    class: w!("STATIC"),
                    text: "",
                    style: WINDOW_STYLE(0),
                    ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                    x: margin,
                    y: 192 + TOP_OFFSET,
                    w: field_w,
                    h: 20,
                    id: ID_ERROR,
                },
            )?
        };
    } else {
        hwnd_error = unsafe {
            create_child(
                hwnd,
                hinstance,
                ChildSpec {
                    class: w!("STATIC"),
                    text: "",
                    style: WINDOW_STYLE(0),
                    ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                    x: margin,
                    y: 110 + TOP_OFFSET,
                    w: field_w,
                    h: 20,
                    id: ID_ERROR,
                },
            )?
        };
    }

    let buttons_y = height - margin - 40;
    let button_w = (field_w - 30) / 2;
    let hwnd_cancel = unsafe {
        create_child(
            hwnd,
            hinstance,
            ChildSpec {
                class: w!("BUTTON"),
                text: "",
                style: WINDOW_STYLE(BS_OWNERDRAW as u32) | WS_TABSTOP,
                ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                x: margin,
                y: buttons_y,
                w: button_w,
                h: 40,
                id: ID_CANCEL,
            },
        )?
    };
    let hwnd_ok = unsafe {
        create_child(
            hwnd,
            hinstance,
            ChildSpec {
                class: w!("BUTTON"),
                text: "",
                style: WINDOW_STYLE(BS_OWNERDRAW as u32) | WS_TABSTOP,
                ex_style: windows::Win32::UI::WindowsAndMessaging::WINDOW_EX_STYLE(0),
                x: margin + button_w + 30,
                y: buttons_y,
                w: button_w,
                h: 40,
                id: ID_OK,
            },
        )?
    };
    let _ = hwnd_cancel;

    // Applique la police à tous les contrôles texte (l'icône garde sa propre
    // grande police, posée séparément juste après).
    unsafe {
        for child in [
            hwnd_label_main,
            hwnd_edit_password,
            hwnd_edit_confirm,
            hwnd_error,
            hwnd_strength_label,
        ] {
            if !child.is_invalid() {
                SendMessageW(child, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
            }
        }
        // Sous-classement : peinture personnalisée de la barre de force et
        // de l'icône, placeholder + bordure animée des champs, survol et
        // enfoncement du bouton Valider.
        //
        // L'état du dialogue n'existe pas encore à ce stade (il est construit
        // juste après) : le `WndProc` sous-classé le teste avant usage, donc
        // les quelques messages qui arrivent d'ici là sont simplement passés
        // au traitement par défaut.
        if !hwnd_strength.is_invalid() {
            subclass_child(hwnd_strength);
        }
        subclass_child(hwnd_ok);
        subclass_child(hwnd_icon);
        subclass_child(hwnd_edit_password);
        if !hwnd_edit_confirm.is_invalid() {
            subclass_child(hwnd_edit_confirm);
        }
    }

    let state = Box::new(DialogState {
        mode,
        hwnd_edit_password,
        hwnd_edit_confirm,
        hwnd_toggle,
        hwnd_strength,
        hwnd_strength_label,
        hwnd_error,
        hwnd_frame_password,
        hwnd_frame_password_inner,
        hwnd_frame_confirm,
        hwnd_frame_confirm_inner,
        hwnd_separator,
        hwnd_icon,
        hwnd_ok,
        font,
        icon_font,
        brush_background: unsafe {
            CreateSolidBrush(COLORREF(theme::COLOR_BACKGROUND))
        },
        brush_field: unsafe {
            CreateSolidBrush(COLORREF(theme::COLOR_FIELD_BACKGROUND))
        },
        brush_accent: unsafe { CreateSolidBrush(COLORREF(theme::field_border())) },
        brush_border_inner: unsafe {
            CreateSolidBrush(COLORREF(theme::COLOR_FIELD_BORDER_INNER))
        },
        brush_separator: unsafe { CreateSolidBrush(COLORREF(theme::COLOR_SEPARATOR)) },
        brush_strength: HBRUSH::default(),
        password_visible: false,
        strength: PasswordStrength::VeryWeak,
        ok_hovering: false,

        fade_alpha: 0,
        fade_closing: false,
        focus_anim: [0.0, 0.0],
        focus_target: [0.0, 0.0],
        brush_border: [HBRUSH::default(), HBRUSH::default()],
        strength_shown_percent: 0.0,
        strength_shown_color: PasswordStrength::VeryWeak.color(),
        strength_from_percent: 0.0,
        strength_from_color: PasswordStrength::VeryWeak.color(),
        strength_anim: 1.0,
        hover_anim: 0.0,
        ok_pressed: false,
        icon_center_y: ICON_TOP + ICON_SIZE / 2,
        window_height: height,

        accepted: false,
        result_password: Zeroizing::new(String::new()),
        validator,
        texts,
    });
    let state_ptr = Box::into_raw(state);

    unsafe {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_ptr as isize);
        // Opacité posée AVANT `ShowWindow` : afficher d'abord puis rendre
        // transparent produirait un flash à pleine opacité sur la première
        // frame.
        apply_app_icon(hwnd);
        apply_alpha(hwnd, 0);
        let _ = ShowWindow(hwnd, SW_SHOW);

        // Filet de sécurité : si le timer ne peut pas être créé, la fenêtre
        // resterait invisible POUR TOUJOURS — l'utilisateur verrait son
        // application se bloquer sans rien afficher. On préfère alors une
        // apparition brutale à pleine opacité.
        if SetTimer(hwnd, TIMER_FADE, FADE_INTERVAL_MS, None) == 0 {
            (*state_ptr).fade_alpha = 255;
            apply_alpha(hwnd, 255);
        }
        let _ = SetFocus(hwnd_edit_password);
    }

    unsafe {
        let mut msg = MSG::default();
        loop {
            let ret = GetMessageW(&mut msg, None, 0, 0).0;
            if ret <= 0 {
                break;
            }
            if IsDialogMessageW(hwnd, &msg).as_bool() {
                continue;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    // La fenêtre est détruite ; on récupère le résultat puis on libère l'état.
    let state = unsafe { Box::from_raw(state_ptr) };
    Ok(*state)
}

/// Affiche la popup Win32 native (thème sombre/rouge) demandant un mot de
/// passe. `validator`, si fourni, est appelé à chaque clic sur "Valider" :
/// s'il retourne `false`, la popup reste ouverte (champ vidé, message
/// d'erreur affiché) pour un nouvel essai au lieu de se fermer.
pub fn show_password_prompt(
    title: &str,
    validator: Option<PasswordValidator>,
) -> Result<PasswordPromptResult> {
    let state = run_dialog(
        title,
        crate::i18n::t("password.enter"),
        PromptTexts::password(),
        DialogMode::Simple,
        validator,
    )?;
    if !state.accepted {
        return Err(SecureVaultError::Cancelled);
    }
    Ok(PasswordPromptResult {
        password: state.result_password,
    })
}

/// Popup de déchiffrement : identique à `show_password_prompt`, mais annonce
/// qu'une recovery key peut être collée à la place du mot de passe
/// (`crypto::decrypt_path` détecte automatiquement lequel des deux a été
/// saisi).
///
/// `legacy` : le `.vault` est au format v1 (≤ 1.0.0), dont la recovery key
/// n'ouvre rien. Proposer de la coller serait mentir ; la popup prévient
/// alors que seul le mot de passe fonctionne.
pub fn show_decrypt_prompt(
    title: &str,
    legacy: bool,
    validator: Option<PasswordValidator>,
) -> Result<PasswordPromptResult> {
    let (label, texts) = if legacy {
        (crate::i18n::t("decrypt.legacy_label"), PromptTexts::password())
    } else {
        (
            crate::i18n::t("decrypt.label"),
            PromptTexts {
                placeholder: crate::i18n::t("decrypt.placeholder"),
                wrong: crate::i18n::t("decrypt.wrong"),
            },
        )
    };
    let state = run_dialog(title, label, texts, DialogMode::Simple, validator)?;
    if !state.accepted {
        return Err(SecureVaultError::Cancelled);
    }
    Ok(PasswordPromptResult {
        password: state.result_password,
    })
}

/// Affiche la popup Win32 native avec champ de confirmation et indicateur de
/// force. `label` est le texte affiché au-dessus du premier champ (adapté à
/// l'action : verrouillage, chiffrement, création du Master Password...).
pub fn show_password_confirm_prompt(title: &str, label: &str) -> Result<PasswordConfirmPromptResult> {
    let state = run_dialog(title, label, PromptTexts::password(), DialogMode::Confirm, None)?;
    if !state.accepted {
        return Err(SecureVaultError::Cancelled);
    }
    Ok(PasswordConfirmPromptResult { password: state.result_password })
}

/// Affiche une popup d'information native (`MessageBoxW`, icône ⓘ, bouton OK).
/// Utilisée pour tout retour utilisateur de `main.rs` : lancé depuis le menu
/// contextuel de l'Explorateur, le process n'a pas de console visible, donc
/// `println!` n'atteint jamais l'utilisateur.
pub fn show_info(title: &str, message: &str) {
    let title_w = HSTRING::from(title);
    let message_w = HSTRING::from(message);
    unsafe {
        MessageBoxW(HWND::default(), &message_w, &title_w, MB_OK | MB_ICONINFORMATION);
    }
}

/// Affiche une popup d'erreur native (`MessageBoxW`, icône ✕, bouton OK).
pub fn show_error(title: &str, message: &str) {
    let title_w = HSTRING::from(title);
    let message_w = HSTRING::from(message);
    unsafe {
        MessageBoxW(HWND::default(), &message_w, &title_w, MB_OK | MB_ICONERROR);
    }
}

/// Affiche une popup de confirmation Oui/Non native. Retourne `true` si
/// l'utilisateur a répondu Oui.
pub fn show_confirm(title: &str, message: &str) -> bool {
    let title_w = HSTRING::from(title);
    let message_w = HSTRING::from(message);
    let result = unsafe {
        MessageBoxW(HWND::default(), &message_w, &title_w, MB_YESNO | MB_ICONWARNING)
    };
    result == IDYES
}

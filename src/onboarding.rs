//! Écran de bienvenue affiché au tout premier lancement (voir `main::run` —
//! déclenché uniquement pour `dashboard`, `install`, ou un lancement sans
//! argument, jamais pour les commandes issues du menu contextuel de
//! l'Explorateur). Trois slides avec navigation Suivant/Précédent, le
//! dernier slide intégrant la création du Master Password.
//!
//! Techniques Win32 reprises de `ui::mod` (fond dégradé, `ChildSpec`/
//! `create_child`, sous-classement pour la barre de force) : ce module est
//! volontairement autonome plutôt que de dépendre des internes privés de
//! `ui::mod`, à l'image de `dashboard::window`.

use crate::dashboard::{master, settings};
use std::sync::OnceLock;

use crate::errors::{Result, SecureVaultError};
use crate::i18n::t;
use crate::ui::gfx;
use crate::ui::theme;
use crate::ui::PasswordStrength;

use std::ffi::c_void;

use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::Foundation::{BOOL, COLORREF, HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreatePen, CreateSolidBrush, DeleteObject, EndPaint, FillRect,
    ClientToScreen, InvalidateRect, RedrawWindow, RoundRect, ScreenToClient, SelectObject,
    RDW_ALLCHILDREN, RDW_ERASE, RDW_INVALIDATE, RDW_UPDATENOW, SetBkColor, SetTextColor, FW_BOLD,
    FW_NORMAL, HBRUSH, HDC, HFONT, PAINTSTRUCT, PS_NULL,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::EM_SETPASSWORDCHAR;
use windows::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    GetClientRect, GetMessageW, GetParent, GetSystemMetrics, GetWindowLongPtrW, GetWindowRect,
    GetDlgCtrlID, GetDlgItem, IsDialogMessageW, KillTimer, LoadCursorW, PostQuitMessage,
    RegisterClassW,
    SendMessageW, SetTimer, SetWindowLongPtrW, SetWindowPos, SetWindowTextW, ShowWindow,
    TranslateMessage, BN_CLICKED, CS_HREDRAW, CS_VREDRAW, EN_CHANGE, ES_AUTOHSCROLL, ES_PASSWORD,
    GWLP_USERDATA, GWLP_WNDPROC, HMENU, IDC_ARROW, MSG, SM_CXSCREEN, SM_CYSCREEN, SWP_NOACTIVATE,
    BeginDeferWindowPos, DeferWindowPos, EndDeferWindowPos, HWND_BOTTOM, SET_WINDOW_POS_FLAGS,
    SWP_NOCOPYBITS, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SW_HIDE, SW_SHOW, SW_SHOWNORMAL, WM_CLOSE, WM_COMMAND,
    WM_CTLCOLORBTN, WM_CTLCOLOREDIT, WM_CTLCOLORSTATIC, WM_DESTROY, WM_ERASEBKGND, WM_PAINT,
    WM_SETFONT, WM_TIMER, WNDCLASSW, WS_CAPTION, WS_CHILD, WS_CLIPCHILDREN, WS_CLIPSIBLINGS,
    WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP,
    WS_VISIBLE, WINDOW_STYLE,
};

const CLASS_NAME: PCWSTR = w!("SecureVaultOnboardingClass");
const WINDOW_WIDTH: i32 = 600;
const WINDOW_HEIGHT: i32 = 450;
const MARGIN: i32 = 30;

/// Transition entre slides : glissement horizontal de 250 ms à ~60 fps.
const TIMER_SLIDE: usize = 1;
const SLIDE_INTERVAL_MS: u32 = 16;
const SLIDE_STEP: f32 = 16.0 / 250.0;

/// Puces de progression, en bas au centre.
const DOT_RADIUS: i32 = 4;
const DOT_SPACING: i32 = 12;
const DOTS_Y: i32 = WINDOW_HEIGHT - MARGIN - 36 - 22;

/// Identifiants des STATIC qui portent les illustrations GDI de chaque slide.
const ID_ILLUSTRATION_1: i32 = 20;
const ID_ILLUSTRATION_2A: i32 = 21;
const ID_ILLUSTRATION_2B: i32 = 22;
const ID_ILLUSTRATION_3: i32 = 23;

const ID_BTN_PREV: i32 = 1;
const ID_BTN_NEXT: i32 = 2;
const ID_EDIT_PASSWORD: i32 = 10;
const ID_EDIT_CONFIRM: i32 = 11;
const ID_TOGGLE: i32 = 12;

struct OnboardingState {
    current_slide: u8,
    slide1_controls: Vec<HWND>,
    slide2_controls: Vec<HWND>,
    slide3_controls: Vec<HWND>,
    /// Position « au repos » (x, y, coordonnées client) de chaque contrôle de
    /// slide, relevée UNE fois juste après la création, avant toute animation.
    ///
    /// Les deux coordonnées sont mémorisées. Jusqu'à la 0.8.0 seule l'abscisse
    /// l'était : l'ordonnée était relue sur la fenêtre à chaque frame
    /// (`GetWindowRect` → `ScreenToClient`). L'application n'étant pas
    /// « DPI-aware », Windows virtualise ses coordonnées sur un écran mis à
    /// l'échelle, et chaque aller-retour écran ↔ client peut arrondir d'un
    /// pixel : l'erreur se cumulait d'une frame et d'une transition à l'autre.
    home: Vec<(HWND, i32, i32)>,
    /// Slide qui sort de l'écran pendant la transition (0 = aucune).
    sliding_from: u8,
    slide_progress: f32,
    /// `true` si l'on avance (le contenu part vers la gauche).
    slide_forward: bool,
    hwnd_btn_prev: HWND,
    hwnd_btn_next: HWND,
    hwnd_edit_password: HWND,
    hwnd_edit_confirm: HWND,
    hwnd_toggle: HWND,
    hwnd_strength: HWND,
    hwnd_strength_label: HWND,
    hwnd_error: HWND,
    password_visible: bool,
    strength: PasswordStrength,
    font: HFONT,
    font_bold: HFONT,
    font_title: HFONT,
    icon_font: HFONT,
    brush_background: HBRUSH,
    brush_field: HBRUSH,
    brush_accent: HBRUSH,
    brush_border_inner: HBRUSH,
    completed: bool,
}

/// Rectangle en coordonnées client (origine en haut à gauche).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rect {
    x: i32,
    y: i32,
    w: i32,
    h: i32,
}

impl Rect {
    fn right(&self) -> i32 {
        self.x + self.w
    }
    #[cfg(test)]
    fn bottom(&self) -> i32 {
        self.y + self.h
    }
    /// `true` si `inner` est entièrement contenu dans `self` (bords compris).
    #[cfg(test)]
    fn contains(&self, inner: &Rect) -> bool {
        inner.x >= self.x
            && inner.y >= self.y
            && inner.right() <= self.right()
            && inner.bottom() <= self.bottom()
    }
    #[cfg(test)]
    fn overlaps(&self, other: &Rect) -> bool {
        self.x < other.right()
            && other.x < self.right()
            && self.y < other.bottom()
            && other.y < self.bottom()
    }
}

/// Hauteur de la zone de saisie d'un champ.
const FIELD_EDIT_H: i32 = 30;
/// Bouton 👁 : carré, exactement de la hauteur de la zone de saisie.
const TOGGLE_W: i32 = FIELD_EDIT_H;

/// Géométrie du slide 3 (création du Master Password).
///
/// Un champ = trois rectangles emboîtés : cadre extérieur (1 px), cadre
/// intérieur (1 px), puis la zone de saisie. Sur le champ mot de passe, la
/// zone de saisie est partagée entre l'EDIT et le bouton 👁, collés l'un à
/// l'autre sans se chevaucher.
///
/// Calculée par une fonction pure plutôt qu'en constantes éparpillées dans les
/// `create_child` : jusqu'à la 0.8.0 le bouton 👁 débordait sur la bordure
/// extérieure, et les champs étaient 40 px plus étroits que le texte au-dessus
/// d'eux. Les tests ci-dessous verrouillent ces invariants.
struct Slide3Layout {
    password_frame: Rect,
    password_inner: Rect,
    password_edit: Rect,
    toggle: Rect,
    confirm_frame: Rect,
    confirm_inner: Rect,
    confirm_edit: Rect,
    strength_bar: Rect,
    strength_label: Rect,
    error: Rect,
}

fn slide3_layout(content_w: i32) -> Slide3Layout {
    // Même largeur que le texte d'introduction : bords gauche ET droit alignés.
    let field_w = content_w;

    let frame = |y: i32| Rect { x: MARGIN, y, w: field_w, h: FIELD_EDIT_H + 4 };
    let inner = |outer: Rect| Rect { x: outer.x + 1, y: outer.y + 1, w: outer.w - 2, h: outer.h - 2 };
    let edit_zone = |outer: Rect| Rect { x: outer.x + 2, y: outer.y + 2, w: outer.w - 4, h: FIELD_EDIT_H };

    let password_frame = frame(135);
    let password_zone = edit_zone(password_frame);
    let toggle = Rect {
        x: password_zone.right() - TOGGLE_W,
        y: password_zone.y,
        w: TOGGLE_W,
        h: FIELD_EDIT_H,
    };
    let password_edit = Rect { w: password_zone.w - TOGGLE_W, ..password_zone };

    let confirm_frame = frame(178);

    const LABEL_W: i32 = 95;
    Slide3Layout {
        password_frame,
        password_inner: inner(password_frame),
        password_edit,
        toggle,
        confirm_frame,
        confirm_inner: inner(confirm_frame),
        confirm_edit: edit_zone(confirm_frame),
        strength_bar: Rect { x: MARGIN, y: 226, w: field_w - LABEL_W - 5, h: 10 },
        strength_label: Rect { x: MARGIN + field_w - LABEL_W, y: 220, w: LABEL_W, h: 20 },
        error: Rect { x: MARGIN, y: 246, w: field_w, h: 24 },
    }
}

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
        Default::default(),
        spec.class,
        &text,
        // `WS_CLIPSIBLINGS` : un contrôle ne peint jamais par-dessus un frère
        // placé au-dessus de lui. Indispensable sur le slide 3 où cadres, champ
        // et bouton 👁 se chevauchent — sans lui l'ordre de peinture dépend
        // de l'ordre d'arrivée des WM_PAINT et le cadre pouvait recouvrir le
        // bouton pendant une transition.
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | spec.style,
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

fn set_window_text(hwnd: HWND, text: &str) {
    let wide = HSTRING::from(text);
    unsafe {
        let _ = SetWindowTextW(hwnd, &wide);
    }
}

unsafe fn draw_strength_bar(hdc: HDC, rc: RECT, strength: PasswordStrength) {
    let track_brush = CreateSolidBrush(COLORREF(theme::COLOR_FIELD_BACKGROUND));
    FillRect(hdc, &rc, track_brush);
    let _ = DeleteObject(track_brush);

    let width = rc.right - rc.left;
    let height = rc.bottom - rc.top;
    let fill_width = width * strength.percent() / 100;
    if fill_width <= 0 || height <= 0 {
        return;
    }

    let brush = CreateSolidBrush(COLORREF(strength.color()));
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

/// Sous-classe la barre de force pour lui donner une peinture personnalisée
/// (même technique que `ui::mod::subclass_child`, dupliquée ici — module
/// autonome).
/// Sous-classe un STATIC d'illustration pour le peindre en GDI.
unsafe fn subclass_illustration(hwnd: HWND) {
    let old = SetWindowLongPtrW(
        hwnd,
        GWLP_WNDPROC,
        illustration_subclass_proc as *const () as usize as isize,
    );
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, old);
}

unsafe extern "system" fn illustration_subclass_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg == WM_PAINT {
        draw_illustration(hwnd, GetDlgCtrlID(hwnd));
        return LRESULT(0);
    }
    let old_proc = GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if old_proc != 0 {
        let f: unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT =
            std::mem::transmute(old_proc);
        return f(hwnd, msg, wparam, lparam);
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

unsafe fn subclass_strength_bar(hwnd: HWND) {
    let old = SetWindowLongPtrW(hwnd, GWLP_WNDPROC, strength_bar_subclass_proc as *const () as usize as isize);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, old);
}

unsafe extern "system" fn strength_bar_subclass_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if msg == WM_PAINT {
        let parent = windows::Win32::UI::WindowsAndMessaging::GetParent(hwnd).unwrap_or_default();
        let state_ptr = GetWindowLongPtrW(parent, GWLP_USERDATA) as *mut OnboardingState;
        if !state_ptr.is_null() {
            let state = &*state_ptr;
            let mut ps = PAINTSTRUCT::default();
            let hdc = BeginPaint(hwnd, &mut ps);
            let mut rc = RECT::default();
            let _ = windows::Win32::UI::WindowsAndMessaging::GetClientRect(hwnd, &mut rc);
            draw_strength_bar(hdc, rc, state.strength);
            let _ = EndPaint(hwnd, &ps);
            return LRESULT(0);
        }
    }
    let old_proc = GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    if old_proc != 0 {
        let f: unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT = std::mem::transmute(old_proc);
        return f(hwnd, msg, wparam, lparam);
    }
    let _ = wparam;
    let _ = lparam;
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

unsafe fn update_strength_display(state: &mut OnboardingState) {
    let password = get_window_text(state.hwnd_edit_password);
    state.strength = PasswordStrength::from_password(&password);
    set_window_text(state.hwnd_strength_label, state.strength.label());
    let _ = windows::Win32::Graphics::Gdi::InvalidateRect(state.hwnd_strength, None, BOOL(1));
}

/// Recalcule si "Commencer" doit être actif : mots de passe non vides et
/// identiques.
unsafe fn update_slide3_validity(state: &OnboardingState) {
    let password = get_window_text(state.hwnd_edit_password);
    let confirm = get_window_text(state.hwnd_edit_confirm);
    let valid = !password.is_empty() && password == confirm;
    let _ = EnableWindow(state.hwnd_btn_next, BOOL::from(valid));
}

/// Illustration d'un slide, dessinée en GDI plutôt qu'en emoji : même
/// raison que dans la popup mot de passe (rendu dépendant de la police, style
/// incohérent avec le reste).
unsafe fn draw_illustration(hwnd: HWND, id: i32) {
    let mut ps = PAINTSTRUCT::default();
    let hdc = BeginPaint(hwnd, &mut ps);
    let mut rc = RECT::default();
    let _ = GetClientRect(hwnd, &mut rc);

    // Les slides sont sur le fond dégradé de la fenêtre : on échantillonne la
    // teinte à la hauteur du contrôle pour que l'icône s'y fonde.
    let mut origin = windows::Win32::Foundation::POINT { x: 0, y: 0 };
    let _ = ClientToScreen(hwnd, &mut origin);
    let parent = GetParent(hwnd).unwrap_or_default();
    let _ = ScreenToClient(parent, &mut origin);
    let t = ((origin.y + (rc.bottom - rc.top) / 2) as f32 / WINDOW_HEIGHT as f32).clamp(0.0, 1.0);
    let background = gfx::lerp_color(theme::COLOR_BACKGROUND, theme::COLOR_BACKGROUND_BOTTOM, t);

    gfx::fill_rect(hdc, rc, background);
    let icon = match id {
        ID_ILLUSTRATION_1 => gfx::Icon::Shield,
        ID_ILLUSTRATION_2A => gfx::Icon::Lock,
        ID_ILLUSTRATION_2B => gfx::Icon::Shield,
        _ => gfx::Icon::Key,
    };
    gfx::draw_icon(hdc, rc, icon, theme::accent_end(), background);

    let _ = EndPaint(hwnd, &ps);
}

/// Trois puces indiquant la position dans le parcours.
unsafe fn draw_progress_dots(hdc: HDC, current: u8) {
    let total = 3i32;
    let span = (total - 1) * (DOT_RADIUS * 2 + DOT_SPACING);
    let start_x = (WINDOW_WIDTH - span) / 2;
    for index in 0..total {
        let cx = start_x + index * (DOT_RADIUS * 2 + DOT_SPACING);
        if index + 1 == current as i32 {
            gfx::fill_circle(hdc, cx, DOTS_Y, DOT_RADIUS, theme::accent_end());
        } else {
            gfx::stroke_circle(hdc, cx, DOTS_Y, DOT_RADIUS, theme::COLOR_DOT_INACTIVE, 1);
        }
    }
}

/// Contrôles d'un slide donné.
fn slide_controls(state: &OnboardingState, slide: u8) -> &Vec<HWND> {
    match slide {
        1 => &state.slide1_controls,
        2 => &state.slide2_controls,
        _ => &state.slide3_controls,
    }
}

/// Position d'un contrôle décalé horizontalement de `dx` depuis son repos.
///
/// Fonction pure et sans état : la position ne dépend QUE du repos mémorisé et
/// du décalage demandé, jamais de la position courante — c'est ce qui garantit
/// l'absence de dérive cumulative (voir `OnboardingState::home`).
fn slid_position(home_x: i32, home_y: i32, dx: i32) -> (i32, i32) {
    (home_x + dx, home_y)
}

/// Repositionne les contrôles d'un slide avec un décalage horizontal.
///
/// Tous les contrôles bougent dans UN seul lot `DeferWindowPos`, avec
/// `SWP_NOCOPYBITS`. Sans ce drapeau, Windows recopie les anciens pixels d'un
/// contrôle déplacé vers sa nouvelle position au lieu de le repeindre. Sur le
/// slide 3, où cadre, cadre intérieur, champ et bouton 👁 se superposent, et
/// déplacés un par un, ces recopies laissaient des images fantômes du bouton
/// (« dupliqué », « débordant sur le champ »), aggravées par l'arrondi de la
/// mise à l'échelle DPI.
unsafe fn offset_slide(state: &OnboardingState, slide: u8, dx: i32) {
    const FLAGS: SET_WINDOW_POS_FLAGS = SET_WINDOW_POS_FLAGS(
        SWP_NOSIZE.0 | SWP_NOZORDER.0 | SWP_NOACTIVATE.0 | SWP_NOCOPYBITS.0,
    );

    let moves: Vec<(HWND, i32, i32)> = slide_controls(state, slide)
        .iter()
        .filter_map(|&control| {
            state
                .home
                .iter()
                .find(|(h, _, _)| *h == control)
                .map(|&(_, hx, hy)| {
                    let (x, y) = slid_position(hx, hy, dx);
                    (control, x, y)
                })
        })
        .collect();

    // Lot atomique ; si Windows refuse de l'ouvrir (ressources épuisées), on
    // retombe sur des déplacements individuels plutôt que de figer le slide.
    let mut batch = BeginDeferWindowPos(moves.len() as i32).ok();
    for &(control, x, y) in &moves {
        batch = match batch {
            Some(hdwp) => DeferWindowPos(hdwp, control, None, x, y, 0, 0, FLAGS).ok(),
            None => {
                let _ = SetWindowPos(control, None, x, y, 0, 0, FLAGS);
                None
            }
        };
    }
    if let Some(hdwp) = batch {
        let _ = EndDeferWindowPos(hdwp);
    }
}

/// Repeint entièrement la fenêtre et TOUS ses enfants, de façon synchrone.
/// Filet de sécurité en fin de transition : aucun pixel d'une position
/// intermédiaire ne doit survivre à l'animation.
unsafe fn repaint_all(hwnd: HWND) {
    let _ = RedrawWindow(
        hwnd,
        None,
        None,
        RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW,
    );
}

/// Démarre le glissement d'un slide vers un autre.
unsafe fn begin_slide_transition(hwnd: HWND, state: &mut OnboardingState, to: u8) {
    let from = state.current_slide;
    if from == to {
        return;
    }
    state.sliding_from = from;
    state.slide_forward = to > from;
    state.slide_progress = 0.0;

    // Les deux slides sont visibles pendant la transition ; le sortant est
    // masqué à la fin (voir `TIMER_SLIDE`).
    show_slide(state, to);
    for &control in slide_controls(state, from) {
        let _ = ShowWindow(control, SW_SHOW);
    }
    let direction = if state.slide_forward { 1 } else { -1 };
    offset_slide(state, to, direction * WINDOW_WIDTH);

    if SetTimer(hwnd, TIMER_SLIDE, SLIDE_INTERVAL_MS, None) == 0 {
        // Sans timer, on saute directement à l'état final plutôt que de
        // laisser les deux slides superposés.
        finish_slide_transition(state);
    }
}

/// Remet tout en place à la fin (ou à l'abandon) d'une transition.
unsafe fn finish_slide_transition(state: &mut OnboardingState) {
    if state.sliding_from != 0 {
        for &control in slide_controls(state, state.sliding_from) {
            let _ = ShowWindow(control, SW_HIDE);
        }
        offset_slide(state, state.sliding_from, 0);
    }
    offset_slide(state, state.current_slide, 0);
    state.sliding_from = 0;
    state.slide_progress = 1.0;

    if let Ok(parent) = GetParent(state.hwnd_btn_next) {
        repaint_all(parent);
    }
}

unsafe fn show_slide(state: &mut OnboardingState, slide: u8) {
    state.current_slide = slide;
    // Les puces sont peintes sur le fond : il faut le réinvalider.
    if let Ok(parent) = GetParent(state.hwnd_btn_next) {
        let _ = InvalidateRect(parent, None, BOOL(1));
    }
    for &hwnd in &state.slide1_controls {
        let _ = ShowWindow(hwnd, if slide == 1 { SW_SHOW } else { SW_HIDE });
    }
    for &hwnd in &state.slide2_controls {
        let _ = ShowWindow(hwnd, if slide == 2 { SW_SHOW } else { SW_HIDE });
    }
    for &hwnd in &state.slide3_controls {
        let _ = ShowWindow(hwnd, if slide == 3 { SW_SHOW } else { SW_HIDE });
    }
    let _ = ShowWindow(state.hwnd_btn_prev, if slide == 1 { SW_HIDE } else { SW_SHOW });
    set_window_text(state.hwnd_btn_next, if slide == 3 { t("onboarding.btn.start") } else { t("onboarding.btn.next") });

    if slide == 3 {
        update_slide3_validity(state);
        let _ = SetFocus(state.hwnd_edit_password);
    } else {
        let _ = EnableWindow(state.hwnd_btn_next, BOOL(1));
    }
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let state_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut OnboardingState;

    match msg {
        WM_ERASEBKGND => {
            let hdc = HDC(wparam.0 as *mut c_void);
            let mut rc = RECT::default();
            let _ = windows::Win32::UI::WindowsAndMessaging::GetClientRect(hwnd, &mut rc);
            const BAND: i32 = 3;
            let height = (rc.bottom - rc.top).max(1);
            let mut y = rc.top;
            while y < rc.bottom {
                let t = (y - rc.top) as f32 / height as f32;
                let color = lerp_color(theme::COLOR_BACKGROUND, theme::COLOR_BACKGROUND_BOTTOM, t);
                let band = RECT { left: rc.left, top: y, right: rc.right, bottom: (y + BAND).min(rc.bottom) };
                let brush = CreateSolidBrush(COLORREF(color));
                FillRect(hdc, &band, brush);
                let _ = DeleteObject(brush);
                y += BAND;
            }

            if !state_ptr.is_null() {
                draw_progress_dots(hdc, (*state_ptr).current_slide);
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
            if ctrl == state.hwnd_error {
                SetTextColor(hdc, COLORREF(theme::COLOR_ERROR));
                SetBkColor(hdc, COLORREF(theme::COLOR_BACKGROUND));
                return LRESULT(state.brush_background.0 as isize);
            }
            if ctrl == state.hwnd_strength_label {
                SetTextColor(hdc, COLORREF(state.strength.color()));
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
        WM_COMMAND => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &mut *state_ptr;
            let control_id = (wparam.0 & 0xFFFF) as i32;
            let notify_code = ((wparam.0 >> 16) & 0xFFFF) as u32;

            match control_id {
                ID_TOGGLE if notify_code == BN_CLICKED => {
                    state.password_visible = !state.password_visible;
                    let ch: u16 = if state.password_visible { 0 } else { b'*' as u16 };
                    SendMessageW(state.hwnd_edit_password, EM_SETPASSWORDCHAR, WPARAM(ch as usize), LPARAM(0));
                    SendMessageW(state.hwnd_edit_confirm, EM_SETPASSWORDCHAR, WPARAM(ch as usize), LPARAM(0));
                    set_window_text(state.hwnd_toggle, if state.password_visible { "🙈" } else { "👁" });
                    let _ = windows::Win32::Graphics::Gdi::InvalidateRect(state.hwnd_edit_password, None, BOOL(1));
                    let _ = windows::Win32::Graphics::Gdi::InvalidateRect(state.hwnd_edit_confirm, None, BOOL(1));
                }
                ID_EDIT_PASSWORD if notify_code == EN_CHANGE => {
                    update_strength_display(state);
                    set_window_text(state.hwnd_error, "");
                    update_slide3_validity(state);
                }
                ID_EDIT_CONFIRM if notify_code == EN_CHANGE => {
                    set_window_text(state.hwnd_error, "");
                    update_slide3_validity(state);
                }
                ID_BTN_PREV if notify_code == BN_CLICKED => {
                    if state.current_slide > 1 && state.sliding_from == 0 {
                        begin_slide_transition(hwnd, state, state.current_slide - 1);
                    }
                }
                ID_BTN_NEXT if notify_code == BN_CLICKED => {
                    if state.current_slide < 3 && state.sliding_from == 0 {
                        begin_slide_transition(hwnd, state, state.current_slide + 1);
                    } else {
                        let password = get_window_text(state.hwnd_edit_password);
                        let confirm = get_window_text(state.hwnd_edit_confirm);
                        if password.is_empty() || password != confirm {
                            set_window_text(state.hwnd_error, t("password.mismatch"));
                            return LRESULT(0);
                        }
                        match master::setup_master_password(&password) {
                            Ok(()) => {
                                let mut cfg = settings::load_settings();
                                cfg.first_launch_done = true;
                                let _ = settings::save_settings(&cfg);
                                state.completed = true;
                                let _ = DestroyWindow(hwnd);
                            }
                            Err(e) => {
                                set_window_text(state.hwnd_error, &e.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
        }
        WM_TIMER if wparam.0 == TIMER_SLIDE => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &mut *state_ptr;
            state.slide_progress = (state.slide_progress + SLIDE_STEP).min(1.0);
            let t = gfx::ease_out_cubic(state.slide_progress);
            let direction = if state.slide_forward { 1.0 } else { -1.0 };

            // Le sortant part vers -W (ou +W), l'entrant arrive de +W (ou -W).
            let leaving = (-direction * WINDOW_WIDTH as f32 * t).round() as i32;
            let entering = (direction * WINDOW_WIDTH as f32 * (1.0 - t)).round() as i32;
            let from = state.sliding_from;
            if from != 0 {
                offset_slide(state, from, leaving);
            }
            offset_slide(state, state.current_slide, entering);

            // `SWP_NOCOPYBITS` fait repeindre les contrôles déplacés ; il faut
            // aussi effacer les bandes de fond qu'ils viennent de libérer.
            let _ = RedrawWindow(hwnd, None, None, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);

            if state.slide_progress >= 1.0 {
                let _ = KillTimer(hwnd, TIMER_SLIDE);
                finish_slide_transition(state);
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            if !state_ptr.is_null() {
                let state = &*state_ptr;
                let _ = DeleteObject(state.font);
                let _ = DeleteObject(state.font_bold);
                let _ = DeleteObject(state.font_title);
                let _ = DeleteObject(state.icon_font);
                let _ = DeleteObject(state.brush_background);
                let _ = DeleteObject(state.brush_field);
                let _ = DeleteObject(state.brush_accent);
                let _ = DeleteObject(state.brush_border_inner);
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
            Err(SecureVaultError::Crypto("impossible d'enregistrer la classe de fenêtre d'onboarding".into()))
        }
    }
}

/// Affiche l'écran de bienvenue en 3 slides, se terminant par la création du
/// Master Password. Retourne `true` si l'utilisateur est allé jusqu'au bout
/// (le Master Password a été créé et `first_launch_done` est maintenant
/// `true`), `false` s'il a fermé la fenêtre avant.
pub fn show() -> Result<bool> {
    register_class_once()?;

    let hinstance: HINSTANCE = unsafe { GetModuleHandleW(PCWSTR::null()) }
        .map_err(|e| SecureVaultError::Crypto(format!("GetModuleHandleW échoué: {e}")))?
        .into();

    // `WS_CLIPCHILDREN` : le fond dégradé n'est plus peint sous les contrôles,
    // qui ne sont donc plus effacés puis redessinés à chaque frame.
    let window_style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN;
    let mut window_rect = RECT { left: 0, top: 0, right: WINDOW_WIDTH, bottom: WINDOW_HEIGHT };
    unsafe {
        let _ = windows::Win32::UI::WindowsAndMessaging::AdjustWindowRectEx(
            &mut window_rect,
            window_style,
            false,
            Default::default(),
        );
    }
    let outer_w = window_rect.right - window_rect.left;
    let outer_h = window_rect.bottom - window_rect.top;
    let (screen_w, screen_h) = unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
    let x = ((screen_w - outer_w) / 2).max(0);
    let y = ((screen_h - outer_h) / 2).max(0);

    let title = HSTRING::from(t("onboarding.window_title"));
    let hwnd = unsafe {
        CreateWindowExW(
            Default::default(),
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
        CreateFontW(-theme::FONT_SIZE_PX, 0, 0, 0, FW_BOLD.0 as i32, 0, 0, 0, 0, 0, 0, 0, 0, &HSTRING::from(theme::FONT_FACE))
    };
    let font_title = unsafe {
        CreateFontW(-22, 0, 0, 0, FW_BOLD.0 as i32, 0, 0, 0, 0, 0, 0, 0, 0, &HSTRING::from(theme::FONT_FACE))
    };
    let icon_font = unsafe {
        CreateFontW(-48, 0, 0, 0, FW_NORMAL.0 as i32, 0, 0, 0, 0, 0, 0, 0, 0, &HSTRING::from(theme::FONT_FACE))
    };

    let content_w = WINDOW_WIDTH - MARGIN * 2;

    // ---- Slide 1 ----
    let s1_icon = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("STATIC"), text: "", style: WINDOW_STYLE(0), x: (WINDOW_WIDTH - 64) / 2, y: 40, w: 64, h: 64, id: ID_ILLUSTRATION_1 })?
    };
    let s1_title = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("STATIC"), text: t("onboarding.slide1.title"), style: WINDOW_STYLE(0), x: MARGIN, y: 135, w: content_w, h: 30, id: 0 })?
    };
    let s1_body = unsafe {
        create_child(
            hwnd, hinstance,
            ChildSpec {
                class: w!("STATIC"),
                text: t("onboarding.slide1.body"),
                style: WINDOW_STYLE(0),
                x: MARGIN + 40, y: 190, w: content_w - 80, h: 140, id: 0,
            },
        )?
    };
    unsafe {
        SendMessageW(s1_icon, WM_SETFONT, WPARAM(icon_font.0 as usize), LPARAM(1));
        SendMessageW(s1_title, WM_SETFONT, WPARAM(font_title.0 as usize), LPARAM(1));
        SendMessageW(s1_body, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    }
    let slide1_controls = vec![s1_icon, s1_title, s1_body];

    // ---- Slide 2 ----
    let s2_title = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("STATIC"), text: t("onboarding.slide2.title"), style: WINDOW_STYLE(0), x: MARGIN, y: 30, w: content_w, h: 30, id: 0 })?
    };
    let col_w = (content_w - 20) / 2;
    // Une illustration par colonne : cadenas pour le mode Rapide, bouclier
    // pour le mode Fort — la même symbolique que dans le reste de l'interface.
    const S2_ICON: i32 = 40;
    let s2_left_icon = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("STATIC"), text: "", style: WINDOW_STYLE(0), x: MARGIN + (col_w - S2_ICON) / 2, y: 78, w: S2_ICON, h: S2_ICON, id: ID_ILLUSTRATION_2A })?
    };
    let s2_right_icon = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("STATIC"), text: "", style: WINDOW_STYLE(0), x: MARGIN + col_w + 20 + (col_w - S2_ICON) / 2, y: 78, w: S2_ICON, h: S2_ICON, id: ID_ILLUSTRATION_2B })?
    };
    let s2_left_title = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("STATIC"), text: t("onboarding.slide2.quick_title"), style: WINDOW_STYLE(0), x: MARGIN, y: 126, w: col_w, h: 24, id: 0 })?
    };
    let s2_left_body = unsafe {
        create_child(
            hwnd, hinstance,
            ChildSpec {
                class: w!("STATIC"),
                text: t("onboarding.slide2.quick_body"),
                style: WINDOW_STYLE(0), x: MARGIN, y: 160, w: col_w, h: 150, id: 0,
            },
        )?
    };
    let s2_right_title = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("STATIC"), text: t("onboarding.slide2.strong_title"), style: WINDOW_STYLE(0), x: MARGIN + col_w + 20, y: 126, w: col_w, h: 24, id: 0 })?
    };
    let s2_right_body = unsafe {
        create_child(
            hwnd, hinstance,
            ChildSpec {
                class: w!("STATIC"),
                text: t("onboarding.slide2.strong_body"),
                style: WINDOW_STYLE(0), x: MARGIN + col_w + 20, y: 160, w: col_w, h: 150, id: 0,
            },
        )?
    };
    unsafe {
        for h in [s2_title] {
            SendMessageW(h, WM_SETFONT, WPARAM(font_title.0 as usize), LPARAM(1));
        }
        for h in [s2_left_title, s2_right_title] {
            SendMessageW(h, WM_SETFONT, WPARAM(font_bold.0 as usize), LPARAM(1));
        }
        for h in [s2_left_body, s2_right_body] {
            SendMessageW(h, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
        }
    }
    let slide2_controls = vec![s2_left_icon, s2_right_icon, s2_title, s2_left_title, s2_left_body, s2_right_title, s2_right_body];

    // ---- Slide 3 ----
    let s3_icon = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("STATIC"), text: "", style: WINDOW_STYLE(0), x: MARGIN, y: 20, w: 48, h: 48, id: ID_ILLUSTRATION_3 })?
    };
    let s3_title = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("STATIC"), text: t("onboarding.slide3.title"), style: WINDOW_STYLE(0), x: MARGIN + 60, y: 32, w: content_w - 60, h: 26, id: 0 })?
    };
    let s3_body = unsafe {
        create_child(
            hwnd, hinstance,
            ChildSpec {
                class: w!("STATIC"),
                text: t("onboarding.slide3.body"),
                style: WINDOW_STYLE(0), x: MARGIN, y: 80, w: content_w, h: 40, id: 0,
            },
        )?
    };

    let layout = slide3_layout(content_w);
    let at = |class: PCWSTR, text: &'static str, style: WINDOW_STYLE, r: Rect, id: i32| ChildSpec {
        class,
        text,
        style,
        x: r.x,
        y: r.y,
        w: r.w,
        h: r.h,
        id,
    };
    let edit_style = WINDOW_STYLE((ES_PASSWORD | ES_AUTOHSCROLL) as u32) | WS_TABSTOP;

    let hwnd_frame_password = unsafe {
        create_child(hwnd, hinstance, at(w!("STATIC"), "", WINDOW_STYLE(0), layout.password_frame, 0))?
    };
    let hwnd_frame_password_inner = unsafe {
        create_child(hwnd, hinstance, at(w!("STATIC"), "", WINDOW_STYLE(0), layout.password_inner, 0))?
    };
    let hwnd_edit_password = unsafe {
        create_child(hwnd, hinstance, at(w!("EDIT"), "", edit_style, layout.password_edit, ID_EDIT_PASSWORD))?
    };
    let hwnd_toggle = unsafe {
        create_child(
            hwnd,
            hinstance,
            at(w!("BUTTON"), "👁", WINDOW_STYLE(0) | WS_TABSTOP, layout.toggle, ID_TOGGLE),
        )?
    };

    let hwnd_frame_confirm = unsafe {
        create_child(hwnd, hinstance, at(w!("STATIC"), "", WINDOW_STYLE(0), layout.confirm_frame, 0))?
    };
    let hwnd_frame_confirm_inner = unsafe {
        create_child(hwnd, hinstance, at(w!("STATIC"), "", WINDOW_STYLE(0), layout.confirm_inner, 0))?
    };
    let hwnd_edit_confirm = unsafe {
        create_child(hwnd, hinstance, at(w!("EDIT"), "", edit_style, layout.confirm_edit, ID_EDIT_CONFIRM))?
    };

    let hwnd_strength = unsafe {
        create_child(hwnd, hinstance, at(w!("STATIC"), "", WINDOW_STYLE(0), layout.strength_bar, 0))?
    };
    let hwnd_strength_label = unsafe {
        create_child(
            hwnd,
            hinstance,
            at(w!("STATIC"), PasswordStrength::VeryWeak.label(), WINDOW_STYLE(0), layout.strength_label, 0),
        )?
    };
    let hwnd_error = unsafe {
        create_child(hwnd, hinstance, at(w!("STATIC"), "", WINDOW_STYLE(0), layout.error, 0))?
    };

    // Ordre d'empilement EXPLICITE : les cadres tout au fond, champs et bouton
    // 👁 au-dessus. Avec `WS_CLIPSIBLINGS`, c'est cet ordre qui décide qui
    // peint sur qui — on le fixe plutôt que de dépendre de l'ordre de
    // création. Intérieur puis extérieur, pour que l'extérieur finisse tout
    // en bas.
    unsafe {
        for frame in [
            hwnd_frame_password_inner,
            hwnd_frame_password,
            hwnd_frame_confirm_inner,
            hwnd_frame_confirm,
        ] {
            let _ = SetWindowPos(
                frame,
                HWND_BOTTOM,
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
            );
        }
    }

    unsafe {
        SendMessageW(s3_icon, WM_SETFONT, WPARAM(font_title.0 as usize), LPARAM(1));
        SendMessageW(s3_title, WM_SETFONT, WPARAM(font_title.0 as usize), LPARAM(1));
        for h in [s3_body, hwnd_edit_password, hwnd_edit_confirm, hwnd_toggle, hwnd_error, hwnd_strength_label] {
            SendMessageW(h, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
        }
        subclass_strength_bar(hwnd_strength);
    }

    let slide3_controls = vec![
        s3_icon, s3_title, s3_body,
        hwnd_frame_password, hwnd_frame_password_inner, hwnd_edit_password, hwnd_toggle,
        hwnd_frame_confirm, hwnd_frame_confirm_inner, hwnd_edit_confirm,
        hwnd_strength, hwnd_strength_label, hwnd_error,
    ];

    // ---- Navigation ----
    let buttons_y = WINDOW_HEIGHT - MARGIN - 36;
    let hwnd_btn_prev = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("BUTTON"), text: t("onboarding.btn.prev"), style: WINDOW_STYLE(0) | WS_TABSTOP, x: MARGIN, y: buttons_y, w: 130, h: 36, id: ID_BTN_PREV })?
    };
    let hwnd_btn_next = unsafe {
        create_child(hwnd, hinstance, ChildSpec { class: w!("BUTTON"), text: t("onboarding.btn.next"), style: WINDOW_STYLE(0) | WS_TABSTOP, x: WINDOW_WIDTH - MARGIN - 150, y: buttons_y, w: 150, h: 36, id: ID_BTN_NEXT })?
    };
    unsafe {
        SendMessageW(hwnd_btn_prev, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
        SendMessageW(hwnd_btn_next, WM_SETFONT, WPARAM(font.0 as usize), LPARAM(1));
    }

    let state = Box::new(OnboardingState {
        current_slide: 1,
        home: Vec::new(),
        sliding_from: 0,
        slide_progress: 1.0,
        slide_forward: true,
        slide1_controls,
        slide2_controls,
        slide3_controls,
        hwnd_btn_prev,
        hwnd_btn_next,
        hwnd_edit_password,
        hwnd_edit_confirm,
        hwnd_toggle,
        hwnd_strength,
        hwnd_strength_label,
        hwnd_error,
        password_visible: false,
        strength: PasswordStrength::VeryWeak,
        font,
        font_bold,
        font_title,
        icon_font,
        brush_background: unsafe { CreateSolidBrush(COLORREF(theme::COLOR_BACKGROUND)) },
        brush_field: unsafe { CreateSolidBrush(COLORREF(theme::COLOR_FIELD_BACKGROUND)) },
        brush_accent: unsafe { CreateSolidBrush(COLORREF(theme::field_border())) },
        brush_border_inner: unsafe { CreateSolidBrush(COLORREF(theme::COLOR_FIELD_BORDER_INNER)) },
        completed: false,
    });
    let state_ptr = Box::into_raw(state);

    unsafe {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_ptr as isize);

        // Positions de repos (x ET y), relevées une seule fois, AVANT toute
        // animation : c'est le seul moment où elles sont garanties exactes.
        let state = &mut *state_ptr;
        // Collecté d'abord, poussé ensuite : `slide_controls` emprunte `state`
        // en lecture, on ne peut pas écrire dans `home` pendant l'itération.
        let mut homes: Vec<(HWND, i32, i32)> = Vec::new();
        for slide in 1..=3u8 {
            for &control in slide_controls(state, slide) {
                let mut rc = RECT::default();
                let _ = GetWindowRect(control, &mut rc);
                let mut origin = windows::Win32::Foundation::POINT { x: rc.left, y: rc.top };
                let _ = ScreenToClient(hwnd, &mut origin);
                homes.push((control, origin.x, origin.y));
            }
        }
        state.home = homes;

        // Les illustrations sont des STATIC vides peints en GDI.
        for &control in &[
            ID_ILLUSTRATION_1,
            ID_ILLUSTRATION_2A,
            ID_ILLUSTRATION_2B,
            ID_ILLUSTRATION_3,
        ] {
            let child = GetDlgItem(hwnd, control).unwrap_or_default();
            if !child.is_invalid() {
                subclass_illustration(child);
            }
        }

        crate::ui::apply_app_icon(hwnd);
        show_slide(state, 1);
        let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
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

    let state = unsafe { Box::from_raw(state_ptr) };
    Ok(state.completed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> Slide3Layout {
        slide3_layout(WINDOW_WIDTH - MARGIN * 2)
    }

    /// Régression 0.8.1 : le bouton 👁 doit être DANS le champ (à l'intérieur
    /// du cadre intérieur, pas sur la bordure), aligné à droite, et de la même
    /// hauteur que la zone de saisie.
    #[test]
    fn toggle_sits_inside_the_field_right_aligned_and_same_height() {
        let l = layout();
        assert!(l.password_inner.contains(&l.toggle), "le bouton 👁 déborde du cadre");
        assert!(!l.toggle.overlaps(&Rect { x: l.password_frame.right() - 1, y: l.password_frame.y, w: 1, h: l.password_frame.h }),
            "le bouton 👁 ne doit pas recouvrir la bordure extérieure droite");
        assert_eq!(l.toggle.h, l.password_edit.h, "même hauteur que la zone de saisie");
        assert_eq!(l.toggle.y, l.password_edit.y, "aligné verticalement sur la zone de saisie");
        // Aligné à droite : même retrait qu'à gauche entre la zone de saisie et
        // le cadre intérieur.
        let left_inset = l.password_edit.x - l.password_inner.x;
        let right_inset = l.password_inner.right() - l.toggle.right();
        assert_eq!(left_inset, right_inset, "retraits gauche/droite symétriques");
    }

    /// Le champ de saisie et le bouton 👁 sont collés, sans chevauchement.
    #[test]
    fn edit_and_toggle_are_adjacent_without_overlap() {
        let l = layout();
        assert!(!l.password_edit.overlaps(&l.toggle), "champ et bouton se chevauchent");
        assert_eq!(l.password_edit.right(), l.toggle.x, "espace mort entre champ et bouton");
    }

    /// Les deux champs partagent exactement la même emprise horizontale, et
    /// cette emprise est celle du texte au-dessus (bords gauche et droit
    /// alignés sur la marge).
    #[test]
    fn both_fields_are_aligned_with_the_content_margins() {
        let l = layout();
        let content_w = WINDOW_WIDTH - MARGIN * 2;
        for frame in [l.password_frame, l.confirm_frame] {
            assert_eq!(frame.x, MARGIN);
            assert_eq!(frame.right(), MARGIN + content_w, "champ plus étroit que le contenu");
        }
        assert_eq!(l.password_frame.w, l.confirm_frame.w);
        assert_eq!(l.password_edit.x, l.confirm_edit.x);
        // Sans bouton 👁, le champ de confirmation occupe toute la zone de saisie.
        assert_eq!(l.confirm_edit.right(), l.toggle.right());
    }

    /// Aucun élément du slide ne doit en chevaucher un autre en dehors de
    /// l'emboîtement voulu (cadre ⊃ intérieur ⊃ saisie).
    #[test]
    fn rows_do_not_overlap_each_other() {
        let l = layout();
        let rows = [l.password_frame, l.confirm_frame, l.strength_bar, l.error];
        for (i, a) in rows.iter().enumerate() {
            for b in rows.iter().skip(i + 1) {
                assert!(!a.overlaps(b), "{a:?} chevauche {b:?}");
            }
        }
        assert!(!l.strength_bar.overlaps(&l.strength_label));
        assert!(l.confirm_frame.contains(&l.confirm_inner));
        assert!(l.confirm_inner.contains(&l.confirm_edit));
        assert!(l.password_frame.contains(&l.password_inner));
        assert!(l.password_inner.contains(&l.password_edit));
    }

    /// Régression 0.8.1 : la position d'un contrôle ne dépend que de son
    /// repos et du décalage demandé. Enchaîner des transitions dans tous les
    /// sens puis revenir à 0 doit ramener EXACTEMENT au repos, sans dérive.
    #[test]
    fn sliding_never_drifts_from_the_rest_position() {
        let (home_x, home_y) = (MARGIN + 2, 137);
        for dx in [WINDOW_WIDTH, -WINDOW_WIDTH, 313, -77, 1, -1, 0] {
            let (x, y) = slid_position(home_x, home_y, dx);
            assert_eq!(x, home_x + dx);
            assert_eq!(y, home_y, "l'ordonnée ne doit jamais bouger");
        }
        assert_eq!(slid_position(home_x, home_y, 0), (home_x, home_y));
    }
}

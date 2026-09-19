//! Popup « Limite atteinte » de la version gratuite.
//!
//! **Version gratuite open source** : la saisie et l'activation d'une clé
//! SecureVault Pro ne sont pas incluses dans ce code source. La popup propose
//! seulement d'ouvrir la page d'achat, ou de revenir plus tard.
//!
//! Même fondation visuelle que la popup mot de passe (fond dégradé, accent du
//! thème, boutons owner-draw peints via `ui::gfx`).

use crate::errors::{Result, SecureVaultError};
use crate::i18n::t;
use crate::license::{self, LicenseStatus, Quota};
use crate::ui::{self, gfx, theme};

use std::ffi::c_void;
use std::sync::OnceLock;

use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::Foundation::{COLORREF, HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreateSolidBrush, DeleteObject, EndPaint, SetBkColor, SetTextColor,
    DT_CENTER, DT_SINGLELINE, DT_VCENTER, FW_BOLD, FW_NORMAL, HBRUSH, HDC, HFONT, PAINTSTRUCT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::DRAWITEMSTRUCT;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{
    AdjustWindowRectEx, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    GetClientRect, GetMessageW, GetSystemMetrics, GetWindowLongPtrW, GetWindowTextW,
    IsDialogMessageW, LoadCursorW, PostQuitMessage, RegisterClassW, SendMessageW,
    SetWindowLongPtrW, ShowWindow, TranslateMessage, BN_CLICKED, BS_OWNERDRAW, CS_HREDRAW,
    CS_VREDRAW, GWLP_USERDATA, HMENU, IDC_ARROW, MSG, SM_CXSCREEN, SM_CYSCREEN, SW_SHOW,
    SW_SHOWNORMAL, WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_COMMAND, WM_CTLCOLORSTATIC,
    WM_DESTROY, WM_DRAWITEM, WM_ERASEBKGND, WM_PAINT, WM_SETFONT, WNDCLASSW, WS_CAPTION,
    WS_CHILD, WS_CLIPCHILDREN, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
};

const CLASS_NAME: PCWSTR = w!("SecureVaultLicenseClass");

/// Page d'achat ouverte par « Acheter » (popup, dashboard).
const BUY_URL: PCWSTR = w!("https://securevault-app.com/pro");

const WIDTH: i32 = 460;
const HEIGHT: i32 = 314;
const MARGIN: i32 = 24;
const BUTTON_H: i32 = 38;

// IDCANCEL : Échap ferme la popup via `IsDialogMessageW`.
const ID_CANCEL: i32 = 2;
const ID_BUY: i32 = 11;

struct PromptState {
    font: HFONT,
    font_bold: HFONT,
    brush_background: HBRUSH,
    brush_card: HBRUSH,
    /// Rectangle de la carte du message, peinte par la fenêtre elle-même.
    panel: RECT,
}

/// Message de l'écran « Limite atteinte ». Fonction pure, testée.
///
/// Deux situations : quota épuisé, ou quota insuffisant pour la sélection
/// (ex. 2 chiffrements restants pour 5 fichiers sélectionnés). Dire « vous
/// avez utilisé vos 3 chiffrements » dans le second cas serait faux.
fn limit_message(quota: Quota, status: &LicenseStatus, requested: u32) -> String {
    let max = quota.limit().to_string();
    let remaining = status.remaining(quota).unwrap_or(u32::MAX);
    let first = if remaining > 0 && requested > remaining {
        let key = match quota {
            Quota::Lock => "license.locks_insufficient",
            Quota::Encrypt => "license.encrypts_insufficient",
        };
        t(key)
            .replace("{remaining}", &remaining.to_string())
            .replace("{count}", &requested.to_string())
    } else {
        let key = match quota {
            Quota::Lock => "license.locks_limit",
            Quota::Encrypt => "license.encrypts_limit",
        };
        t(key).replace("{max}", &max)
    };
    format!("{first}\n\n{}", t("license.upgrade_pitch"))
}

/// Vérifie le quota avant une nouvelle protection. Retourne `true` si l'action
/// peut continuer ; sinon affiche la popup « Limite atteinte » et retourne
/// `false` (la version gratuite ne peut pas passer en Pro sur place).
pub fn offer_upgrade(quota: Quota, requested: u32) -> bool {
    let status = license::status();
    if status.allows(quota, requested) {
        return true;
    }
    let message = limit_message(quota, &status, requested);
    let _ = run(&message);
    false
}

/// Ouvre la page d'achat de SecureVault Pro dans le navigateur.
pub fn open_buy_page() {
    unsafe {
        ShellExecuteW(None, w!("open"), BUY_URL, PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL);
    }
}

// ---------------------------------------------------------------------------
// Fenêtre
// ---------------------------------------------------------------------------

fn register_class_once() -> Result<()> {
    static REGISTERED: OnceLock<bool> = OnceLock::new();
    let ok = *REGISTERED.get_or_init(|| unsafe {
        let Ok(module) = GetModuleHandleW(PCWSTR::null()) else {
            return false;
        };
        let class = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc),
            hInstance: module.into(),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            lpszClassName: CLASS_NAME,
            ..Default::default()
        };
        RegisterClassW(&class) != 0
    });
    if ok {
        Ok(())
    } else {
        Err(SecureVaultError::License(
            "impossible d'enregistrer la classe de fenêtre de licence".into(),
        ))
    }
}

unsafe fn child(
    parent: HWND,
    hinstance: HINSTANCE,
    class: PCWSTR,
    text: &str,
    style: WINDOW_STYLE,
    rc: RECT,
    id: i32,
) -> Result<HWND> {
    CreateWindowExW(
        WINDOW_EX_STYLE(0),
        class,
        &HSTRING::from(text),
        WS_CHILD | WS_VISIBLE | style,
        rc.left,
        rc.top,
        rc.right - rc.left,
        rc.bottom - rc.top,
        parent,
        HMENU(id as isize as *mut c_void),
        hinstance,
        None,
    )
    .map_err(|e| SecureVaultError::License(format!("création de contrôle échouée : {e}")))
}

fn rect(x: i32, y: i32, w: i32, h: i32) -> RECT {
    RECT { left: x, top: y, right: x + w, bottom: y + h }
}

fn run(message: &str) -> Result<()> {
    register_class_once()?;
    let hinstance: HINSTANCE = unsafe { GetModuleHandleW(PCWSTR::null()) }
        .map_err(|e| SecureVaultError::License(format!("GetModuleHandleW échoué : {e}")))?
        .into();

    let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_CLIPCHILDREN;
    let mut outer = rect(0, 0, WIDTH, HEIGHT);
    unsafe {
        let _ = AdjustWindowRectEx(&mut outer, style, false, WINDOW_EX_STYLE(0));
    }
    let (ow, oh) = (outer.right - outer.left, outer.bottom - outer.top);
    let (sw, sh) = unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };

    let title = format!("🛡️ {}", t("license.limit_title"));
    let hwnd = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            CLASS_NAME,
            &HSTRING::from(title.as_str()),
            style,
            ((sw - ow) / 2).max(0),
            ((sh - oh) / 2).max(0),
            ow,
            oh,
            None,
            None,
            hinstance,
            None,
        )
    }
    .map_err(|e| SecureVaultError::License(format!("création de la fenêtre échouée : {e}")))?;

    let face = HSTRING::from(theme::FONT_FACE);
    let font = unsafe { CreateFontW(-14, 0, 0, 0, FW_NORMAL.0 as i32, 0, 0, 0, 0, 0, 0, 0, 0, &face) };
    let font_bold = unsafe { CreateFontW(-18, 0, 0, 0, FW_BOLD.0 as i32, 0, 0, 0, 0, 0, 0, 0, 0, &face) };
    let content_w = WIDTH - MARGIN * 2;

    let set_font = |h: HWND, f: HFONT| unsafe {
        SendMessageW(h, WM_SETFONT, WPARAM(f.0 as usize), LPARAM(1));
    };

    let panel = rect(MARGIN, 62, content_w, 132);
    unsafe {
        let h = child(hwnd, hinstance, w!("STATIC"), &title, WINDOW_STYLE(0), rect(MARGIN, 20, content_w, 28), 0)?;
        set_font(h, font_bold);

        let h = child(
            hwnd,
            hinstance,
            w!("STATIC"),
            message,
            WINDOW_STYLE(0),
            rect(MARGIN + 16, 76, content_w - 32, 106),
            0,
        )?;
        set_font(h, font);

        for (index, (id, label)) in [(ID_BUY, t("license.buy")), (ID_CANCEL, t("license.later"))]
            .into_iter()
            .enumerate()
        {
            let b = child(
                hwnd,
                hinstance,
                w!("BUTTON"),
                label,
                WINDOW_STYLE(BS_OWNERDRAW as u32) | WS_TABSTOP,
                rect(MARGIN, 212 + index as i32 * (BUTTON_H + 8), content_w, BUTTON_H),
                id,
            )?;
            set_font(b, font);
        }
    }

    let state = Box::new(PromptState {
        font,
        font_bold,
        brush_background: unsafe { CreateSolidBrush(COLORREF(theme::COLOR_BACKGROUND)) },
        brush_card: unsafe { CreateSolidBrush(COLORREF(theme::COLOR_CARD_BG)) },
        panel,
    });
    let state_ptr = Box::into_raw(state);

    unsafe {
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_ptr as isize);
        ui::apply_app_icon(hwnd);
        let _ = ShowWindow(hwnd, SW_SHOW);

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
            if IsDialogMessageW(hwnd, &msg).as_bool() {
                continue;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    // La fenêtre est détruite (WM_DESTROY a libéré les objets GDI) : on
    // libère l'état.
    drop(unsafe { Box::from_raw(state_ptr) });
    Ok(())
}

unsafe fn draw_button(item: &DRAWITEMSTRUCT, font: HFONT) {
    let rc = item.rcItem;
    let pressed = (item.itemState.0 & 0x0001) != 0; // ODS_SELECTED
    gfx::fill_rect(item.hDC, rc, theme::COLOR_BACKGROUND_BOTTOM);

    let mut label = vec![0u16; 128];
    let len = GetWindowTextW(item.hwndItem, &mut label).max(0) as usize;
    let text = String::from_utf16_lossy(&label[..len]);

    if item.CtlID as i32 == ID_BUY {
        let shade = |c: u32| if pressed { gfx::darken(c, 0.1) } else { c };
        gfx::fill_round_rect_gradient(item.hDC, rc, shade(theme::accent_start()), shade(theme::accent_end()), 6, true);
        gfx::draw_text_in(item.hDC, rc, &text, theme::COLOR_WHITE, font, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    } else {
        if pressed {
            gfx::fill_round_rect(item.hDC, rc, theme::COLOR_CARD_BG, 6);
        }
        gfx::stroke_round_rect(item.hDC, rc, theme::COLOR_BTN_SECONDARY_BORDER, 6, 1);
        gfx::draw_text_in(item.hDC, rc, &text, theme::COLOR_BTN_SECONDARY_TEXT, font, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    }
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let state_ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut PromptState;

    match msg {
        // Tout est peint dans WM_PAINT, en double tampon.
        WM_ERASEBKGND => LRESULT(1),
        WM_PAINT => {
            let mut ps = PAINTSTRUCT::default();
            let hdc = BeginPaint(hwnd, &mut ps);
            let mut client = RECT::default();
            let _ = GetClientRect(hwnd, &mut client);
            if let Some(buffer) = gfx::BackBuffer::new(hdc, client) {
                gfx::fill_rect(buffer.dc, buffer.local(), theme::COLOR_BACKGROUND);
                if !state_ptr.is_null() {
                    gfx::fill_round_rect(buffer.dc, (*state_ptr).panel, theme::COLOR_CARD_BG, 8);
                }
                buffer.present();
            }
            let _ = EndPaint(hwnd, &ps);
            LRESULT(0)
        }
        WM_CTLCOLORSTATIC => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            let state = &*state_ptr;
            let hdc = HDC(wparam.0 as *mut c_void);
            let ctrl = HWND(lparam.0 as *mut c_void);
            // Le message est posé sur la carte, le titre sur le fond.
            let mut ctrl_rc = RECT::default();
            let _ = windows::Win32::UI::WindowsAndMessaging::GetWindowRect(ctrl, &mut ctrl_rc);
            let mut origin = windows::Win32::Foundation::POINT { x: ctrl_rc.left, y: ctrl_rc.top };
            let _ = windows::Win32::Graphics::Gdi::ScreenToClient(hwnd, &mut origin);
            let on_card = origin.y >= state.panel.top && origin.y < state.panel.bottom;
            SetTextColor(hdc, COLORREF(theme::COLOR_TEXT));
            if on_card {
                SetBkColor(hdc, COLORREF(theme::COLOR_CARD_BG));
                LRESULT(state.brush_card.0 as isize)
            } else {
                SetBkColor(hdc, COLORREF(theme::COLOR_BACKGROUND));
                LRESULT(state.brush_background.0 as isize)
            }
        }
        WM_DRAWITEM => {
            if state_ptr.is_null() {
                return DefWindowProcW(hwnd, msg, wparam, lparam);
            }
            draw_button(&*(lparam.0 as *const DRAWITEMSTRUCT), (*state_ptr).font);
            LRESULT(1)
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xFFFF) as i32;
            let code = ((wparam.0 >> 16) & 0xFFFF) as u32;
            match (id, code) {
                (ID_BUY, BN_CLICKED) => {
                    open_buy_page();
                    let _ = DestroyWindow(hwnd);
                }
                (ID_CANCEL, BN_CLICKED) => {
                    let _ = DestroyWindow(hwnd);
                }
                _ => {}
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            if !state_ptr.is_null() {
                let state = &*state_ptr;
                let _ = DeleteObject(state.font);
                let _ = DeleteObject(state.font_bold);
                let _ = DeleteObject(state.brush_background);
                let _ = DeleteObject(state.brush_card);
            }
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::license::UsageCounters;

    fn free(locks: u32, encrypts: u32) -> LicenseStatus {
        LicenseStatus {
            pro: false,
            usage: UsageCounters { locks_used: locks, encrypts_used: encrypts },
        }
    }

    #[test]
    fn exhausted_quota_message_states_the_limit() {
        let message = limit_message(Quota::Encrypt, &free(0, 3), 1);
        assert!(message.contains('3'), "{message}");
        assert!(!message.contains("{max}"), "marqueur non remplacé : {message}");
    }

    /// Quota non épuisé mais insuffisant pour la sélection : le message ne
    /// doit PAS prétendre que toutes les actions gratuites sont consommées.
    #[test]
    fn insufficient_quota_message_mentions_remaining_and_selection() {
        let message = limit_message(Quota::Lock, &free(18, 0), 5);
        assert!(message.contains('2'), "reste 2 : {message}");
        assert!(message.contains('5'), "5 sélectionnés : {message}");
        assert!(!message.contains('{'), "marqueur non remplacé : {message}");
    }
}

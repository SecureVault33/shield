//! Primitives de dessin GDI partagées par les trois fenêtres (`ui::mod`,
//! `dashboard::window`, `onboarding`).
//!
//! Jusqu'à la 0.7.0 chacune reproduisait sa propre `lerp_color`, sa propre
//! peinture de dégradé et son propre `RoundRect` — trois copies à corriger à
//! chaque fois. La 0.8.0 introduisant des animations et un jeu d'icônes
//! vectorielles partout, la duplication devenait ingérable : tout est
//! centralisé ici.
//!
//! **Anti-aliasing sans GDI+** : GDI ne lisse ni les courbes ni les
//! diagonales. Plutôt que d'embarquer GDI+ (init/shutdown global, API plate
//! verbeuse) pour cinq icônes, on dessine dans un DC mémoire à
//! `SUPERSAMPLE`× la taille finale puis on réduit avec `StretchBlt` +
//! `HALFTONE` : Windows moyenne les pixels, ce qui donne exactement le
//! lissage recherché pour des aplats de couleur.

use windows::Win32::Foundation::{COLORREF, POINT, RECT};
use windows::Win32::Graphics::Gdi::{
    BeginPath, CloseFigure, CreateCompatibleBitmap, CreateCompatibleDC, CreatePen, CreateSolidBrush,
    DeleteDC, DeleteObject, DrawTextW, Ellipse, EndPath, FillPath, FillRect, LineTo, MoveToEx, Pie,
    PolyBezierTo, RoundRect, SelectObject, SetBkMode, SetBrushOrgEx, SetStretchBltMode, SetTextColor,
    StretchBlt, DRAW_TEXT_FORMAT, HALFTONE, HBRUSH, HDC, HFONT, PS_NULL, PS_SOLID, SRCCOPY,
    TRANSPARENT,
};

/// Facteur de suréchantillonnage des icônes vectorielles. 4× suffit
/// visuellement et garde les DC mémoire petits (une icône 64 px en dessine
/// une de 256 px).
const SUPERSAMPLE: i32 = 4;

// ---------------------------------------------------------------------------
// Couleurs
// ---------------------------------------------------------------------------

/// Un `COLORREF` Win32 est encodé `0x00BBGGRR` — l'inverse de l'habituel
/// `#RRGGBB`, d'où cette conversion explicite partout.
pub fn channels(colorref: u32) -> (u8, u8, u8) {
    (
        (colorref & 0xFF) as u8,
        ((colorref >> 8) & 0xFF) as u8,
        ((colorref >> 16) & 0xFF) as u8,
    )
}

pub fn from_channels(r: u8, g: u8, b: u8) -> u32 {
    (b as u32) << 16 | (g as u32) << 8 | r as u32
}

/// Interpolation linéaire entre deux couleurs. `t` est borné à [0, 1] : les
/// animations calculent souvent une progression qui déborde légèrement.
pub fn lerp_color(from: u32, to: u32, t: f32) -> u32 {
    let t = t.clamp(0.0, 1.0);
    let (r1, g1, b1) = channels(from);
    let (r2, g2, b2) = channels(to);
    let lerp = |a: u8, b: u8| -> u8 { (a as f32 + (b as f32 - a as f32) * t).round() as u8 };
    from_channels(lerp(r1, r2), lerp(g1, g2), lerp(b1, b2))
}

/// Éclaircit vers le blanc (`amount` = 0.15 pour « 15 % plus clair »).
pub fn lighten(color: u32, amount: f32) -> u32 {
    lerp_color(color, 0x00FFFFFF, amount)
}

/// Assombrit vers le noir.
pub fn darken(color: u32, amount: f32) -> u32 {
    lerp_color(color, 0x00000000, amount)
}

/// Simule une couleur semi-transparente sur un fond opaque : GDI ne gère pas
/// l'alpha sur les primitives, donc on pré-mélange.
pub fn over(foreground: u32, background: u32, alpha: f32) -> u32 {
    lerp_color(background, foreground, alpha)
}

// ---------------------------------------------------------------------------
// Courbes d'animation
// ---------------------------------------------------------------------------

/// Décélération cubique : rapide au début, qui se pose en douceur. C'est la
/// courbe qui « sent » le plus naturel pour une valeur qui arrive à
/// destination (compteurs, glissement d'indicateur).
pub fn ease_out_cubic(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    1.0 - (1.0 - t).powi(3)
}

// ---------------------------------------------------------------------------
// Remplissages
// ---------------------------------------------------------------------------

/// Dégradé vertical peint par bandes de 3 px. GDI n'a pas de dégradé sans
/// `GradientFill` (msimg32) ; des bandes fines sont indiscernables à l'œil et
/// évitent une DLL supplémentaire.
pub unsafe fn fill_gradient_v(hdc: HDC, rc: RECT, top: u32, bottom: u32) {
    const BAND: i32 = 3;
    let height = (rc.bottom - rc.top).max(1);
    let mut y = rc.top;
    while y < rc.bottom {
        let t = (y - rc.top) as f32 / height as f32;
        let band = RECT {
            left: rc.left,
            top: y,
            right: rc.right,
            bottom: (y + BAND).min(rc.bottom),
        };
        let brush = CreateSolidBrush(COLORREF(lerp_color(top, bottom, t)));
        FillRect(hdc, &band, brush);
        let _ = DeleteObject(brush);
        y += BAND;
    }
}

/// Dégradé horizontal, même technique (utilisé par le header du dashboard).
pub unsafe fn fill_gradient_h(hdc: HDC, rc: RECT, left: u32, right: u32) {
    const BAND: i32 = 3;
    let width = (rc.right - rc.left).max(1);
    let mut x = rc.left;
    while x < rc.right {
        let t = (x - rc.left) as f32 / width as f32;
        let band = RECT {
            left: x,
            top: rc.top,
            right: (x + BAND).min(rc.right),
            bottom: rc.bottom,
        };
        let brush = CreateSolidBrush(COLORREF(lerp_color(left, right, t)));
        FillRect(hdc, &band, brush);
        let _ = DeleteObject(brush);
        x += BAND;
    }
}

pub unsafe fn fill_rect(hdc: HDC, rc: RECT, color: u32) {
    let brush = CreateSolidBrush(COLORREF(color));
    FillRect(hdc, &rc, brush);
    let _ = DeleteObject(brush);
}

/// Rectangle à coins arrondis, plein, sans contour.
pub unsafe fn fill_round_rect(hdc: HDC, rc: RECT, color: u32, radius: i32) {
    let brush = CreateSolidBrush(COLORREF(color));
    let pen = CreatePen(PS_NULL, 0, COLORREF(0));
    let old_brush = SelectObject(hdc, brush);
    let old_pen = SelectObject(hdc, pen);
    // +1 : `RoundRect` exclut le bord droit/bas, contrairement à `FillRect`.
    let _ = RoundRect(hdc, rc.left, rc.top, rc.right + 1, rc.bottom + 1, radius, radius);
    SelectObject(hdc, old_brush);
    SelectObject(hdc, old_pen);
    let _ = DeleteObject(brush);
    let _ = DeleteObject(pen);
}

/// Contour arrondi seul (fond inchangé).
pub unsafe fn stroke_round_rect(hdc: HDC, rc: RECT, color: u32, radius: i32, width: i32) {
    let pen = CreatePen(PS_SOLID, width, COLORREF(color));
    let old_pen = SelectObject(hdc, pen);
    let old_brush = SelectObject(hdc, null_brush());
    let _ = RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, radius, radius);
    SelectObject(hdc, old_pen);
    SelectObject(hdc, old_brush);
    let _ = DeleteObject(pen);
}

/// `GetStockObject(NULL_BRUSH)` — évite d'importer `GetStockObject` partout.
unsafe fn null_brush() -> HBRUSH {
    use windows::Win32::Graphics::Gdi::{GetStockObject, NULL_BRUSH};
    HBRUSH(GetStockObject(NULL_BRUSH).0)
}

/// Rectangle arrondi rempli d'un dégradé : le dégradé est peint bande par
/// bande, mais seulement à l'intérieur de la forme arrondie (obtenue par un
/// chemin GDI transformé en région de découpe).
pub unsafe fn fill_round_rect_gradient(
    hdc: HDC,
    rc: RECT,
    start: u32,
    end: u32,
    radius: i32,
    horizontal: bool,
) {
    use windows::Win32::Graphics::Gdi::{
        DeleteObject as DelObj, PathToRegion, SelectClipRgn, SetPolyFillMode, WINDING,
    };

    let _ = BeginPath(hdc);
    SetPolyFillMode(hdc, WINDING);
    let _ = RoundRect(hdc, rc.left, rc.top, rc.right + 1, rc.bottom + 1, radius, radius);
    let _ = EndPath(hdc);

    // `PathToRegion` retourne un HRGN nul en cas d'échec (pas un Result).
    let region = PathToRegion(hdc);
    if region.is_invalid() {
        // Repli : sans région, un aplat vaut mieux qu'un bouton invisible.
        fill_round_rect(hdc, rc, lerp_color(start, end, 0.5), radius);
        return;
    }

    let _ = SelectClipRgn(hdc, region);
    if horizontal {
        fill_gradient_h(hdc, rc, start, end);
    } else {
        fill_gradient_v(hdc, rc, start, end);
    }
    let _ = SelectClipRgn(hdc, None);
    let _ = DelObj(region);
}

pub unsafe fn fill_circle(hdc: HDC, cx: i32, cy: i32, radius: i32, color: u32) {
    let brush = CreateSolidBrush(COLORREF(color));
    let pen = CreatePen(PS_NULL, 0, COLORREF(0));
    let old_brush = SelectObject(hdc, brush);
    let old_pen = SelectObject(hdc, pen);
    let _ = Ellipse(hdc, cx - radius, cy - radius, cx + radius, cy + radius);
    SelectObject(hdc, old_brush);
    SelectObject(hdc, old_pen);
    let _ = DeleteObject(brush);
    let _ = DeleteObject(pen);
}

/// Anneau (cercle non rempli) d'épaisseur `width`.
pub unsafe fn stroke_circle(hdc: HDC, cx: i32, cy: i32, radius: i32, color: u32, width: i32) {
    let pen = CreatePen(PS_SOLID, width, COLORREF(color));
    let old_pen = SelectObject(hdc, pen);
    let old_brush = SelectObject(hdc, null_brush());
    let _ = Ellipse(hdc, cx - radius, cy - radius, cx + radius, cy + radius);
    SelectObject(hdc, old_pen);
    SelectObject(hdc, old_brush);
    let _ = DeleteObject(pen);
}

pub unsafe fn draw_text_in(
    hdc: HDC,
    rect: RECT,
    text: &str,
    color: u32,
    font: HFONT,
    format: DRAW_TEXT_FORMAT,
) {
    let old_font = SelectObject(hdc, font);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, COLORREF(color));
    let mut wide: Vec<u16> = text.encode_utf16().collect();
    let mut rc = rect;
    DrawTextW(hdc, &mut wide, &mut rc, format);
    SelectObject(hdc, old_font);
}

// ---------------------------------------------------------------------------
// Icônes vectorielles
// ---------------------------------------------------------------------------

/// Les icônes dessinées à la main, en remplacement des emojis (dont le rendu
/// dépend de la police installée et qui jurent avec le reste de l'interface).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Icon {
    /// Bouclier — identité de l'application, mode Fort.
    Shield,
    /// Cadenas fermé — mode Rapide.
    Lock,
    /// Clé — Master Password / recovery key.
    Key,
    /// Silhouette « incognito » (chapeau + lunettes) — popup mot de passe.
    Detective,
    /// Triangle d'alerte — zone de déverrouillage forcé.
    Warning,
}

/// Dessine `icon` centrée dans `rc`, suréchantillonnée puis réduite.
///
/// `background` doit être la couleur réellement présente sous l'icône : le DC
/// mémoire est opaque, donc c'est cette couleur qui se retrouve autour des
/// bords lissés. Sur un fond en dégradé, échantillonner la teinte à la hauteur
/// de l'icône suffit — la variation sur 50 px est invisible.
pub unsafe fn draw_icon(hdc: HDC, rc: RECT, icon: Icon, color: u32, background: u32) {
    let w = rc.right - rc.left;
    let h = rc.bottom - rc.top;
    if w <= 0 || h <= 0 {
        return;
    }
    let side = w.min(h);
    let big = side * SUPERSAMPLE;

    let mem_dc = CreateCompatibleDC(hdc);
    if mem_dc.is_invalid() {
        return;
    }
    let bitmap = CreateCompatibleBitmap(hdc, big, big);
    if bitmap.is_invalid() {
        let _ = DeleteDC(mem_dc);
        return;
    }
    let old_bitmap = SelectObject(mem_dc, bitmap);

    fill_rect(
        mem_dc,
        RECT { left: 0, top: 0, right: big, bottom: big },
        background,
    );

    match icon {
        Icon::Shield => draw_shield(mem_dc, big, color),
        Icon::Lock => draw_lock(mem_dc, big, color),
        Icon::Key => draw_key(mem_dc, big, color),
        Icon::Detective => draw_detective(mem_dc, big),
        Icon::Warning => draw_warning(mem_dc, big, color),
    }

    // `HALFTONE` fait la moyenne des pixels source — c'est lui qui produit
    // l'anti-aliasing. Windows exige un `SetBrushOrgEx` après (documenté).
    SetStretchBltMode(hdc, HALFTONE);
    let _ = SetBrushOrgEx(hdc, 0, 0, None);
    let x = rc.left + (w - side) / 2;
    let y = rc.top + (h - side) / 2;
    let _ = StretchBlt(hdc, x, y, side, side, mem_dc, 0, 0, big, big, SRCCOPY);

    SelectObject(mem_dc, old_bitmap);
    let _ = DeleteObject(bitmap);
    let _ = DeleteDC(mem_dc);
}

/// Convertit une coordonnée exprimée dans le repère normalisé 0..100 vers la
/// taille réelle du canevas. Toutes les icônes sont décrites dans ce repère,
/// ce qui les rend indépendantes de la taille de rendu.
fn u(canvas: i32, v: f32) -> i32 {
    (v / 100.0 * canvas as f32).round() as i32
}

fn pt(canvas: i32, x: f32, y: f32) -> POINT {
    POINT { x: u(canvas, x), y: u(canvas, y) }
}

/// Prépare un chemin plein : `BeginPath` … `EndPath` + `FillPath` avec la
/// brosse voulue et aucun contour.
unsafe fn with_filled_path(hdc: HDC, color: u32, build: impl FnOnce(HDC)) {
    let brush = CreateSolidBrush(COLORREF(color));
    let pen = CreatePen(PS_NULL, 0, COLORREF(0));
    let old_brush = SelectObject(hdc, brush);
    let old_pen = SelectObject(hdc, pen);

    let _ = BeginPath(hdc);
    build(hdc);
    let _ = EndPath(hdc);
    let _ = FillPath(hdc);

    SelectObject(hdc, old_brush);
    SelectObject(hdc, old_pen);
    let _ = DeleteObject(brush);
    let _ = DeleteObject(pen);
}

/// Bouclier : bord supérieur droit, flancs qui s'incurvent vers une pointe
/// basse. Les courbes sont des Bézier cubiques, d'où le lissage.
unsafe fn draw_shield(hdc: HDC, canvas: i32, color: u32) {
    with_filled_path(hdc, color, |dc| {
        let _ = MoveToEx(dc, u(canvas, 50.0), u(canvas, 6.0), None);
        let _ = LineTo(dc, u(canvas, 88.0), u(canvas, 20.0));
        let _ = LineTo(dc, u(canvas, 88.0), u(canvas, 50.0));
        let right = [
            pt(canvas, 88.0, 70.0),
            pt(canvas, 74.0, 86.0),
            pt(canvas, 50.0, 95.0),
        ];
        let _ = PolyBezierTo(dc, &right);
        let left = [
            pt(canvas, 26.0, 86.0),
            pt(canvas, 12.0, 70.0),
            pt(canvas, 12.0, 50.0),
        ];
        let _ = PolyBezierTo(dc, &left);
        let _ = LineTo(dc, u(canvas, 12.0), u(canvas, 20.0));
        let _ = CloseFigure(dc);
    });

    // Coche intérieure, dans une teinte plus sombre pour rester lisible quel
    // que soit le thème d'accent.
    let check = darken(color, 0.55);
    let pen_w = u(canvas, 7.0).max(1);
    let pen = CreatePen(PS_SOLID, pen_w, COLORREF(check));
    let old_pen = SelectObject(hdc, pen);
    let _ = MoveToEx(hdc, u(canvas, 33.0), u(canvas, 49.0), None);
    let _ = LineTo(hdc, u(canvas, 45.0), u(canvas, 62.0));
    let _ = LineTo(hdc, u(canvas, 69.0), u(canvas, 36.0));
    SelectObject(hdc, old_pen);
    let _ = DeleteObject(pen);
}

/// Cadenas : anse en arc épais, corps en rectangle arrondi, trou de serrure.
unsafe fn draw_lock(hdc: HDC, canvas: i32, color: u32) {
    // Anse (demi-cercle ouvert vers le bas).
    let shackle_w = u(canvas, 9.0).max(1);
    let pen = CreatePen(PS_SOLID, shackle_w, COLORREF(darken(color, 0.2)));
    let old_pen = SelectObject(hdc, pen);
    let old_brush = SelectObject(hdc, null_brush());
    let _ = Pie(
        hdc,
        u(canvas, 27.0),
        u(canvas, 14.0),
        u(canvas, 73.0),
        u(canvas, 60.0),
        u(canvas, 27.0),
        u(canvas, 37.0),
        u(canvas, 73.0),
        u(canvas, 37.0),
    );
    SelectObject(hdc, old_pen);
    SelectObject(hdc, old_brush);
    let _ = DeleteObject(pen);

    // Corps.
    fill_round_rect(
        hdc,
        RECT {
            left: u(canvas, 18.0),
            top: u(canvas, 44.0),
            right: u(canvas, 82.0),
            bottom: u(canvas, 90.0),
        },
        color,
        u(canvas, 12.0),
    );

    // Trou de serrure.
    let hole = darken(color, 0.6);
    fill_circle(hdc, u(canvas, 50.0), u(canvas, 62.0), u(canvas, 8.0), hole);
    with_filled_path(hdc, hole, |dc| {
        let _ = MoveToEx(dc, u(canvas, 46.0), u(canvas, 64.0), None);
        let _ = LineTo(dc, u(canvas, 54.0), u(canvas, 64.0));
        let _ = LineTo(dc, u(canvas, 56.0), u(canvas, 80.0));
        let _ = LineTo(dc, u(canvas, 44.0), u(canvas, 80.0));
        let _ = CloseFigure(dc);
    });
}

/// Clé : anneau à gauche, tige horizontale, deux dents.
unsafe fn draw_key(hdc: HDC, canvas: i32, color: u32) {
    stroke_circle(
        hdc,
        u(canvas, 28.0),
        u(canvas, 50.0),
        u(canvas, 18.0),
        color,
        u(canvas, 9.0).max(1),
    );
    fill_rect(
        hdc,
        RECT {
            left: u(canvas, 44.0),
            top: u(canvas, 45.0),
            right: u(canvas, 88.0),
            bottom: u(canvas, 55.0),
        },
        color,
    );
    for x in [64.0f32, 78.0f32] {
        fill_rect(
            hdc,
            RECT {
                left: u(canvas, x),
                top: u(canvas, 55.0),
                right: u(canvas, x + 9.0),
                bottom: u(canvas, 70.0),
            },
            color,
        );
    }
}

/// Silhouette « incognito » : épaules, tête, chapeau fedora, lunettes.
/// Couleurs fixes (gris) plutôt que l'accent du thème — c'est un élément
/// décoratif neutre, qui ne doit pas rivaliser avec le bouton Valider.
unsafe fn draw_detective(hdc: HDC, canvas: i32) {
    const COAT: u32 = 0x00555555;
    const SKIN: u32 = 0x00666666;
    const HAT: u32 = 0x00505050;
    const GLASS_FILL: u32 = 0x00333333;
    const GLASS_RIM: u32 = 0x00888888;

    // Épaules : demi-disque en bas.
    let old_brush = SelectObject(hdc, CreateSolidBrush(COLORREF(COAT)));
    let old_pen = SelectObject(hdc, CreatePen(PS_NULL, 0, COLORREF(0)));
    let _ = Pie(
        hdc,
        u(canvas, 10.0),
        u(canvas, 62.0),
        u(canvas, 90.0),
        u(canvas, 122.0),
        u(canvas, 90.0),
        u(canvas, 92.0),
        u(canvas, 10.0),
        u(canvas, 92.0),
    );
    let brush = SelectObject(hdc, old_brush);
    let pen = SelectObject(hdc, old_pen);
    let _ = DeleteObject(brush);
    let _ = DeleteObject(pen);

    // Tête.
    fill_circle(hdc, u(canvas, 50.0), u(canvas, 50.0), u(canvas, 23.0), SKIN);

    // Chapeau : calotte trapézoïdale puis bord large.
    with_filled_path(hdc, HAT, |dc| {
        let _ = MoveToEx(dc, u(canvas, 33.0), u(canvas, 34.0), None);
        let _ = LineTo(dc, u(canvas, 38.0), u(canvas, 17.0));
        let _ = LineTo(dc, u(canvas, 62.0), u(canvas, 17.0));
        let _ = LineTo(dc, u(canvas, 67.0), u(canvas, 34.0));
        let _ = CloseFigure(dc);
    });
    let old_brush = SelectObject(hdc, CreateSolidBrush(COLORREF(HAT)));
    let old_pen = SelectObject(hdc, CreatePen(PS_NULL, 0, COLORREF(0)));
    let _ = Ellipse(
        hdc,
        u(canvas, 16.0),
        u(canvas, 30.0),
        u(canvas, 84.0),
        u(canvas, 42.0),
    );
    let brush = SelectObject(hdc, old_brush);
    let pen = SelectObject(hdc, old_pen);
    let _ = DeleteObject(brush);
    let _ = DeleteObject(pen);

    // Lunettes : deux verres reliés par un pont.
    for cx in [39.0f32, 61.0f32] {
        fill_circle(hdc, u(canvas, cx), u(canvas, 52.0), u(canvas, 9.0), GLASS_FILL);
        stroke_circle(
            hdc,
            u(canvas, cx),
            u(canvas, 52.0),
            u(canvas, 9.0),
            GLASS_RIM,
            u(canvas, 3.0).max(1),
        );
    }
    let pen = CreatePen(PS_SOLID, u(canvas, 3.0).max(1), COLORREF(GLASS_RIM));
    let old_pen = SelectObject(hdc, pen);
    let _ = MoveToEx(hdc, u(canvas, 48.0), u(canvas, 52.0), None);
    let _ = LineTo(hdc, u(canvas, 52.0), u(canvas, 52.0));
    SelectObject(hdc, old_pen);
    let _ = DeleteObject(pen);
}

/// Triangle d'alerte à coins légèrement adoucis, avec point d'exclamation.
unsafe fn draw_warning(hdc: HDC, canvas: i32, color: u32) {
    with_filled_path(hdc, color, |dc| {
        let _ = MoveToEx(dc, u(canvas, 50.0), u(canvas, 10.0), None);
        let _ = LineTo(dc, u(canvas, 94.0), u(canvas, 86.0));
        let _ = LineTo(dc, u(canvas, 6.0), u(canvas, 86.0));
        let _ = CloseFigure(dc);
    });

    let mark = 0x001a1a1a;
    fill_rect(
        hdc,
        RECT {
            left: u(canvas, 45.0),
            top: u(canvas, 38.0),
            right: u(canvas, 55.0),
            bottom: u(canvas, 66.0),
        },
        mark,
    );
    fill_circle(hdc, u(canvas, 50.0), u(canvas, 76.0), u(canvas, 6.0), mark);
}

// ---------------------------------------------------------------------------
// Double buffering
// ---------------------------------------------------------------------------

/// DC mémoire de la taille d'un contrôle, recopié d'un coup à la fin.
///
/// Les contrôles animés (cartes, header, barre de force) sont repeints
/// plusieurs fois par seconde : dessiner directement dans le DC écran ferait
/// scintiller le fond dégradé à chaque frame.
pub struct BackBuffer {
    pub dc: HDC,
    bitmap: windows::Win32::Graphics::Gdi::HBITMAP,
    old_bitmap: windows::Win32::Graphics::Gdi::HGDIOBJ,
    target: HDC,
    rc: RECT,
}

impl BackBuffer {
    pub unsafe fn new(target: HDC, rc: RECT) -> Option<Self> {
        let w = rc.right - rc.left;
        let h = rc.bottom - rc.top;
        if w <= 0 || h <= 0 {
            return None;
        }
        let dc = CreateCompatibleDC(target);
        if dc.is_invalid() {
            return None;
        }
        let bitmap = CreateCompatibleBitmap(target, w, h);
        if bitmap.is_invalid() {
            let _ = DeleteDC(dc);
            return None;
        }
        let old_bitmap = SelectObject(dc, bitmap);
        Some(BackBuffer { dc, bitmap, old_bitmap, target, rc })
    }

    /// Recopie le tampon vers l'écran et libère les objets GDI.
    pub unsafe fn present(self) {
        let w = self.rc.right - self.rc.left;
        let h = self.rc.bottom - self.rc.top;
        let _ = StretchBlt(
            self.target, self.rc.left, self.rc.top, w, h, self.dc, 0, 0, w, h, SRCCOPY,
        );
        SelectObject(self.dc, self.old_bitmap);
        let _ = DeleteObject(self.bitmap);
        let _ = DeleteDC(self.dc);
    }

    /// Rectangle local au tampon (origine 0,0).
    pub fn local(&self) -> RECT {
        RECT {
            left: 0,
            top: 0,
            right: self.rc.right - self.rc.left,
            bottom: self.rc.bottom - self.rc.top,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lerp_endpoints_are_exact() {
        assert_eq!(lerp_color(0x00112233, 0x00AABBCC, 0.0), 0x00112233);
        assert_eq!(lerp_color(0x00112233, 0x00AABBCC, 1.0), 0x00AABBCC);
    }

    /// Une progression qui déborde (timer en retard) ne doit pas produire une
    /// couleur aberrante par débordement de `u8`.
    #[test]
    fn lerp_clamps_out_of_range_progress() {
        assert_eq!(lerp_color(0x00000000, 0x00FFFFFF, 2.5), 0x00FFFFFF);
        assert_eq!(lerp_color(0x00000000, 0x00FFFFFF, -1.0), 0x00000000);
    }

    #[test]
    fn channels_round_trip() {
        for color in [0x00000000u32, 0x00FFFFFF, 0x002d2d2d, 0x003c4ce7] {
            let (r, g, b) = channels(color);
            assert_eq!(from_channels(r, g, b), color, "couleur {color:#08x}");
        }
    }

    #[test]
    fn lighten_and_darken_move_in_opposite_directions() {
        let base = 0x00808080;
        let (r_light, _, _) = channels(lighten(base, 0.5));
        let (r_dark, _, _) = channels(darken(base, 0.5));
        assert!(r_light > 0x80, "éclaircir doit augmenter la composante");
        assert!(r_dark < 0x80, "assombrir doit la diminuer");
    }

    #[test]
    fn ease_out_cubic_starts_fast_and_settles() {
        assert_eq!(ease_out_cubic(0.0), 0.0);
        assert_eq!(ease_out_cubic(1.0), 1.0);
        // À mi-parcours, une décélération cubique a déjà couvert ~87 %.
        assert!(ease_out_cubic(0.5) > 0.8);
        // Monotone croissante.
        let mut previous = 0.0;
        for step in 0..=20 {
            let value = ease_out_cubic(step as f32 / 20.0);
            assert!(value >= previous, "doit être monotone");
            previous = value;
        }
    }

    #[test]
    fn over_blends_towards_the_foreground() {
        let bg = 0x00000000;
        let fg = 0x00FFFFFF;
        assert_eq!(over(fg, bg, 0.0), bg);
        assert_eq!(over(fg, bg, 1.0), fg);
        let (r, _, _) = channels(over(fg, bg, 0.25));
        assert!((0x3E..=0x41).contains(&r), "25 % de blanc sur noir ≈ 0x40");
    }
}

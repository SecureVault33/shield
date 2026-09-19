//! Constantes du thème sombre, partagées par toutes les popups Win32. Seule
//! la couleur d'accent varie selon le thème choisi dans les paramètres
//! (Rouge/Bleu/Vert) — les fonds, textes et couleurs de force de mot de
//! passe restent identiques quel que soit le thème.

use std::sync::OnceLock;

/// Couleurs au format COLORREF Win32 (0x00BBGGRR).
pub const COLOR_BACKGROUND: u32 = 0x001a1a1a; // #1a1a1a
pub const COLOR_BACKGROUND_BOTTOM: u32 = 0x000f0f0f; // #0f0f0f (bas du dégradé de fond)
pub const COLOR_TEXT: u32 = 0x00f0f0f0; // #f0f0f0
pub const COLOR_FIELD_BACKGROUND: u32 = 0x002d2d2d; // #2d2d2d
pub const COLOR_FIELD_BORDER_INNER: u32 = 0x003d3d3d; // #3d3d3d (liseré intérieur, "ombre" du champ)
pub const COLOR_SEPARATOR: u32 = 0x00333333; // #333333
pub const COLOR_TEXT_MUTED: u32 = 0x00888888; // #888888
pub const COLOR_TEXT_HOVER: u32 = 0x00bbbbbb; // #bbbbbb
pub const COLOR_WHITE: u32 = 0x00ffffff;

/// Lignes de la ListView — contraste renforcé en 0.8.0 (les anciennes
/// #252525/#2d2d2d se distinguaient à peine sur un écran non calibré).
pub const COLOR_ROW_EVEN: u32 = 0x001e1e1e; // #1e1e1e
pub const COLOR_ROW_ODD: u32 = 0x00262626; // #262626
pub const COLOR_ROW_HOVER: u32 = 0x00303030; // #303030

/// Cartes statistiques : fond au repos et au survol.
pub const COLOR_CARD_BG: u32 = 0x002d2d2d; // #2d2d2d
pub const COLOR_CARD_HOVER: u32 = 0x00363636; // #363636
pub const COLOR_CARD_BORDER: u32 = 0x00333333; // #333333

/// Boutons secondaires (fond transparent, contour discret).
pub const COLOR_BTN_SECONDARY_BORDER: u32 = 0x00444444; // #444444
pub const COLOR_BTN_SECONDARY_TEXT: u32 = 0x00cccccc; // #cccccc

/// Actions destructrices / élévation de privilèges. Orange fixe, jamais la
/// couleur d'accent : « attention » ne doit pas dépendre du thème choisi,
/// sinon un thème rouge rendrait le bouton dangereux indiscernable d'un
/// bouton normal.
pub const COLOR_DANGER: u32 = 0x00227ee6; // #e67e22
pub const COLOR_DANGER_ZONE_BG: u32 = 0x0000121a; // #1a1200 (noir très légèrement chaud)

/// Pastilles de statut de la ListView. Fixes elles aussi : ce sont des
/// informations sémantiques (comme les couleurs de force du mot de passe).
pub const COLOR_STATUS_ACL: u32 = 0x00227ee6; // #e67e22 — verrouillé (Rapide)
pub const COLOR_STATUS_ENCRYPTED: u32 = 0x002b39c0; // #c0392b — chiffré (Fort)
pub const COLOR_STATUS_UNLOCKED: u32 = 0x0060ae27; // #27ae60 — exposé

/// Puces de progression de l'onboarding (inactives).
pub const COLOR_DOT_INACTIVE: u32 = 0x00555555; // #555555

/// Barre de statut de licence du dashboard (1.0.0).
pub const COLOR_STATUS_BAR_BG: u32 = 0x00141414; // #141414
pub const COLOR_ERROR: u32 = 0x003c4ce7; // #e74c3c
pub const COLOR_ICON: u32 = 0x00888888; // #888888

/// Couleurs de l'indicateur de force du mot de passe (5 niveaux) — fixes,
/// indépendantes du thème d'accent.
pub const COLOR_STRENGTH_VERY_WEAK: u32 = 0x003c4ce7; // #e74c3c
pub const COLOR_STRENGTH_WEAK: u32 = 0x00227ee6; // #e67e22
pub const COLOR_STRENGTH_MEDIUM: u32 = 0x000fc4f1; // #f1c40f
pub const COLOR_STRENGTH_STRONG: u32 = 0x0071cc2e; // #2ecc71
pub const COLOR_STRENGTH_VERY_STRONG: u32 = 0x0060ae27; // #27ae60

/// Police par défaut de toute l'UI.
pub const FONT_FACE: &str = "Segoe UI";
pub const FONT_SIZE_PX: i32 = 14;
/// Police de l'icône "incognito" en haut de la popup (grand emoji).
pub const ICON_FONT_SIZE_PX: i32 = 32;

/// Dimensions des fenêtres popup (largeur x hauteur, en pixels client).
pub const WINDOW_WIDTH: i32 = 420;
pub const WINDOW_HEIGHT_SIMPLE: i32 = 342;
pub const WINDOW_HEIGHT_CONFIRM: i32 = 402;

/// Marge standard utilisée pour la mise en page des contrôles.
pub const MARGIN: i32 = 20;

/// Couleurs d'accent d'un thème : c'est la SEULE chose qui change entre
/// Rouge/Bleu/Vert. Bordures de champs, bouton "Valider", onglets actifs,
/// séparateurs... tous utilisent `accent_start()`/`accent_end()`.
#[derive(Debug, Clone, Copy)]
pub struct ThemeColors {
    pub accent_start: u32,
    pub accent_end: u32,
    pub accent_hover_start: u32,
    pub accent_hover_end: u32,
}

/// Thème actif, initialisé une fois au démarrage depuis les paramètres
/// (voir `init_theme`). Un `OnceLock` plutôt qu'un paramètre propagé à
/// travers toutes les fonctions UI — plus simple, et le thème ne change de
/// toute façon qu'au redémarrage du dashboard (voir la note dans
/// `dashboard::window::on_save_settings`).
static CURRENT_THEME: OnceLock<ThemeColors> = OnceLock::new();

/// Retourne les couleurs d'accent pour un nom de thème (`"red"` par défaut
/// si inconnu).
pub fn get_theme(name: &str) -> ThemeColors {
    match name {
        "blue" => ThemeColors {
            accent_start: 0x00a84c2c,       // #2c4ca8 (bleu sombre)
            accent_end: 0x00e07040,         // #4070e0 (bleu vif)
            accent_hover_start: 0x00c05c38, // légèrement plus clair
            accent_hover_end: 0x00f08050,
        },
        "green" => ThemeColors {
            accent_start: 0x002b8c27,       // #278c2b (vert sombre)
            accent_end: 0x0043cc2e,         // #2ecc43 (vert vif)
            accent_hover_start: 0x0038a032,
            accent_hover_end: 0x0055dc42,
        },
        _ => ThemeColors {
            accent_start: 0x002b39c0,       // #c0392b (rouge sombre)
            accent_end: 0x003c4ce7,         // #e74c3c (rouge vif)
            accent_hover_start: 0x003746d4,
            accent_hover_end: 0x004e5cf2,
        },
    }
}

/// Initialise le thème actif pour tout le processus — à appeler une seule
/// fois, tôt dans `main()`. Sans appel préalable, les accesseurs retombent
/// sur le thème rouge par défaut (`get_or_init`).
pub fn init_theme(name: &str) {
    let _ = CURRENT_THEME.set(get_theme(name));
}

fn current() -> &'static ThemeColors {
    CURRENT_THEME.get_or_init(|| get_theme("red"))
}

pub fn accent_start() -> u32 {
    current().accent_start
}

pub fn accent_end() -> u32 {
    current().accent_end
}

pub fn accent_hover_start() -> u32 {
    current().accent_hover_start
}

pub fn accent_hover_end() -> u32 {
    current().accent_hover_end
}

/// Couleur de bordure des champs = couleur d'accent du thème.
pub fn field_border() -> u32 {
    accent_start()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_named_theme_has_distinct_accent_colors() {
        let red = get_theme("red");
        let blue = get_theme("blue");
        let green = get_theme("green");

        assert_ne!(red.accent_start, blue.accent_start);
        assert_ne!(red.accent_start, green.accent_start);
        assert_ne!(blue.accent_start, green.accent_start);
    }

    #[test]
    fn unknown_theme_name_falls_back_to_red() {
        let unknown = get_theme("purple");
        let red = get_theme("red");
        assert_eq!(unknown.accent_start, red.accent_start);
        assert_eq!(unknown.accent_end, red.accent_end);
    }

    #[test]
    fn each_theme_hover_colors_differ_from_base_colors() {
        for name in ["red", "blue", "green"] {
            let theme = get_theme(name);
            assert_ne!(theme.accent_start, theme.accent_hover_start, "theme {name}");
            assert_ne!(theme.accent_end, theme.accent_hover_end, "theme {name}");
        }
    }
}

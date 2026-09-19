//! Génération programmatique d'icônes `.ico` colorées pour les entrées du
//! menu contextuel. Pas de dépendance externe : on construit le format ICO
//! brut (ICONDIR + ICONDIRENTRY + BITMAPINFOHEADER 32bpp + masque AND) à la
//! main, et on dessine des formes simples (cadenas, bouclier, clé) en traçant
//! directement des rectangles/cercles dans le buffer de pixels.

use crate::errors::Result;
use std::path::{Path, PathBuf};

const SIZE: usize = 32;

#[derive(Clone, Copy)]
enum Shape {
    Lock,
    Unlock,
    Shield,
    Key,
}

/// Une icône à générer : nom de fichier, couleur (R, G, B), forme.
struct IconSpec {
    file_name: &'static str,
    color: (u8, u8, u8),
    shape: Shape,
}

const ICON_SPECS: [IconSpec; 4] = [
    IconSpec { file_name: "lock.ico", color: (0xc0, 0x39, 0x2b), shape: Shape::Lock },
    IconSpec { file_name: "unlock.ico", color: (0x27, 0xae, 0x60), shape: Shape::Unlock },
    IconSpec { file_name: "encrypt.ico", color: (0xc0, 0x39, 0x2b), shape: Shape::Shield },
    IconSpec { file_name: "decrypt.ico", color: (0xf3, 0x9c, 0x12), shape: Shape::Key },
];

/// Trace `shape` en couleur `color` (RGB) dans une grille `SIZE`x`SIZE` de
/// pixels RGBA (transparent par défaut). Formes simplifiées en "pixel art" :
/// pas de rendu vectoriel, juste des rectangles/cercles, suffisant pour une
/// icône 32x32 de menu contextuel.
fn set_pixel(pixels: &mut [[u8; 4]], color: (u8, u8, u8), x: i32, y: i32) {
    let (r, g, b) = color;
    if x >= 0 && y >= 0 && (x as usize) < SIZE && (y as usize) < SIZE {
        pixels[y as usize * SIZE + x as usize] = [b, g, r, 255];
    }
}

fn fill_rect(pixels: &mut [[u8; 4]], color: (u8, u8, u8), x0: i32, y0: i32, x1: i32, y1: i32) {
    for y in y0..y1 {
        for x in x0..x1 {
            set_pixel(pixels, color, x, y);
        }
    }
}

fn draw_shape(shape: Shape, color: (u8, u8, u8)) -> Vec<[u8; 4]> {
    let mut pixels = vec![[0u8, 0, 0, 0]; SIZE * SIZE];

    match shape {
        Shape::Lock => {
            // Anse (forme en U) : deux montants + une barre horizontale.
            fill_rect(&mut pixels, color, 10, 6, 13, 17);
            fill_rect(&mut pixels, color, 19, 6, 22, 17);
            fill_rect(&mut pixels, color, 10, 6, 22, 9);
            // Corps du cadenas.
            fill_rect(&mut pixels, color, 8, 15, 24, 28);
        }
        Shape::Unlock => {
            // Anse ouverte : relevée et décalée d'un côté (asymétrique,
            // pour se distinguer visuellement du cadenas fermé).
            fill_rect(&mut pixels, color, 8, 4, 11, 15);
            fill_rect(&mut pixels, color, 8, 4, 24, 7);
            // Corps, identique au cadenas fermé.
            fill_rect(&mut pixels, color, 8, 15, 24, 28);
        }
        Shape::Shield => {
            // Haut rectangulaire, bas qui se resserre en triangle (pointe).
            fill_rect(&mut pixels, color, 8, 4, 24, 18);
            for y in 18..29 {
                let t = (y - 18) as f32 / (29 - 18) as f32;
                let half = (8.0 * (1.0 - t)) as i32;
                for x in (16 - half)..(16 + half) {
                    set_pixel(&mut pixels, color, x, y);
                }
            }
        }
        Shape::Key => {
            // Anneau (panneton) : disque évidé au centre.
            let (cx, cy) = (11i32, 11i32);
            for y in 0..SIZE as i32 {
                for x in 0..SIZE as i32 {
                    let dx = x - cx;
                    let dy = y - cy;
                    let d2 = dx * dx + dy * dy;
                    if (16..=49).contains(&d2) {
                        set_pixel(&mut pixels, color, x, y);
                    }
                }
            }
            // Tige.
            fill_rect(&mut pixels, color, 11, 9, 27, 13);
            // Dents.
            fill_rect(&mut pixels, color, 19, 13, 22, 18);
            fill_rect(&mut pixels, color, 23, 13, 26, 21);
        }
    }

    pixels
}

/// Encode une grille de pixels RGBA `SIZE`x`SIZE` en fichier `.ico` brut
/// (une seule image, 32 bits par pixel avec canal alpha).
fn encode_ico(pixels: &[[u8; 4]]) -> Vec<u8> {
    let w = SIZE;
    let h = SIZE;
    let image_size = w * h * 4;
    let mask_row_bytes = w.div_ceil(32) * 4;
    let mask_size = mask_row_bytes * h;
    let header_size = 40usize;
    let bytes_in_res = header_size + image_size + mask_size;

    let mut out = Vec::with_capacity(6 + 16 + bytes_in_res);

    // ICONDIR
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&1u16.to_le_bytes()); // type = icone
    out.extend_from_slice(&1u16.to_le_bytes()); // 1 image

    // ICONDIRENTRY
    out.push(w as u8);
    out.push(h as u8);
    out.push(0); // pas de palette
    out.push(0); // réservé
    out.extend_from_slice(&1u16.to_le_bytes()); // plans
    out.extend_from_slice(&32u16.to_le_bytes()); // bits/pixel
    out.extend_from_slice(&(bytes_in_res as u32).to_le_bytes());
    out.extend_from_slice(&22u32.to_le_bytes()); // offset (6 + 16)

    // BITMAPINFOHEADER
    out.extend_from_slice(&40u32.to_le_bytes()); // biSize
    out.extend_from_slice(&(w as i32).to_le_bytes()); // biWidth
    out.extend_from_slice(&((h * 2) as i32).to_le_bytes()); // biHeight (XOR+AND)
    out.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
    out.extend_from_slice(&32u16.to_le_bytes()); // biBitCount
    out.extend_from_slice(&0u32.to_le_bytes()); // biCompression = BI_RGB
    out.extend_from_slice(&(image_size as u32).to_le_bytes()); // biSizeImage
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());

    // Pixels BGRA, bas en haut (convention BMP/ICO).
    for row in (0..h).rev() {
        for col in 0..w {
            out.extend_from_slice(&pixels[row * w + col]);
        }
    }

    // Masque AND : tout à zéro (opaque), le canal alpha gère la vraie
    // transparence en 32bpp — convention standard pour les icônes modernes.
    out.extend(std::iter::repeat(0u8).take(mask_size));

    out
}

/// Écrit les 4 icônes `.ico` dans `dir` (créé si besoin). Idempotent : les
/// fichiers sont régénérés à chaque appel (déterministe, pas de contrôle de
/// version nécessaire pour un simple pictogramme).
pub fn write_icons(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    for spec in &ICON_SPECS {
        let pixels = draw_shape(spec.shape, spec.color);
        let bytes = encode_ico(&pixels);
        std::fs::write(dir.join(spec.file_name), bytes)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Icône de l'application (0.8.0)
// ---------------------------------------------------------------------------

/// Nom du fichier d'icône de l'application.
pub const APP_ICON_FILE: &str = "app.ico";

/// Tailles présentes dans `app.ico`. Windows pioche la plus adaptée selon le
/// contexte (16 = barre de titre, 32 = barre des tâches, 48 = grandes icônes,
/// 256 = vignettes de l'Explorateur).
const APP_ICON_SIZES: [usize; 4] = [16, 32, 48, 256];

/// Sous-échantillons par axe pour l'anti-aliasing (16 échantillons/pixel).
const APP_ICON_SS: usize = 4;

/// Silhouette du bouclier dans un repère normalisé 0..1.
///
/// Flancs droits jusqu'à mi-hauteur, puis affinement elliptique vers une
/// pointe basse — le profil classique d'un écu. Décrit analytiquement plutôt
/// que par un chemin GDI : `icons.rs` reste utilisable hors contexte
/// graphique (et donc testable).
fn shield_contains(u: f32, v: f32) -> bool {
    const TOP: f32 = 0.06;
    const SHOULDER: f32 = 0.14;
    const WAIST: f32 = 0.48;
    const BOTTOM: f32 = 0.96;
    const HALF: f32 = 0.38;

    if v < TOP || v > BOTTOM {
        return false;
    }
    let half_width = if v < SHOULDER {
        // Épaules légèrement biseautées.
        HALF * (0.78 + 0.22 * (v - TOP) / (SHOULDER - TOP))
    } else if v <= WAIST {
        HALF
    } else {
        let k = (v - WAIST) / (BOTTOM - WAIST);
        HALF * (1.0 - k * k).max(0.0).sqrt()
    };
    (u - 0.5).abs() <= half_width
}

/// Coche intérieure : distance à une polyligne à deux segments.
fn check_contains(u: f32, v: f32) -> bool {
    const THICKNESS: f32 = 0.052;
    const POINTS: [(f32, f32); 3] = [(0.32, 0.50), (0.45, 0.63), (0.70, 0.36)];

    for pair in POINTS.windows(2) {
        let (x0, y0) = pair[0];
        let (x1, y1) = pair[1];
        let (dx, dy) = (x1 - x0, y1 - y0);
        let len2 = dx * dx + dy * dy;
        let t = if len2 == 0.0 {
            0.0
        } else {
            (((u - x0) * dx + (v - y0) * dy) / len2).clamp(0.0, 1.0)
        };
        let (px, py) = (x0 + t * dx, y0 + t * dy);
        let dist = ((u - px).powi(2) + (v - py).powi(2)).sqrt();
        if dist <= THICKNESS {
            return true;
        }
    }
    false
}

/// Rend le bouclier à `size`×`size` en BGRA prémultiplié-compatible.
///
/// L'alpha vient du taux de couverture des sous-échantillons : c'est ce qui
/// donne des bords lisses sans GDI+ ni bibliothèque de rendu.
fn render_app_icon(size: usize, color: (u8, u8, u8)) -> Vec<[u8; 4]> {
    let (r, g, b) = color;
    let mut pixels = vec![[0u8, 0, 0, 0]; size * size];
    let total = (APP_ICON_SS * APP_ICON_SS) as f32;

    for y in 0..size {
        for x in 0..size {
            let mut inside = 0f32;
            let mut on_check = 0f32;
            for sy in 0..APP_ICON_SS {
                for sx in 0..APP_ICON_SS {
                    let u = (x as f32 + (sx as f32 + 0.5) / APP_ICON_SS as f32) / size as f32;
                    let v = (y as f32 + (sy as f32 + 0.5) / APP_ICON_SS as f32) / size as f32;
                    if shield_contains(u, v) {
                        inside += 1.0;
                        if check_contains(u, v) {
                            on_check += 1.0;
                        }
                    }
                }
            }
            if inside == 0.0 {
                continue;
            }
            let alpha = (inside / total * 255.0).round() as u8;
            // Proportion de la surface couverte occupée par la coche.
            let check_ratio = on_check / inside;
            let mix = |base: u8| -> u8 {
                (base as f32 + (255.0 - base as f32) * check_ratio).round() as u8
            };
            pixels[y * size + x] = [mix(b), mix(g), mix(r), alpha];
        }
    }
    pixels
}

/// Encode plusieurs tailles dans un seul `.ico`.
fn encode_multi_ico(images: &[(usize, Vec<[u8; 4]>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(images.len() as u16).to_le_bytes());

    // Les données suivent le répertoire : le premier offset est donc
    // 6 (ICONDIR) + 16 octets par entrée.
    let mut offset = 6 + 16 * images.len();
    let mut bodies = Vec::new();

    for (size, pixels) in images {
        let mask_row_bytes = size.div_ceil(32) * 4;
        let mask_size = mask_row_bytes * size;
        let image_size = size * size * 4;
        let bytes_in_res = 40 + image_size + mask_size;

        // 0 signifie 256 dans le format ICO (le champ ne fait qu'un octet).
        out.push(if *size >= 256 { 0 } else { *size as u8 });
        out.push(if *size >= 256 { 0 } else { *size as u8 });
        out.push(0);
        out.push(0);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&(bytes_in_res as u32).to_le_bytes());
        out.extend_from_slice(&(offset as u32).to_le_bytes());
        offset += bytes_in_res;

        let mut body = Vec::with_capacity(bytes_in_res);
        body.extend_from_slice(&40u32.to_le_bytes());
        body.extend_from_slice(&(*size as i32).to_le_bytes());
        body.extend_from_slice(&((*size * 2) as i32).to_le_bytes());
        body.extend_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&32u16.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&(image_size as u32).to_le_bytes());
        body.extend_from_slice(&0i32.to_le_bytes());
        body.extend_from_slice(&0i32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        for row in (0..*size).rev() {
            for col in 0..*size {
                body.extend_from_slice(&pixels[row * size + col]);
            }
        }
        body.extend(std::iter::repeat(0u8).take(mask_size));
        bodies.push(body);
    }

    for body in bodies {
        out.extend_from_slice(&body);
    }
    out
}

/// Écrit `app.ico` (16/32/48/256) dans `dir`, dans la couleur d'accent du
/// thème courant — l'icône suit donc le thème choisi par l'utilisateur.
pub fn write_app_icon(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let accent = crate::ui::theme::accent_end();
    let color = (
        (accent & 0xFF) as u8,
        ((accent >> 8) & 0xFF) as u8,
        ((accent >> 16) & 0xFF) as u8,
    );
    let images: Vec<(usize, Vec<[u8; 4]>)> = APP_ICON_SIZES
        .iter()
        .map(|&size| (size, render_app_icon(size, color)))
        .collect();
    std::fs::write(dir.join(APP_ICON_FILE), encode_multi_ico(&images))?;
    Ok(())
}

/// Chemin de l'icône générée pour une entrée de menu donnée (`"lock.ico"`, etc.).
pub fn icon_path(dir: &Path, file_name: &str) -> PathBuf {
    dir.join(file_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shield_geometry_is_plausible() {
        // Centre du bouclier : plein.
        assert!(shield_contains(0.5, 0.3));
        // Au-dessus du sommet et sous la pointe : vide.
        assert!(!shield_contains(0.5, 0.02));
        assert!(!shield_contains(0.5, 0.99));
        // Les coins hauts sont hors de la silhouette (flancs à ±0.38).
        assert!(!shield_contains(0.02, 0.3));
        assert!(!shield_contains(0.98, 0.3));
        // La base s'affine : large à la taille, étroite près de la pointe.
        assert!(shield_contains(0.20, 0.45));
        assert!(!shield_contains(0.20, 0.92));
    }

    #[test]
    fn check_mark_sits_inside_the_shield() {
        // Chaque sommet de la coche doit être dans la silhouette, sinon la
        // coche déborderait sur le fond transparent.
        for (u, v) in [(0.32f32, 0.50f32), (0.45, 0.63), (0.70, 0.36)] {
            assert!(check_contains(u, v), "sommet ({u}, {v}) hors de la coche");
            assert!(shield_contains(u, v), "sommet ({u}, {v}) hors du bouclier");
        }
        assert!(!check_contains(0.5, 0.15));
    }

    /// L'anti-aliasing doit produire des alphas intermédiaires sur le
    /// contour : sans eux l'icône serait crénelée.
    #[test]
    fn rendered_icon_has_antialiased_edges() {
        let pixels = render_app_icon(48, (0xe7, 0x4c, 0x3c));
        let opaque = pixels.iter().filter(|p| p[3] == 255).count();
        let partial = pixels.iter().filter(|p| p[3] > 0 && p[3] < 255).count();
        let empty = pixels.iter().filter(|p| p[3] == 0).count();

        assert!(opaque > 200, "le bouclier doit couvrir une vraie surface");
        assert!(partial > 40, "les bords doivent être lissés ({partial} pixels partiels)");
        assert!(empty > 200, "les coins doivent rester transparents");
    }

    /// En-tête ICO : nombre d'images, et offsets cohérents avec les tailles
    /// annoncées (un offset faux donne une icône que Windows refuse).
    #[test]
    fn multi_ico_header_is_consistent() {
        let images: Vec<(usize, Vec<[u8; 4]>)> = [16usize, 32]
            .iter()
            .map(|&size| (size, render_app_icon(size, (0xff, 0x00, 0x00))))
            .collect();
        let ico = encode_multi_ico(&images);

        assert_eq!(&ico[0..2], &[0, 0], "champ réservé");
        assert_eq!(u16::from_le_bytes([ico[2], ico[3]]), 1, "type = icône");
        assert_eq!(u16::from_le_bytes([ico[4], ico[5]]), 2, "2 images");

        let mut expected_offset = 6 + 16 * 2;
        for index in 0..2 {
            let entry = 6 + 16 * index;
            let size = if ico[entry] == 0 { 256 } else { ico[entry] as usize };
            let bytes = u32::from_le_bytes(ico[entry + 8..entry + 12].try_into().unwrap()) as usize;
            let offset = u32::from_le_bytes(ico[entry + 12..entry + 16].try_into().unwrap()) as usize;

            let mask = size.div_ceil(32) * 4 * size;
            assert_eq!(bytes, 40 + size * size * 4 + mask, "taille image {size}");
            assert_eq!(offset, expected_offset, "offset image {size}");
            expected_offset += bytes;
        }
        assert_eq!(ico.len(), expected_offset, "taille totale du fichier");
    }

    /// Écrit `app.ico` sous `%TEMP%` pour inspection visuelle. `#[ignore]`
    /// car il produit un fichier au lieu de vérifier quelque chose :
    /// `cargo test --release -- --ignored dump_app_icon`.
    #[test]
    #[ignore = "génère un fichier pour inspection visuelle"]
    fn dump_app_icon() {
        let dir = std::env::temp_dir().join("securevault_icon_preview");
        write_app_icon(&dir).unwrap();
        println!("icône écrite dans {}", dir.join(APP_ICON_FILE).display());
    }

    /// 256 doit être encodé par 0 : le champ ne fait qu'un octet.
    #[test]
    fn size_256_is_encoded_as_zero() {
        // Buffer neutre à la bonne taille : seul l'en-tête est testé ici, pas
        // le rendu (un vrai rendu 256×256 coûterait un million d'échantillons).
        let images = vec![(256usize, vec![[0u8, 0, 0, 0]; 256 * 256])];
        let ico = encode_multi_ico(&images);
        assert_eq!(ico[6], 0, "largeur 256 encodée par 0");
        assert_eq!(ico[7], 0, "hauteur 256 encodée par 0");
    }
}

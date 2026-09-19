//! Empaquetage/désempaquetage de dossiers en archive tar (en mémoire), pour
//! le mode Chiffrement Fort appliqué à un dossier entier plutôt qu'à un
//! fichier unique (voir `aes_gcm::encrypt_path`/`decrypt_path`).

use crate::errors::Result;
use std::path::Path;

/// Empaquette récursivement `dir_path` (sous-dossiers vides inclus) dans une
/// archive tar en mémoire, avec des chemins relatifs à `dir_path`.
pub fn pack_directory(dir_path: &Path) -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    builder.append_dir_all("", dir_path)?;
    let buffer = builder.into_inner()?;
    Ok(buffer)
}

/// Extrait une archive tar (produite par `pack_directory`) dans `dest_path`,
/// recréant l'arborescence complète (fichiers et sous-dossiers, y compris vides).
pub fn unpack_directory(data: &[u8], dest_path: &Path) -> Result<()> {
    std::fs::create_dir_all(dest_path)?;
    let mut archive = tar::Archive::new(data);
    archive.unpack(dest_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("securevault_archive_test_{}_{name}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn round_trip_preserves_structure_including_empty_dirs() {
        let source = temp_dir("pack_source");
        fs::write(source.join("racine.txt"), b"contenu racine").unwrap();
        fs::create_dir_all(source.join("sous-dossier avec accents éà")).unwrap();
        fs::write(
            source.join("sous-dossier avec accents éà/fichier.txt"),
            b"contenu imbrique",
        )
        .unwrap();
        fs::create_dir_all(source.join("dossier_vide")).unwrap();
        fs::write(source.join("vide.txt"), b"").unwrap();

        let packed = pack_directory(&source).unwrap();
        assert!(!packed.is_empty());

        let dest = temp_dir("unpack_dest");
        unpack_directory(&packed, &dest).unwrap();

        assert_eq!(fs::read(dest.join("racine.txt")).unwrap(), b"contenu racine");
        assert_eq!(
            fs::read(dest.join("sous-dossier avec accents éà/fichier.txt")).unwrap(),
            b"contenu imbrique"
        );
        assert!(dest.join("dossier_vide").is_dir());
        assert_eq!(fs::read(dest.join("vide.txt")).unwrap(), b"");

        let _ = fs::remove_dir_all(&source);
        let _ = fs::remove_dir_all(&dest);
    }
}

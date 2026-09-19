use crate::errors::Result;
use rand::rngs::OsRng;
use rand::RngCore;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

const CHUNK_SIZE: usize = 64 * 1024;

/// Écrase le contenu d'un fichier en 3 passes (zéros, uns, aléatoire) avant de
/// le supprimer, pour limiter la récupération de données par des outils de
/// forensic sur disque classique.
pub fn secure_delete(path: &Path) -> Result<()> {
    let len = fs::metadata(path)?.len();
    let mut file = OpenOptions::new().write(true).open(path)?;

    overwrite_with_byte(&mut file, len, 0x00)?;
    overwrite_with_byte(&mut file, len, 0xFF)?;
    overwrite_with_random(&mut file, len)?;

    drop(file);
    fs::remove_file(path)?;
    Ok(())
}

fn overwrite_with_byte(file: &mut File, len: u64, byte: u8) -> Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let buf = vec![byte; CHUNK_SIZE.min(len.max(1) as usize)];
    let mut remaining = len;
    while remaining > 0 {
        let write_len = remaining.min(buf.len() as u64) as usize;
        file.write_all(&buf[..write_len])?;
        remaining -= write_len as u64;
    }
    file.flush()?;
    Ok(())
}

fn overwrite_with_random(file: &mut File, len: u64) -> Result<()> {
    file.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0u8; CHUNK_SIZE.min(len.max(1) as usize)];
    let mut remaining = len;
    while remaining > 0 {
        let write_len = remaining.min(buf.len() as u64) as usize;
        OsRng.fill_bytes(&mut buf[..write_len]);
        file.write_all(&buf[..write_len])?;
        remaining -= write_len as u64;
    }
    file.flush()?;
    Ok(())
}

/// Écrase puis supprime chaque fichier d'un dossier, récursivement, du plus
/// profond au moins profond (post-ordre : chaque sous-dossier est vidé avant
/// que son propre dossier ne soit supprimé), puis supprime les dossiers
/// eux-mêmes une fois vides. Utilisé après le chiffrement d'un dossier
/// entier : chaque fichier passe par les 3 passes d'écrasement de
/// `secure_delete` avant suppression, plutôt qu'un simple `fs::remove_dir_all`.
pub fn secure_delete_directory(dir_path: &Path) -> Result<()> {
    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            secure_delete_directory(&path)?;
        } else {
            secure_delete(&path)?;
        }
    }
    fs::remove_dir(dir_path)?;
    Ok(())
}

pub mod aes_gcm;
pub mod archive;
pub mod kdf;
pub mod recovery;
pub mod secure_delete;

pub use aes_gcm::{decrypt_path, encrypt_path, is_legacy_vault, verify_password};

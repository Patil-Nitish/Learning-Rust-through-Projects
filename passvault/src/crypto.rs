use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce
};
use rand::RngCore;
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose, Engine as _};

const NONCE_LEN: usize = 12;

fn derive_key(master_password: &str) -> Key<Aes256Gcm> {
    let mut hasher = Sha256::new();
    hasher.update(master_password.as_bytes());
    let result = hasher.finalize();
    *Key::<Aes256Gcm>::from_slice(&result)
}

pub fn encrypt(master_password: &str, plaintext: &str) -> String {
    let key = derive_key(master_password);
    let cipher = Aes256Gcm::new(&key);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).expect("encryption failure");
    let mut combined = nonce_bytes.to_vec();
    combined.extend(ciphertext);
    general_purpose::STANDARD.encode(combined)
}

pub fn decrypt(master_password: &str, encoded: &str) -> Result<String, String> {
    let decoded = general_purpose::STANDARD.decode(encoded).map_err(|_| "Invalid base64")?;
    if decoded.len() < NONCE_LEN {
        return Err("Corrupted data".into());
    }
    let (nonce_bytes, ciphertext) = decoded.split_at(NONCE_LEN);
    let key = derive_key(master_password);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let decrypted = cipher.decrypt(nonce, ciphertext).map_err(|_| "Decryption failed")?;
    String::from_utf8(decrypted).map_err(|_| "Invalid UTF-8".into())
}
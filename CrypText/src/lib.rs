#![allow(warnings)]
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, OsRng, rand_core::RngCore};
use base64::{engine::general_purpose, Engine as _};
use sha2::{Digest,Sha256};
use x25519_dalek::{EphemeralSecret,PublicKey as X25519PublicKey};

pub struct KeyPair{
    pub secret: EphemeralSecret,
    pub public: X25519PublicKey,
}

pub fn generate_keypair()->KeyPair{
    let secret=EphemeralSecret::random_from_rng(OsRng);
    let public=X25519PublicKey::from(&secret);
    KeyPair{secret,public}
}

pub fn derive_sharedkey(secret:EphemeralSecret,peer_public:X25519PublicKey)->[u8;32]{
        let shared_secret=secret.diffie_hellman(&peer_public);
        let hash=Sha256::digest(shared_secret.as_bytes());
        let mut key=[0u8;32];
        key.copy_from_slice(&hash);
        key
}    



pub fn encrypt_message(cipher: &Aes256Gcm, plaintext: &str) -> String {
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .expect("Encryption failed");

    let mut combined = nonce_bytes.to_vec();
    combined.extend_from_slice(&ciphertext);

    general_purpose::STANDARD.encode(combined)
}

pub fn decrypt_message(cipher: &Aes256Gcm, encoded: &str) -> Option<String> {
    let decoded = general_purpose::STANDARD.decode(encoded).ok()?;
    if decoded.len() < 12 {
        return None;
    }

    let (nonce_bytes, ciphertext) = decoded.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;
    String::from_utf8(plaintext).ok()
}

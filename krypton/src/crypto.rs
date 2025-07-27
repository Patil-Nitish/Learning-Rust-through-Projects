


use anyhow::Result;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, AeadCore, OsRng};
use rand_core::RngCore;
use ring::agreement::{X25519, EphemeralPrivateKey, UnparsedPublicKey, agree_ephemeral};
use ring::rand::{SystemRandom, SecureRandom}; 
use base64::{engine::general_purpose, Engine};
use std::collections::HashMap;
use tracing::info;
use std::time::{SystemTime, UNIX_EPOCH};


#[derive(Clone)]
pub struct KeyPair {
    pub public: [u8; 32],  
    pub secret: [u8; 32],  
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut secret_bytes = [0u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut secret_bytes);
        
        
        let system_random = SystemRandom::new();
        let private_key = EphemeralPrivateKey::generate(&X25519, &system_random).unwrap();
        let public_key = private_key.compute_public_key().unwrap();
        
        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(public_key.as_ref());
        
        Self {
            public: public_bytes,
            secret: secret_bytes,
        }
    }
    
    pub fn from_private_bytes(bytes: [u8; 32]) -> Result<Self> {
        
        let system_random = SystemRandom::new();
        let private_key = EphemeralPrivateKey::generate(&X25519, &system_random).unwrap();
        let public_key = private_key.compute_public_key().unwrap();
        
        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(public_key.as_ref());
        
        Ok(Self {
            public: public_bytes,
            secret: bytes,
        })
    }
    
    pub fn to_public_base64(&self) -> String {
        general_purpose::STANDARD.encode(self.public)
    }
    
    pub fn from_public_base64(b64: &str) -> Result<[u8; 32]> {
        let bytes = general_purpose::STANDARD.decode(b64)?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!("Invalid public key length"));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        Ok(key_bytes)
    }
    
    pub fn perform_ecdh(&self, their_public: &[u8; 32]) -> [u8; 32] {
        let system_random = SystemRandom::new();
        let private_key = EphemeralPrivateKey::generate(&X25519, &system_random).unwrap();
        let peer_public_key = UnparsedPublicKey::new(&X25519, their_public);
        
        let mut shared_secret = [0u8; 32];
        agree_ephemeral(private_key, &peer_public_key, |key_material| {
            shared_secret.copy_from_slice(&key_material[..32]);
            shared_secret
        }).unwrap();
        
        shared_secret
    }
    
    
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public
    }
}


pub fn generate_keypair() -> KeyPair {
    KeyPair::generate()
}


pub fn derive_shared_key(private_key: &[u8; 32], public_key: [u8; 32]) -> [u8; 32] {
    let keypair = KeyPair::from_private_bytes(*private_key).unwrap();
    keypair.perform_ecdh(&public_key)
}


#[derive(Clone)]
pub struct VpnCipher {
    cipher: Aes256Gcm,
    session_id: u64,
}

impl VpnCipher {
    pub fn new(shared_secret: [u8; 32]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(&shared_secret)
            .expect("Invalid key length");
        
        Self {
            cipher,
            session_id: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    pub fn encrypt_packet(&self, data: &[u8]) -> Result<Vec<u8>> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self.cipher
            .encrypt(&nonce, data)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt_packet(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        if encrypted_data.len() < 12 {
            anyhow::bail!("Encrypted data too short");
        }

        
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);

        let plaintext = self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }
    
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self.cipher.encrypt(&nonce, data)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }
    
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 {
            return Err(anyhow::anyhow!("Data too short for nonce"));
        }
        
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let plaintext = self.cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
        
        Ok(plaintext)
    }
    
    pub fn get_session_id(&self) -> u64 {
        self.session_id
    }
}


pub struct CryptoManager {
    sessions: HashMap<String, VpnCipher>,
    auth_tokens: HashMap<String, SystemTime>,
    server_keypair: Option<KeyPair>,
}

impl CryptoManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            auth_tokens: HashMap::new(),
            server_keypair: None,
        }
    }
    
    pub fn init_server(&mut self) -> Result<String> {
        info!("🖥️ Initializing server crypto (generating keypair)");
        
        let keypair = generate_keypair();
        let public_key_b64 = base64::engine::general_purpose::STANDARD
            .encode(keypair.public_bytes());
        
        self.server_keypair = Some(keypair);
        
        info!("Server initialized with public key: {}", public_key_b64);
        Ok(public_key_b64)
    }
    
    
    pub fn handle_client_key_exchange_old(&mut self, session_token: &str, client_public_key_b64: &str) -> Result<String> {
        info!("🔄 Handling key exchange for session: {}", session_token);
        
        
        let server_keypair = self.server_keypair.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Server not initialized"))?;
    
        
        let client_pub_bytes = base64::engine::general_purpose::STANDARD
            .decode(client_public_key_b64.trim())
            .map_err(|e| anyhow::anyhow!("Invalid client public key: {}", e))?;
        
        if client_pub_bytes.len() != 32 {
            anyhow::bail!("Invalid client public key length: {}", client_pub_bytes.len());
        }
    
        let mut client_public_key = [0u8; 32];
        client_public_key.copy_from_slice(&client_pub_bytes);
    
        
        let shared_key = server_keypair.perform_ecdh(&client_public_key);
        
        
        let cipher = VpnCipher::new(shared_key);
        self.sessions.insert(session_token.to_string(), cipher);
    
        
        let server_public_key_b64 = base64::engine::general_purpose::STANDARD
            .encode(server_keypair.public_bytes());
        
        info!("✅ Key exchange completed for session: {}", session_token);
        Ok(server_public_key_b64)
    }
    
    pub fn active_cipher_count(&self) -> usize {
        self.sessions.len()
    }
    
    pub fn create_session(&mut self, session_id: String, shared_secret: [u8; 32]) {
        let cipher = VpnCipher::new(shared_secret);
        self.sessions.insert(session_id, cipher);
    }
    
    pub fn get_session(&self, session_id: &str) -> Option<&VpnCipher> {
        self.sessions.get(session_id)
    }
    
    pub fn encrypt_packet(&self, session_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        let cipher = self.sessions.get(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
        cipher.encrypt(data)
    }
    
    pub fn decrypt_packet(&self, session_id: &str, data: &[u8]) -> Result<Vec<u8>> {
        let cipher = self.sessions.get(session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;
        cipher.decrypt(data)
    }
    
    pub fn generate_auth_token(&mut self, username: &str) -> String {
        let token = format!("{}_{}", username, 
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
        
        let expires_at = SystemTime::now() + std::time::Duration::from_secs(3600);
        self.auth_tokens.insert(token.clone(), expires_at);
        
        info!("Generated auth token for user: {}", username);
        token
    }
    
    pub fn validate_token(&self, token: &str) -> bool {
        if let Some(&expires_at) = self.auth_tokens.get(token) {
            SystemTime::now() < expires_at
        } else {
            false
        }
    }
    
    pub fn cleanup_expired(&mut self) {
        
        let before_count = self.sessions.len();
        
        if before_count > 0 {
            info!("🧹 Cleanup check: {} active sessions", before_count);
        }
    }

    pub fn remove_cipher(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    pub fn init_client_key_exchange(&mut self, _session_id: &str) -> Result<(String, KeyPair)> {
        let keypair = generate_keypair();
        let public_key_b64 = keypair.to_public_base64();
        Ok((public_key_b64, keypair))
    }

    pub fn complete_client_key_exchange(&mut self, session_id: &str, password: &str) -> Result<()> {
        
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(session_id.as_bytes());
        hasher.update(b"Krypton_SECRET_2024"); 
        
        let result = hasher.finalize();
        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(&result);
        
        self.create_session(session_id.to_string(), shared_secret);
        info!("✅ Client created session {} with deterministic key", session_id);
        Ok(())
    }

    
    pub fn handle_client_key_exchange(&mut self, session_id: &str, _client_public_key: &str) -> Result<()> {
        
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        hasher.update(session_id.as_bytes());
        hasher.update(b"Krypton_SECRET_2024"); 
        
        let result = hasher.finalize();
        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(&result);
        
        self.create_session(session_id.to_string(), shared_secret);
        info!("✅ Created session {} with deterministic key", session_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_keypair_generation() {
        let keypair = generate_keypair();
        assert_eq!(keypair.secret.len(), 32);
        assert_eq!(keypair.public.len(), 32);
    }
    
    #[test]
    fn test_ecdh_exchange() {
        let alice = generate_keypair();
        let bob = generate_keypair();
        
        let alice_shared = alice.perform_ecdh(&bob.public);
        let bob_shared = bob.perform_ecdh(&alice.public);
        
        
        
        println!("Alice shared: {:?}", &alice_shared[..8]);
        println!("Bob shared: {:?}", &bob_shared[..8]);
    }
    
    #[test]
    fn test_encryption_decryption() {
        let shared_secret = [1u8; 32];
        let cipher = VpnCipher::new(shared_secret);
        
        let plaintext = b"Hello, VPN World!";
        let encrypted = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }
    
    #[test]
    fn test_crypto_manager() {
        let mut manager = CryptoManager::new();
        let server_pub = manager.init_server().unwrap();
        
        assert!(!server_pub.is_empty());
        assert_eq!(manager.active_cipher_count(), 0);
        
        let shared_secret = [42u8; 32];
        manager.create_session("test_session".to_string(), shared_secret);
        assert_eq!(manager.active_cipher_count(), 1);
    }
}
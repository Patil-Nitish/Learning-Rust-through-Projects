use crate::config;
use anyhow::Result;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

pub use config::{User, AdminConfig};


#[derive(Debug, Clone)]
pub struct Session {
    pub username: String,
    pub created_at: u64,
    pub last_activity: u64,
    pub is_admin: bool,
    pub vpn_ip: String,  
}


pub struct AuthManager {
    users: HashMap<String, User>,
    admin_config: AdminConfig,
    active_sessions: HashMap<String, Session>, 
    failed_attempts: HashMap<String, (u32, u64)>, 
}

impl AuthManager {
    
    pub fn new() -> Result<Self> {
        info!("🔐 Initializing Krypton authentication system");
        
        if !std::path::Path::new(config::USERS_DB_PATH).exists() {
            info!("📁 Creating empty user database");
            let _ = std::fs::write(config::USERS_DB_PATH, "[]");
        }
        
        let users = match std::fs::read_to_string(config::USERS_DB_PATH) {
            Ok(content) => {
                let users: Vec<User> = serde_json::from_str(&content)?;
                let mut user_map = HashMap::new();
                for user in users {
                    user_map.insert(user.username.clone(), user);
                }
                info!("✅ Loaded {} users from {}", user_map.len(), config::USERS_DB_PATH);
                user_map
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!("⚠️  User file not found, loading embedded users");
                let embedded_users = config::load_embedded_users()?;
                let mut user_map = HashMap::new();
                for user in embedded_users {
                    user_map.insert(user.username.clone(), user);
                }
                user_map
            }
            Err(e) => return Err(e.into()),
        };

        
        let admin_config = match config::load_embedded_admin_config() {
            Ok(config) => {
                info!("✅ Loaded admin configuration");
                config
            }
            Err(e) => {
                warn!("⚠️  Failed to load admin config: {}", e);
                AdminConfig::default()
            }
        };

        Ok(Self {
            users,
            admin_config,
            active_sessions: HashMap::new(),
            failed_attempts: HashMap::new(),
        })
    }

    
    pub fn authenticate(&mut self, username: &str, password: &str) -> Result<String> {
        info!("🔑 Authentication attempt for user: {}", username);

        
        if self.users.is_empty() {
            warn!("📝 Empty user database - creating default test user");
            let test_user = User {
                username: "test".to_string(),
                password_hash: self.hash_password("test")?, 
                salt: "default_salt".to_string(),
                created_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                is_admin: false,
                vpn_ip: None,
            };
            self.users.insert("test".to_string(), test_user);
            info!("✅ Created default test user (username: test, password: test)");
        }

        
        if self.is_account_locked(username) {
            warn!("🔒 Account locked due to too many failed attempts: {}", username);
            anyhow::bail!("Account temporarily locked due to too many failed attempts");
        }

        
        let user = match self.users.get(username) {
            Some(user) => user,
            None => {
                self.record_failed_attempt(username);
                warn!("❌ Authentication failed - user not found: {}", username);
                anyhow::bail!("Invalid username or password");
            }
        };

        
        if self.verify_password(password, &user.password_hash)? {
            
            self.clear_failed_attempts(username);
            let token = self.create_session(username)?;
            info!("✅ Authentication successful for user: {}", username);
            Ok(token)
        } else {
            self.record_failed_attempt(username);
            warn!("❌ Authentication failed - invalid password for: {}", username);
            anyhow::bail!("Invalid username or password");
        }
    }

    
    pub fn register_user(&mut self, username: &str, password: &str) -> Result<()> {
        
        if self.users.contains_key(username) {
            return Err(anyhow::anyhow!("User already exists"));
        }
        
        
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?
            .to_string();
        
        
        let user = User {
            username: username.to_string(),
            password_hash: self.hash_password(password)?,
            salt: SaltString::generate(&mut OsRng).to_string(),
            created_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            is_admin: false,
            vpn_ip: None,
        };
    
        
        self.users.insert(username.to_string(), user.clone());
        self.save_users_to_file()?;
    
        info!("✅ User {} registered successfully", username);
        Ok(())
    }
    
    fn save_users_to_file(&self) -> Result<()> {
        let users: Vec<&User> = self.users.values().collect();
        let json = serde_json::to_string_pretty(&users)?;
        std::fs::write(config::USERS_DB_PATH, json)?;
        Ok(())
    }

    
    fn create_session(&mut self, username: &str) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        
        let token = format!("Krypton_{}_{}", username, now);

        
        let vpn_ip = self.assign_vpn_ip(username)?;

        
        let session = Session {
            username: username.to_string(),
            created_at: now,
            last_activity: now,
            is_admin: username == "admin", 
            vpn_ip,
        };

        self.active_sessions.insert(token.clone(), session);
        info!("🎫 Created session for {}: VPN IP {}", username, 
              self.active_sessions.get(&token).unwrap().vpn_ip);

        Ok(token)
    }

    
    fn assign_vpn_ip(&self, username: &str) -> Result<String> {
        
        
        let hash = username.chars()
            .map(|c| c as u32)
            .sum::<u32>();
        
        let ip_suffix = (hash % 250) + 3; 
        let vpn_ip = format!("10.8.0.{}", ip_suffix);
        
        
        let in_use = self.active_sessions.values()
            .any(|session| session.vpn_ip == vpn_ip);
        
        if in_use {
            
            let alt_suffix = ((ip_suffix + 1) % 250) + 3;
            Ok(format!("10.8.0.{}", alt_suffix))
        } else {
            Ok(vpn_ip)
        }
    }

    
    pub fn get_user_vpn_ip(&self, token: &str) -> Option<String> {
        self.active_sessions.get(token)
            .map(|session| session.vpn_ip.clone())
    }

    
    fn verify_password(&self, password: &str, hash: &str) -> Result<bool> {
        if hash.is_empty() {
            return Ok(false);
        }

        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| anyhow::anyhow!("Invalid password hash format: {}", e))?;

        let argon2 = Argon2::default();
        Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }

    
    fn is_account_locked(&self, username: &str) -> bool {
        if let Some((count, last_attempt)) = self.failed_attempts.get(username) {
            if *count >= 3 { 
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                
                
                return (now - last_attempt) < 900;
            }
        }
        false
    }

    
    fn record_failed_attempt(&mut self, username: &str) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let (count, _) = self.failed_attempts
            .get(username)
            .unwrap_or(&(0, 0));

        self.failed_attempts.insert(
            username.to_string(), 
            (count + 1, now)
        );
    }

    
    fn clear_failed_attempts(&mut self, username: &str) {
        self.failed_attempts.remove(username);
    }

    
    pub fn logout(&mut self, token: &str) -> Result<()> {
        if let Some(session) = self.active_sessions.remove(token) {
            info!("👋 User {} logged out", session.username);
            Ok(())
        } else {
            anyhow::bail!("Invalid session token")
        }
    }

    
    pub fn cleanup_expired_sessions(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let timeout = 3600; 
        
        self.active_sessions.retain(|_token, session| {
            let session_age = now - session.created_at;
            if session_age > timeout {
                info!("🧹 Cleaned up expired session for: {}", session.username);
                false
            } else {
                true
            }
        });
    }

    
    pub fn hash_password(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;

        Ok(password_hash.to_string())
    }
}

impl AuthManager {
    pub fn list_active_connections(&self) -> Vec<(String, String, String)> {
        self.active_sessions.values()
            .map(|session| (
                session.username.clone(),
                session.vpn_ip.clone(),
                format!("{}s", SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() - session.created_at)
            ))
            .collect()
    }

    pub fn user_count(&self) -> usize {
        self.users.len()
    }
    
    pub fn active_sessions_count(&self) -> usize {
        self.active_sessions.len()
    }
    
    pub fn validate_session(&self, token: &str) -> bool {
        self.active_sessions.contains_key(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_manager_creation() {
        let auth_manager = AuthManager::new();
        assert!(auth_manager.is_ok());
    }

    #[test]
    fn test_password_hashing() {
        let auth_manager = AuthManager::new().unwrap();
        let password = "test123";
        let hash = auth_manager.hash_password(password).unwrap();
        
        assert!(!hash.is_empty());
        assert!(auth_manager.verify_password(password, &hash).unwrap());
        assert!(!auth_manager.verify_password("wrong", &hash).unwrap());
    }

    #[test]
    fn test_vpn_ip_assignment() {
        let auth_manager = AuthManager::new().unwrap();
        let ip1 = auth_manager.assign_vpn_ip("user1").unwrap();
        let ip2 = auth_manager.assign_vpn_ip("user2").unwrap();
        
        
        assert_ne!(ip1, ip2);
        
        assert!(ip1.starts_with("10.8.0."));
        assert!(ip2.starts_with("10.8.0."));
    }
}


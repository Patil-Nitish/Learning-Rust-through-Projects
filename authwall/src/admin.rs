use crate::{crypto, password_input};
use std::fs;
use serde::{Serialize, Deserialize};

const ADMIN_CONFIG_PATH: &str = "admin_config.json";

#[derive(Serialize, Deserialize)]
struct AdminConfig {
    password_hash: String,
    salt: String,
    setup_complete: bool,
}

pub fn setup_admin_if_needed() -> bool {
    if !std::path::Path::new(ADMIN_CONFIG_PATH).exists() {
        setup_admin_password()
    } else {
        load_admin_config().setup_complete
    }
}

fn setup_admin_password() -> bool {
    println!("🔧 Admin Setup Required");
    println!("Create an admin password for system management:");
    
    let password = match password_input::secure_password_input("Admin password: ") {
        Ok(p) => p,
        Err(e) => {
            println!("❌ {}", e);
            return false;
        }
    };
    
    if let Err(e) = password_input::confirm_password_input(&password) {
        println!("❌ {}", e);
        return false;
    }
    
    let salt = crypto::generate_salt();
    let hash = crypto::hash_password(&password, &salt);
    
    let config = AdminConfig {
        password_hash: hash,
        salt,
        setup_complete: true,
    };
    
    let json = serde_json::to_string_pretty(&config).unwrap();
    if fs::write(ADMIN_CONFIG_PATH, json).is_ok() {
        println!("✅ Admin password configured successfully");
        true
    } else {
        println!("❌ Failed to save admin configuration");
        false
    }
}

pub fn authenticate_admin() -> bool {
    let config = load_admin_config();
    if !config.setup_complete {
        println!("❌ Admin not configured");
        return false;
    }
    
    println!("🔐 Admin Authentication");
    
    match password_input::secure_password_input("Admin password: ") {
        Ok(password) => {
            if crypto::verify_password(&config.password_hash, &password, &config.salt) {
                println!("✅ Admin access granted");
                true
            } else {
                println!("❌ Admin access denied");
                false
            }
        }
        Err(_) => {
            println!("❌ Admin authentication failed");
            false
        }
    }
}

fn load_admin_config() -> AdminConfig {
    if let Ok(content) = fs::read_to_string(ADMIN_CONFIG_PATH) {
        serde_json::from_str(&content).unwrap_or_else(|_| AdminConfig {
            password_hash: String::new(),
            salt: String::new(),
            setup_complete: false,
        })
    } else {
        AdminConfig {
            password_hash: String::new(),
            salt: String::new(),
            setup_complete: false,
        }
    }
}

pub fn reset_admin_password() {
    println!("🔄 Resetting admin password...");
    if std::path::Path::new(ADMIN_CONFIG_PATH).exists() {
        fs::remove_file(ADMIN_CONFIG_PATH).unwrap_or_default();
    }
    setup_admin_password();
}
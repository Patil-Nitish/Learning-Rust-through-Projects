use crate::config::{AdminConfig, SecuritySettings};
use std::fs;
use std::io::{self, Write};
use serde_json;

const ADMIN_CONFIG_PATH: &str = "cryptlink_admin.json";

pub fn setup_admin_if_needed() -> bool {
    let config = load_admin_config();
    if !config.setup_complete || config.password_hash.is_empty() {
        println!("🔧 Admin setup required for Krypton VPN");
        setup_admin_password()
    } else {
        println!("✅ Admin already configured");
        true
    }
}

fn setup_admin_password() -> bool {
    println!("🛡️  Krypton Admin Setup");
    println!("==========================================");
    println!("Create an admin password for VPN management:");
    
    loop {
        let password = match read_password("🔐 Admin password (minimum 8 chars): ") {
            Ok(p) => p,
            Err(e) => {
                println!("❌ {}", e);
                continue;
            }
        };
        
        if password.len() < 8 {
            println!("❌ Password must be at least 8 characters long");
            continue;
        }
        
        let confirm_password = match read_password("🔐 Confirm admin password: ") {
            Ok(p) => p,
            Err(e) => {
                println!("❌ {}", e);
                continue;
            }
        };
        
        if password != confirm_password {
            println!("❌ Passwords do not match. Please try again.");
            continue;
        }
        
        let salt = generate_salt();
        let password_hash = hash_password(&password, &salt);
        
        let config = AdminConfig {
            password_hash,
            salt,
            setup_complete: true,
            created_at: get_current_timestamp(),
            last_updated: Some(get_current_timestamp()),
            security_settings: SecuritySettings {
                max_failed_attempts: 3,
                session_timeout_hours: 24,
                require_strong_passwords: true,
                enable_2fa: false,
            },
        };
        
        let json = serde_json::to_string_pretty(&config).unwrap();
        if fs::write(ADMIN_CONFIG_PATH, json).is_ok() {
            println!("✅ Admin password configured successfully");
            println!("🔐 Admin credentials are now ready for Krypton VPN");
            return true;
        } else {
            println!("❌ Failed to save admin configuration");
            continue;
        }
    }
}

pub fn authenticate_admin() -> bool {
    let config = load_admin_config();
    if !config.setup_complete {
        println!("❌ Admin not configured - run setup first");
        return false;
    }
    
    println!("🔐 Admin Authentication Required");
    
    match read_password("🔑 Admin password: ") {
        Ok(password) => {
            if verify_password(&config.password_hash, &password, &config.salt) {
                println!("✅ Admin access granted");
                true
            } else {
                println!("❌ Invalid admin password");
                false
            }
        }
        Err(_) => {
            println!("❌ Admin authentication failed");
            false
        }
    }
}

pub fn is_admin_configured() -> bool {
    let config = load_admin_config();
    config.setup_complete && !config.password_hash.is_empty()
}

fn load_admin_config() -> AdminConfig {
    if let Ok(content) = fs::read_to_string(ADMIN_CONFIG_PATH) {
        serde_json::from_str(&content).unwrap_or_default()
    } else {
        AdminConfig::default()
    }
}

fn read_password(prompt: &str) -> Result<String, String> {
    print!("{}", prompt);
    io::stdout().flush().map_err(|_| "Failed to flush stdout")?;
    
    let mut password = String::new();
    io::stdin().read_line(&mut password)
        .map_err(|_| "Failed to read password")?;
    
    Ok(password.trim().to_string())
}

fn generate_salt() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let mut hasher = DefaultHasher::new();
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    
    format!("{:016x}", hasher.finish())
}

fn hash_password(password: &str, salt: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let salted_password = format!("{}{}", password, salt);
    let mut hasher = DefaultHasher::new();
    salted_password.hash(&mut hasher);
    
    format!("{:016x}", hasher.finish())
}

fn verify_password(hash: &str, password: &str, salt: &str) -> bool {
    hash_password(password, salt) == hash
}

fn get_current_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let timestamp = duration.as_secs();
    
    let days_since_epoch = timestamp / 86400;
    let year = 1970 + (days_since_epoch / 365);
    let month = ((days_since_epoch % 365) / 30) + 1;
    let day = ((days_since_epoch % 365) % 30) + 1;
    let hour = (timestamp / 3600) % 24;
    let minute = (timestamp / 60) % 60;
    let second = timestamp % 60;
    
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", 
        year, month.min(12), day.min(31), hour, minute, second)
}

pub fn reset_admin_password() -> bool {
    println!("🔄 Resetting admin password...");
    if std::path::Path::new(ADMIN_CONFIG_PATH).exists() {
        if let Err(e) = fs::remove_file(ADMIN_CONFIG_PATH) {
            println!("❌ Failed to remove existing config: {}", e);
            return false;
        }
    }
    
    setup_admin_password()
}

pub fn change_admin_password() -> bool {
    println!("🔄 Changing admin password...");
    
    
    if !authenticate_admin() {
        println!("❌ Current password authentication failed");
        return false;
    }
    
    
    setup_admin_password()
}

pub fn show_admin_status() {
    let config = load_admin_config();
    
    println!("🔐 Admin Configuration Status");
    println!("==========================================");
    println!("Setup Complete: {}", if config.setup_complete { "✅ Yes" } else { "❌ No" });
    println!("Created At: {}", config.created_at);
    if let Some(updated) = config.last_updated {
        println!("Last Updated: {}", updated);
    } else {
        println!("Last Updated: Never");
    }
    println!("Max Failed Attempts: {}", config.security_settings.max_failed_attempts);
    println!("Session Timeout: {} hours", config.security_settings.session_timeout_hours);
    println!("Strong Passwords Required: {}", if config.security_settings.require_strong_passwords { "✅ Yes" } else { "❌ No" });
    println!("2FA Enabled: {}", if config.security_settings.enable_2fa { "✅ Yes" } else { "❌ No" });
    println!("==========================================");
}
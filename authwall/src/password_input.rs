use rpassword::read_password;
use std::io::{self, Write};

pub fn secure_password_input(prompt: &str) -> Result<String, String> {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    
    match read_password() {
        Ok(password) => {
            if password.trim().is_empty() {
                Err("Password cannot be empty".to_string())
            } else {
                Ok(password.trim().to_string())
            }
        }
        Err(_) => Err("Failed to read password".to_string())
    }
}

pub fn confirm_password_input(password: &str) -> Result<(), String> {
    let confirm = secure_password_input("Confirm: ")?;
    
    if password != confirm {
        Err("Passwords don't match".to_string())
    } else {
        Ok(())
    }
}

pub fn validate_password_strength(password: &str) -> Result<(), String> {
    if password.len() < 6 {
        return Err("Password must be at least 6 characters".to_string());
    }
    
    let has_upper = password.chars().any(|c| c.is_uppercase());
    let has_lower = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_numeric());
    
    if !has_upper || !has_lower || !has_digit {
        return Err("Password must contain uppercase, lowercase, and numbers".to_string());
    }
    
    Ok(())
}
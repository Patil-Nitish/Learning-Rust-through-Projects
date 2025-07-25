use crate::{user::User, userdb, crypto, password_input};
//use std::io::{self, Write};

pub fn register(username: &str) {
    let mut users = userdb::load_users();
    if users.iter().any(|u| u.username == username) {
        println!("❌ User already exists");
        return;
    }

    let password = match password_input::secure_password_input("Password: ") {
        Ok(p) => p,
        Err(e) => {
            println!("❌ {}", e);
            return;
        }
    };

    if let Err(e) = password_input::validate_password_strength(&password) {
        println!("⚠️  {}", e);
    }

    if let Err(e) = password_input::confirm_password_input(&password) {
        println!("❌ {}", e);
        return;
    }

    let salt = crypto::generate_salt();
    let hash = crypto::hash_password(&password, &salt);

    let user = User {
        username: username.to_string(),
        password_hash: hash,
        salt,
        failed_attempts: 0,
    };

    users.push(user);
    userdb::save_users(&users);
    println!("✅ User created");
}

pub fn login(username: &str) -> bool {
    let mut users = userdb::load_users();

    if let Some(user) = users.iter_mut().find(|u| u.username == username) {
        if user.failed_attempts >= 3 {
            println!("🔒 Account locked");
            return false;
        }

        let password = match password_input::secure_password_input("Password: ") {
            Ok(p) => p,
            Err(e) => {
                println!("❌ {}", e);
                return false;
            }
        };
        
        if crypto::verify_password(&user.password_hash, &password, &user.salt) {
            user.failed_attempts = 0;
            userdb::save_users(&users);
            return true;
        } else {
            user.failed_attempts += 1;
            let remaining = 3 - user.failed_attempts;
            
            if remaining > 0 {
                println!("❌ Wrong password ({} left)", remaining);
            } else {
                println!("🔒 Account locked");
            }
            
            userdb::save_users(&users);
            return false;
        }
    } else {
        println!("❌ User not found");
        return false;
    }
}
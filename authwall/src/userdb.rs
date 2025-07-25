use crate::user::User;
use std::fs::OpenOptions;
use std::io::Write;

const DB_PATH: &str = "users.json";
const EMBEDDED_USERS: &str = include_str!("../users.json");

pub fn load_users() -> Vec<User> {
    if std::path::Path::new(DB_PATH).exists() {
        let content = std::fs::read_to_string(DB_PATH).unwrap_or_default();
        serde_json::from_str(&content).unwrap_or_else(|_| load_embedded_users())
    } else {
        load_embedded_users()
    }
}

fn load_embedded_users() -> Vec<User> {
    if EMBEDDED_USERS.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(EMBEDDED_USERS).unwrap_or_default()
    }
}

pub fn save_users(users: &[User]) {
    let json = serde_json::to_string_pretty(users).unwrap();
    
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(DB_PATH)
        .unwrap();
    
    file.write_all(json.as_bytes()).unwrap();
}
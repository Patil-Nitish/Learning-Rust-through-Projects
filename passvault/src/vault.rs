use std::collections::HashMap;
use std::fs::{self, File};
use std::path::Path;
use std::io::{Write, Read};

use serde::{Serialize, Deserialize};

use crate::crypto::{encrypt, decrypt};

const VAULT_FILE: &str = "vault.dat";

#[derive(Serialize, Deserialize)]
pub struct Entry {
    pub username: String,
    pub password: String,
}

pub struct Vault {
    pub data: HashMap<String, Entry>,
}

impl Vault {
    pub fn new() -> Self {
        Self { data: HashMap::new() }
    }

    pub fn load(master_password: &str) -> Result<Self, String> {
        if !Path::new(VAULT_FILE).exists() {
            return Ok(Self::new());
        }

        let mut encrypted = String::new();
        File::open(VAULT_FILE)
            .map_err(|_| "Failed to open vault file")?
            .read_to_string(&mut encrypted)
            .map_err(|_| "Failed to read vault file")?;

        let decrypted = decrypt(master_password, &encrypted)?;
        let data: HashMap<String, Entry> =
            serde_json::from_str(&decrypted).map_err(|_| "Vault corrupted")?;

        Ok(Self { data })
    }

    pub fn save(&self, master_password: &str) -> Result<(), String> {
        let json = serde_json::to_string(&self.data).map_err(|_| "Failed to serialize vault")?;
        let encrypted = encrypt(master_password, &json);

        let mut file = File::create(VAULT_FILE).map_err(|_| "Failed to write vault")?;
        file.write_all(encrypted.as_bytes())
            .map_err(|_| "Failed to write data")?;
        Ok(())
    }

    pub fn insert(&mut self, website: String, entry: Entry) {
        self.data.insert(website, entry);
    }

    pub fn get(&self, website: &str) -> Option<&Entry> {
        self.data.get(website)
    }

    pub fn list(&self) {
        if self.data.is_empty() {
            println!("🔐 Vault is empty.");
        } else {
            for (site, _) in &self.data {
                println!("• {}", site);
            }
        }
    }
}

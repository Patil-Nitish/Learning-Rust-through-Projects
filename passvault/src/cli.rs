use std::io::{self, Write};
use crate::vault::{Vault, Entry};
use rpassword::read_password;

pub fn start_cli() {
    println!("🔐 Welcome to PassVault!");
    print!("Enter master password: ");
    io::stdout().flush().unwrap();
    let master_password = read_password().expect("Failed to read password");

    let mut vault = match Vault::load(&master_password) {
        Ok(v) => v,
        Err(e) => {
            println!("❌ Error: {}", e);
            return;
        }
    };

    loop {
        println!("\n📜 Commands: add | get | list | exit");
        print!("> ");
        io::stdout().flush().unwrap();

        let mut cmd = String::new();
        io::stdin().read_line(&mut cmd).unwrap();
        let cmd = cmd.trim().to_lowercase();

        match cmd.as_str() {
            "add" => {
                print!("Website: ");
                io::stdout().flush().unwrap();
                let mut website = String::new();
                io::stdin().read_line(&mut website).unwrap();

                print!("Username: ");
                io::stdout().flush().unwrap();
                let mut username = String::new();
                io::stdin().read_line(&mut username).unwrap();

                print!("Password: ");
                io::stdout().flush().unwrap();
                let password = read_password().unwrap();

                vault.insert(
                    website.trim().to_string(),
                    Entry {
                        username: username.trim().to_string(),
                        password: password.trim().to_string(),
                    },
                );
                println!("✅ Added entry for {}", website.trim());
            }

            "get" => {
                print!("Website: ");
                io::stdout().flush().unwrap();
                let mut website = String::new();
                io::stdin().read_line(&mut website).unwrap();
                let website = website.trim();

                match vault.get(website) {
                    Some(entry) => {
                        println!("👤 Username: {}", entry.username);
                        println!("🔑 Password: {}", entry.password);
                    }
                    None => println!("❌ No entry found for {}", website),
                }
            }

            "list" => {
                println!("📁 Stored websites:");
                vault.list();
            }

            "exit" => {
                if let Err(e) = vault.save(&master_password) {
                    println!("❌ Failed to save: {}", e);
                } else {
                    println!("💾 Vault saved. Goodbye!");
                }
                break;
            }

            _ => println!("❓ Unknown command."),
        }
    }
}

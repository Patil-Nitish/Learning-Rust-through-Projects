mod user;
mod userdb;
mod crypto;
mod auth;
mod password_input;
mod admin;

use clap::{Parser, Subcommand};
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "authwall")]
#[command(version = "1.0.0")]
#[command(about = "🛡️  Secure authentication system")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Register { username: String },
    Login { username: String },
    #[command(name = "list")]
    ListUsers,
    Status { username: String },
    Reset { username: String },
    #[command(name = "admin-reset")]
    AdminReset,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(cmd) => handle_command(cmd),
        None => interactive_mode(),
    }
}

fn interactive_mode() {
    println!("🛡️  AuthWall");
    println!("{}", "─".repeat(20));
    
    loop {
        println!("\nOptions:");
        println!("1. Register user");
        println!("2. Login");
        println!("3. List users");
        println!("4. User status");
        println!("5. Exit");
        
        print!("\nEnter choice (1-5): ");
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        
        match input.trim() {
            "1" => {
                print!("Enter username: ");
                io::stdout().flush().unwrap();
                let mut username = String::new();
                io::stdin().read_line(&mut username).unwrap();
                handle_command(Commands::Register { 
                    username: username.trim().to_string() 
                });
            }
            "2" => {
                print!("Enter username: ");
                io::stdout().flush().unwrap();
                let mut username = String::new();
                io::stdin().read_line(&mut username).unwrap();
                
                let username_trim = username.trim();
                
                // Hidden admin trigger
                if username_trim == "root" {
                    if admin::setup_admin_if_needed() && admin::authenticate_admin() {
                        admin_mode();
                        continue;
                    } else {
                        println!("❌ Authentication failed");
                        continue;
                    }
                }
                
                handle_command(Commands::Login { 
                    username: username_trim.to_string() 
                });
            }
            "3" => handle_command(Commands::ListUsers),
            "4" => {
                print!("Enter username: ");
                io::stdout().flush().unwrap();
                let mut username = String::new();
                io::stdin().read_line(&mut username).unwrap();
                handle_command(Commands::Status { 
                    username: username.trim().to_string() 
                });
            }
            "5" => {
                println!("👋 Goodbye!");
                break;
            }
            _ => println!("❌ Invalid choice. Please enter 1-5."),
        }
        
        println!("\nPress Enter to continue...");
        let mut _pause = String::new();
        io::stdin().read_line(&mut _pause).unwrap();
    }
}

fn admin_mode() {
    println!("🔧 Admin Mode");
    println!("{}", "─".repeat(20));
    
    loop {
        println!("\nAdmin Options:");
        println!("1. Register user");
        println!("2. Login");
        println!("3. List users");
        println!("4. User status");
        println!("5. 🔧 Reset attempts");
        println!("6. 🔄 Reset admin password");
        println!("7. Exit admin mode");
        
        print!("\nEnter choice (1-7): ");
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        
        match input.trim() {
            "1" => {
                print!("Enter username: ");
                io::stdout().flush().unwrap();
                let mut username = String::new();
                io::stdin().read_line(&mut username).unwrap();
                handle_command(Commands::Register { 
                    username: username.trim().to_string() 
                });
            }
            "2" => {
                print!("Enter username: ");
                io::stdout().flush().unwrap();
                let mut username = String::new();
                io::stdin().read_line(&mut username).unwrap();
                handle_command(Commands::Login { 
                    username: username.trim().to_string() 
                });
            }
            "3" => handle_command(Commands::ListUsers),
            "4" => {
                print!("Enter username: ");
                io::stdout().flush().unwrap();
                let mut username = String::new();
                io::stdin().read_line(&mut username).unwrap();
                handle_command(Commands::Status { 
                    username: username.trim().to_string() 
                });
            }
            "5" => {
                print!("Enter username to reset: ");
                io::stdout().flush().unwrap();
                let mut username = String::new();
                io::stdin().read_line(&mut username).unwrap();
                handle_command(Commands::Reset { 
                    username: username.trim().to_string() 
                });
            }
            "6" => {
                handle_command(Commands::AdminReset);
            }
            "7" => {
                println!("👤 Exiting admin mode");
                break;
            }
            _ => println!("❌ Invalid choice. Please enter 1-7."),
        }
        
        println!("\nPress Enter to continue...");
        let mut _pause = String::new();
        io::stdin().read_line(&mut _pause).unwrap();
    }
}

fn handle_command(command: Commands) {
    match command {
        Commands::Register { username } => {
            auth::register(&username);
        }
        Commands::Login { username } => {
            let success = auth::login(&username);
            if success {
                println!("✅ Login successful");
                println!("🎫 Token: {}", uuid::Uuid::new_v4());
            }
        }
        Commands::ListUsers => {
            let users = userdb::load_users();
            if users.is_empty() {
                println!("📭 No users found");
            } else {
                println!("👥 Users ({})", users.len());
                println!("{}", "─".repeat(40));
                for (i, user) in users.iter().enumerate() {
                    let status = if user.failed_attempts >= 3 {
                        "🔒"
                    } else if user.failed_attempts > 0 {
                        "⚠️"
                    } else {
                        "✅"
                    };
                    println!("{:2}. {} {} ({})", i + 1, status, user.username, user.failed_attempts);
                }
            }
        }
        Commands::Status { username } => {
            let users = userdb::load_users();
            if let Some(user) = users.iter().find(|u| u.username == username) {
                println!("📊 Status: {}", username);
                let status = if user.failed_attempts >= 3 { "🔒 LOCKED" } else { "✅ ACTIVE" };
                println!("   {} | Attempts: {}/3", status, user.failed_attempts);
            } else {
                println!("❌ User '{}' not found", username);
            }
        }
        Commands::Reset { username } => {
            if !admin::authenticate_admin() {
                println!("❌ Admin privileges required for reset");
                return;
            }
            
            let mut users = userdb::load_users();
            if let Some(user) = users.iter_mut().find(|u| u.username == username) {
                user.failed_attempts = 0;
                userdb::save_users(&users);
                println!("🔓 Reset: {}", username);
            } else {
                println!("❌ User '{}' not found", username);
            }
        }
        Commands::AdminReset => {
            admin::reset_admin_password();
        }
    }
}
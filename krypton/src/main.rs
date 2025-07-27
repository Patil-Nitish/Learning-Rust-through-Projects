mod config;
mod tun;
mod auth;
mod crypto;
mod protocol;
mod admin;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, error};
use tokio::signal;
use tokio::sync::oneshot;

#[derive(Parser)]
#[command(name = "Krypton")]
#[command(version = "1.0.0")]
#[command(about = "🔐 Authenticated P2P VPN with built-in key exchange")]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    
    Server {
        #[arg(short, long, default_value = "0.0.0.0:9001")]
        listen: String,
    },
    
    
    Client {
        #[arg(short='e', long, help = "Server peer address")]
        peer: String,
        
        #[arg(short = 'u', long, help = "Username")]
        username: String,
        
        #[arg(short, long, help = "Password")]
        password: String,
    },
    Register { username: String, password: String },
    
    
    Status,

    
    TestTun,

    
    TestAuth,

    
    TestCrypto,

    
    Admin {
        #[command(subcommand)]
        action: AdminCommands,
    },
}

#[derive(Subcommand)]
enum AdminCommands {
    
    Setup,
    
    Change,
    
    Reset,
    
    Status,
    
    Auth,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    
    let level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
    .with_max_level(if level == "debug" { tracing::Level::DEBUG } else { tracing::Level::INFO })
    .init();

    info!("🔐 Krypton VPN - Authenticated P2P VPN");

    match cli.command {
        Commands::Server { listen } => {
            
            if !admin::setup_admin_if_needed() {
                error!("❌ Admin setup failed - cannot start server");
                std::process::exit(1);
            }
            if !std::path::Path::new(config::USERS_DB_PATH).exists() {
                info!("📁 Creating new user database at {}", config::USERS_DB_PATH);
                let _ = std::fs::write(config::USERS_DB_PATH, "[]");
            }
            info!("🖥️ Starting Krypton VPN Server on {}", listen);
            
            
            let server = protocol::VpnServer::new(listen).await?;
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let tun_name = server.get_tun_name().await; 
            tokio::select! {
             _ = server.start(shutdown_rx) => {},
             _ = signal::ctrl_c() => {
                let _ = shutdown_tx.send(());
                if let Err(e) = tun::restore_default_routes(&tun_name) {
                    error!("⚠️ Failed to restore default routes: {}", e);
                }
                info!("🛑 Server shutdown complete");
           


        }
    }
            
        }
        Commands::Client { peer, username, password } => {
            info!("💻 Starting Krypton VPN Client -> {}", peer);
            
            let client = protocol::VpnClient::new(peer, username, password).await?;
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let tun_name = client.get_tun_name().await;
         tokio::select! {
            _ = client.start(shutdown_rx) => {},
            _ = signal::ctrl_c() => {
            let _ = shutdown_tx.send(());
            if let Err(e) = tun::restore_default_routes(&tun_name) {
                error!("⚠️ Failed to restore default routes: {}", e);
            }
            info!("🛑 Client disconnected");
            std::process::exit(0);
        }
    }
        }
        Commands::Register { username, password } => {
            let mut auth_manager = auth::AuthManager::new()?;
            match auth_manager.register_user(&username, &password) {
                Ok(_) => {
                    info!("✅ User '{}' registered successfully!", username);
                    info!("💡 Rebuild the project to embed the new user data");
                }
                Err(e) => error!("❌ Registration failed: {}", e),
            }
            return Ok(());
        }
        Commands::Status => {
            show_status().await?;
        }
        Commands::TestTun => {
            test_tun_creation().await?;
        }
        Commands::TestAuth => {
            test_authentication().await?;
        }
        Commands::TestCrypto => {
            test_cryptography().await?;
        }
        Commands::Admin { action } => {
            handle_admin_command(action).await?;
        }
    }

    Ok(())
}

async fn handle_admin_command(action: AdminCommands) -> Result<()> {
    match action {
        AdminCommands::Setup => {
            if admin::setup_admin_if_needed() {
                println!("✅ Admin setup completed successfully");
            } else {
                println!("❌ Admin setup failed");
                std::process::exit(1);
            }
        }
        AdminCommands::Change => {
            if admin::change_admin_password() {
                println!("✅ Admin password changed successfully");
            } else {
                println!("❌ Failed to change admin password");
                std::process::exit(1);
            }
        }
        AdminCommands::Reset => {
            if admin::reset_admin_password() {
                println!("✅ Admin password reset successfully");
            } else {
                println!("❌ Failed to reset admin password");
                std::process::exit(1);
            }
        }
        AdminCommands::Status => {
            admin::show_admin_status();
        }
        AdminCommands::Auth => {
            if admin::authenticate_admin() {
                println!("✅ Admin authentication successful");
            } else {
                println!("❌ Admin authentication failed");
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

async fn show_status() -> Result<()> {
    println!("📊 Krypton VPN Status");
    println!("==========================================");
    println!("Version: 1.0.0");
    println!("Platform: {}", std::env::consts::OS);
    println!("Architecture: {}", std::env::consts::ARCH);
    
    
    admin::show_admin_status();
    
    
    println!("\n🔧 Configuration:");
    println!("Users Database: cryptlink_users.json");
    println!("Admin Config: cryptlink_admin.json");
    
    if cfg!(target_os = "windows") {
        println!("TUN Driver: WinTUN");
        if std::path::Path::new("wintun.dll").exists() {
            println!("WinTUN DLL: ✅ Found");
        } else {
            println!("WinTUN DLL: ❌ Missing");
        }
    } else if cfg!(target_os = "linux") {
        println!("TUN Driver: Linux TUN/TAP");
        if std::path::Path::new("/dev/net/tun").exists() {
            println!("TUN Device: ✅ Available");
        } else {
            println!("TUN Device: ❌ Not found");
        }
    }
    
    println!("==========================================");
    Ok(())
}

async fn test_tun_creation() -> Result<()> {
    println!("🔧 Testing TUN interface creation...");
    
    match tun::create_server_tun() {
        Ok(tun_interface) => {
            println!("✅ Server TUN interface created successfully");
            println!("   Name: {}", tun_interface.get_name());
            println!("   Status: Ready");
        }
        Err(e) => {
            println!("❌ Failed to create server TUN interface: {}", e);
        }
    }
    
    match tun::create_client_tun() {
        Ok(tun_interface) => {
            println!("✅ Client TUN interface created successfully");
            println!("   Name: {}", tun_interface.get_name());
            println!("   Status: Ready");
        }
        Err(e) => {
            println!("❌ Failed to create client TUN interface: {}", e);
        }
    }
    
    Ok(())
}

async fn test_authentication() -> Result<()> {
    println!("🔐 Testing authentication system...");
    
    
    match config::load_embedded_users() {
        Ok(users) => {
            println!("✅ User database loaded successfully");
            println!("   Users found: {}", users.len());
            for user in users {
                println!("   - {}: {} (admin: {})", 
                    user.username, 
                    user.vpn_ip.unwrap_or_else(|| "No IP".to_string()), 
                    user.is_admin
                );
            }
        }
        Err(e) => {
            println!("❌ Failed to load user database: {}", e);
        }
    }
    
    
    match config::load_embedded_admin_config() {
        Ok(admin_config) => {
            println!("✅ Admin configuration loaded successfully");
            println!("   Setup complete: {}", admin_config.setup_complete);
            println!("   Created: {}", admin_config.created_at);
        }
        Err(e) => {
            println!("❌ Failed to load admin configuration: {}", e);
        }
    }
    
    Ok(())
}

async fn test_cryptography() -> Result<()> {
    println!("🔑 Testing cryptographic system...");
    
    let mut crypto_manager = crypto::CryptoManager::new();
    
    
    let session_token = "test_session_12345";
    let test_data = b"Hello, Krypton VPN!";
    
    match crypto_manager.encrypt_packet(session_token, test_data) {
        Ok(encrypted) => {
            println!("✅ Packet encryption successful");
            println!("   Original size: {} bytes", test_data.len());
            println!("   Encrypted size: {} bytes", encrypted.len());
            
            
            match crypto_manager.decrypt_packet(session_token, &encrypted) {
                Ok(decrypted) => {
                    if decrypted == test_data {
                        println!("✅ Packet decryption successful");
                        println!("   Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
                    } else {
                        println!("❌ Decryption data mismatch");
                    }
                }
                Err(e) => {
                    println!("❌ Packet decryption failed: {}", e);
                }
            }
        }
        Err(e) => {
            println!("❌ Packet encryption failed: {}", e);
        }
    }
    
    Ok(())
}
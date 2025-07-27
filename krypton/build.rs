use std::env;
use std::fs;
use std::path::Path;
use std::io::{self, Write};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct AdminConfig {
    password_hash: String,
    salt: String,
    setup_complete: bool,
    created_at: String,
    last_updated: Option<String>,
    security_settings: SecuritySettings,
}

#[derive(Serialize, Deserialize)]
struct SecuritySettings {
    max_failed_attempts: u32,
    session_timeout_hours: u32,
    require_strong_passwords: bool,
    enable_2fa: bool,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            password_hash: String::new(),
            salt: String::new(),
            setup_complete: false,
            created_at: "2024-01-01T00:00:00Z".to_string(),
            last_updated: None,
            security_settings: SecuritySettings {
                max_failed_attempts: 3,
                session_timeout_hours: 24,
                require_strong_passwords: true,
                enable_2fa: false,
            },
        }
    }
}

fn main() {
    println!("🔐 CryptLink Build System Starting...");
    
    // Platform-specific setup
    if cfg!(target_os = "windows") {
        setup_windows_environment();
    } else if cfg!(target_os = "linux") {
        setup_linux_environment();
    } else {
        println!("⚠️  Unsupported platform - Only Windows and Linux are supported");
        return;
    }
    
    // Setup embedded databases with admin configuration
    setup_embedded_databases_with_admin();
    
    // Generate embedded constants
    generate_embedded_constants();
    
    // Platform-specific post-build instructions
    print_platform_instructions();
    
    println!("✅ Build setup completed successfully!");
}

fn setup_windows_environment() {
    println!("🪟 Setting up Windows environment...");
    
    // Setup WinTUN DLL
    setup_windows_tun();
    
    // Windows-specific linking
    println!("cargo:rustc-link-lib=ws2_32");
    println!("cargo:rustc-link-lib=iphlpapi");
    println!("cargo:rustc-link-lib=netapi32");
    
    println!("✅ Windows environment configured");
}

fn setup_linux_environment() {
    println!("🐧 Setting up Linux environment...");
    
    // Check TUN/TAP support
    check_linux_tun_support();
    
    // Check required capabilities and permissions
    check_linux_permissions();
    
    // Setup Linux-specific build requirements
    setup_linux_build_requirements();
    
    println!("✅ Linux environment configured");
}

fn setup_windows_tun() {
    println!("🪟 Setting up Windows TUN interface (WinTUN)");
    
    let target_dir = env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    let dll_paths = vec![
        format!("{}/debug/wintun.dll", target_dir),
        format!("{}/release/wintun.dll", target_dir),
        "wintun.dll".to_string(),
    ];
    
    let dll_exists = dll_paths.iter().any(|path| Path::new(path).exists()) 
        || Path::new("wintun.dll").exists();
    
    if !dll_exists {
        println!("📥 WinTUN DLL not found - downloading automatically...");
        
        match download_wintun_dll() {
            Ok(_) => {
                println!("✅ WinTUN DLL downloaded successfully");
            }
            Err(e) => {
                println!("❌ Auto-download failed: {}", e);
                print_manual_wintun_instructions();
                return;
            }
        }
    } else {
        println!("✅ WinTUN DLL found");
    }
    
    // Copy DLL to target directories
    if Path::new("wintun.dll").exists() {
        for dll_path in &dll_paths {
            if let Some(parent) = Path::new(dll_path).parent() {
                if parent.exists() || fs::create_dir_all(parent).is_ok() {
                    match fs::copy("wintun.dll", dll_path) {
                        Ok(_) => println!("📋 Copied wintun.dll to {}", dll_path),
                        Err(e) => println!("⚠️  Failed to copy wintun.dll to {}: {}", dll_path, e),
                    }
                }
            }
        }
    }
}

fn check_linux_tun_support() {
    println!("🔍 Checking Linux TUN/TAP support...");
    
    if Path::new("/dev/net/tun").exists() {
        println!("✅ /dev/net/tun device found");
    } else {
        println!("⚠️  /dev/net/tun not found - TUN module may not be loaded");
        println!("💡 You may need to load TUN module: sudo modprobe tun");
    }
    
    // Check if TUN module is loaded
    if let Ok(modules) = fs::read_to_string("/proc/modules") {
        if modules.contains("tun ") {
            println!("✅ TUN module is loaded");
        } else {
            println!("⚠️  TUN module not loaded - VPN may not work");
        }
    }
    
    // Check kernel version for modern netlink support
    if let Ok(version) = fs::read_to_string("/proc/version") {
        println!("🐧 Kernel: {}", version.lines().next().unwrap_or("Unknown"));
    }
}

fn check_linux_permissions() {
    println!("🔐 Checking Linux permissions and capabilities...");
    
    // Check if running as root during build (unlikely but possible)
    #[cfg(unix)]
    {
        if unsafe { libc::getuid() } == 0 {
            println!("✅ Building as root - runtime will have all permissions");
            return;
        }
    }
    
    // Check for CAP_NET_ADMIN capability tools
    match std::process::Command::new("getcap").arg("--version").output() {
        Ok(_) => println!("✅ getcap tool available for capability checking"),
        Err(_) => println!("⚠️  getcap not found - install libcap2-bin for capability management"),
    }
    
    // Check sudo availability
    match std::process::Command::new("sudo").arg("-n").arg("true").output() {
        Ok(output) => {
            if output.status.success() {
                println!("✅ Passwordless sudo available");
            } else {
                println!("⚠️  Sudo may require password");
            }
        }
        Err(_) => {
            println!("⚠️  Sudo not available");
        }
    }
}

fn setup_linux_build_requirements() {
    println!("🔧 Setting up Linux build requirements...");
    
    // Check for required system libraries
    let required_libs = [
        ("libc.so.6", "glibc"),
        ("libpthread.so.0", "pthread"),
    ];
    
    for (lib, name) in &required_libs {
        match std::process::Command::new("ldconfig")
            .arg("-p")
            .output()
        {
            Ok(output) => {
                let ldconfig_output = String::from_utf8_lossy(&output.stdout);
                if ldconfig_output.contains(lib) {
                    println!("✅ {} library found", name);
                } else {
                    println!("⚠️  {} library not found", name);
                }
            }
            Err(_) => {
                println!("⚠️  Could not check system libraries");
                break;
            }
        }
    }
    
    // Check for development tools
    let dev_tools = ["gcc", "make", "pkg-config"];
    for tool in &dev_tools {
        match std::process::Command::new("which").arg(tool).output() {
            Ok(output) => {
                if output.status.success() {
                    println!("✅ {} found", tool);
                } else {
                    println!("⚠️  {} not found - may be needed for dependencies", tool);
                }
            }
            Err(_) => {
                println!("⚠️  Could not check for {}", tool);
            }
        }
    }
}

fn setup_embedded_databases_with_admin() {
    println!("📋 Setting up embedded databases with admin configuration...");
    
    let users_file = "cryptlink_users.json";
    let admin_file = "cryptlink_admin.json";
    
    // Setup users database
    if !Path::new(users_file).exists() {
        println!("📝 Creating default users database: {}", users_file);
        create_default_users_file(users_file);
    } else {
        println!("✅ Users database found: {}", users_file);
    }
    
    // Setup admin configuration for runtime setup
    setup_admin_configuration(admin_file);
    
    println!("cargo:rerun-if-changed={}", users_file);
    println!("cargo:rerun-if-changed={}", admin_file);
}

fn setup_admin_configuration(admin_file: &str) {
    // Skip interactive admin setup during build - handle at runtime like AuthWall
    if !Path::new(admin_file).exists() {
        println!("🔧 Creating empty admin configuration - setup required at runtime");
        
        let config = AdminConfig {
            password_hash: String::new(),
            salt: String::new(),
            setup_complete: false, // Requires runtime setup
            created_at: get_current_timestamp(),
            last_updated: None,
            security_settings: SecuritySettings {
                max_failed_attempts: 3,
                session_timeout_hours: 24,
                require_strong_passwords: true,
                enable_2fa: false,
            },
        };
        
        save_admin_config(admin_file, &config);
        println!("💡 Admin setup will be prompted on first application run");
    } else {
        // Check if existing config is complete
        match fs::read_to_string(admin_file) {
            Ok(content) => {
                match serde_json::from_str::<AdminConfig>(&content) {
                    Ok(config) => {
                        if config.setup_complete && !config.password_hash.is_empty() {
                            println!("✅ Admin configuration found and validated");
                        } else {
                            println!("⚠️  Admin configuration incomplete - will be prompted at runtime");
                        }
                    }
                    Err(_) => {
                        println!("⚠️  Invalid admin configuration - will be recreated at runtime");
                    }
                }
            }
            Err(_) => {
                println!("❌ Failed to read admin configuration - will be recreated at runtime");
            }
        }
    }
}

fn save_admin_config(admin_file: &str, config: &AdminConfig) -> bool {
    match serde_json::to_string_pretty(config) {
        Ok(json) => {
            match fs::write(admin_file, json) {
                Ok(_) => {
                    println!("✅ Admin configuration template created");
                    true
                }
                Err(e) => {
                    println!("❌ Failed to write admin config: {}", e);
                    false
                }
            }
        }
        Err(e) => {
            println!("❌ Failed to serialize admin config: {}", e);
            false
        }
    }
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

fn create_default_users_file(path: &str) {
    let default_users = r#"[
  {
    "username": "test",
    "password_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "salt": "default_salt_test_user_only",
    "created_at": 1704067200,
    "is_admin": false,
    "vpn_ip": "10.8.0.100"
  }
]"#;
    
    match fs::write(path, default_users) {
        Ok(_) => println!("✅ Created default users file: {}", path),
        Err(e) => println!("⚠️  Failed to create {}: {}", path, e),
    }
}

fn generate_embedded_constants() {
    println!("📝 Generating embedded constants...");
    
    let users_content = fs::read_to_string("cryptlink_users.json")
        .unwrap_or_else(|_| "[]".to_string());
    
    let admin_content = fs::read_to_string("cryptlink_admin.json")
        .unwrap_or_else(|_| "{}".to_string());
    
    // Create properly escaped embedded constants
    let escaped_users = users_content.replace('"', r#"\""#);
    let escaped_admin = admin_content.replace('"', r#"\""#);
    
    let constants = format!(
        r#"// Auto-generated embedded constants - DO NOT EDIT
// This file is generated by build.rs during compilation

pub const EMBEDDED_USERS: &str = "{}";
pub const EMBEDDED_ADMIN_CONFIG: &str = "{}";
"#, escaped_users, escaped_admin);
    
    if let Err(e) = fs::write("src/embedded_constants.rs", constants) {
        println!("⚠️  Failed to generate embedded constants: {}", e);
    } else {
        println!("✅ Embedded constants generated");
    }
}

fn print_platform_instructions() {
    println!("\n📋 Platform-Specific Instructions:");
    println!("==========================================");
    
    if cfg!(target_os = "windows") {
        println!("🪟 Windows:");
        println!("   • Run as Administrator for full VPN functionality");
        println!("   • Windows Defender may require firewall exceptions");
        println!("   • WinTUN driver will be installed automatically");
        
    } else if cfg!(target_os = "linux") {
        println!("🐧 Linux:");
        println!("   • Run with elevated privileges:");
        println!("     sudo ./target/debug/cryptlink");
        println!("   • Or set capabilities:");
        println!("     sudo setcap cap_net_admin+ep ./target/debug/cryptlink");
        println!("   • For release build:");
        println!("     sudo setcap cap_net_admin+ep ./target/release/cryptlink");
        println!("   • Ensure TUN module is loaded:");
        println!("     sudo modprobe tun");
        println!("   • Make TUN persistent:");
        println!("     echo 'tun' | sudo tee -a /etc/modules");
        
        // Additional Linux-specific checks
        if !Path::new("/dev/net/tun").exists() {
            println!("   ⚠️  WARNING: /dev/net/tun not found!");
            println!("   ⚠️  VPN will not work without TUN support");
        }
    }
    
    println!("\n🔐 Admin Setup:");
    println!("   • Admin password will be prompted on first run");
    println!("   • Like AuthWall, admin setup is handled at runtime");
    println!("   • Admin config: cryptlink_admin.json");
    println!("   • User database: cryptlink_users.json");
    println!("==========================================\n");
}

// Windows-specific functions
fn download_wintun_dll() -> Result<(), Box<dyn std::error::Error>> {
    println!("🌐 Downloading WinTUN DLL from official source...");
    
    let url = "https://www.wintun.net/builds/wintun-0.14.1.zip";
    let response = std::process::Command::new("powershell")
        .args([
            "-Command",
            &format!(
                "Invoke-WebRequest -Uri '{}' -OutFile 'wintun.zip'",
                url
            ),
        ])
        .output()?;
    
    if !response.status.success() {
        return Err("Failed to download WinTUN ZIP".into());
    }
    
    // Extract the DLL
    let extract_cmd = std::process::Command::new("powershell")
        .args([
            "-Command",
            "Expand-Archive -Path 'wintun.zip' -DestinationPath 'temp_wintun' -Force"
        ])
        .output()?;
    
    if !extract_cmd.status.success() {
        return Err("Failed to extract WinTUN ZIP".into());
    }
    
    // Copy the appropriate DLL
    let arch = if cfg!(target_arch = "x86_64") { "amd64" } else { "x86" };
    let dll_source = format!("temp_wintun/wintun/bin/{}/wintun.dll", arch);
    
    if Path::new(&dll_source).exists() {
        fs::copy(&dll_source, "wintun.dll")?;
        
        // Cleanup
        let _ = fs::remove_dir_all("temp_wintun");
        let _ = fs::remove_file("wintun.zip");
        
        Ok(())
    } else {
        Err("WinTUN DLL not found in expected location".into())
    }
}

fn print_manual_wintun_instructions() {
    println!("\n📋 Manual WinTUN Setup Instructions:");
    println!("==========================================");
    println!("1. Download WinTUN from: https://www.wintun.net/");
    println!("2. Extract the ZIP file");
    println!("3. Copy wintun.dll from bin/amd64/ (or bin/x86/) to this directory");
    println!("4. Run 'cargo build' again");
    println!("==========================================\n");
}
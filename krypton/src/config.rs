use std::net::Ipv4Addr;
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;
use anyhow::{Context, Result};

pub const USERS_DB_FILE: &str = "cryptlink_users.json";
pub const USERS_DB_PATH: &str = "./cryptlink_users.json";
pub const DEFAULT_SERVER_PORT:u16=9001;
pub const DEFAULT_CLIENT_PORT:u16=0;

pub const SERVER_TUN_ADDRESS:&str="10.8.0.1";
pub const CLIENT_TUN_ADDRESS:&str="10.8.0.2";
pub const TUN_NETMASK:&str="255.255.255.0";

pub const VPN_NETWORK:Ipv4Addr=Ipv4Addr::new(10,8,0,0);
pub const VPN_NETMASK:Ipv4Addr=Ipv4Addr::new(255,255,255,0);

pub const AES_KEY_SIZE:usize=32;
pub const AES_NONCE_SIZE:usize=12;
pub const X25519_PUBLIC_KEY_SIZE:usize=32;

pub const MAX_PACKET_SIZE:usize=1504;

pub const PROTOCOL_ICMP:u8=1;
pub const PROTOCOL_TCP:u8=6;
pub const PROTOCOL_UDP:u8=17;
pub const PROTOCOL_IPV6:u8=41;
pub const PROTOCOL_GRE:u8=47;
pub const PROTOCOL_ESP:u8=50;
pub const PROTOCOL_AH:u8=51;


pub const TUN_MTU:usize=1500;
pub const MIN_PACKET_SIZE:usize=20;
pub const MAX_IP_HEADER_SIZE:usize=60;
pub const MAX_TCP_HEADER_SIZE:usize=60;
pub const UDP_HEADER_SIZE:usize=8;
pub const ICMP_HEADER_SIZE:usize=8;

pub const AUTH_TIMEOUT_SECS:u64=60;
pub const HANDSHAKE_TIMEOUT_SECS:u64=10;
pub const KEEPALIVE_INTERVAL_SECS:u64=30;

pub const ADMIN_CONFIG_FILE:&str="cryptlink_admin.json";

include!("embedded_constants.rs");

pub const MAX_FAILED_ATTEMPTS: usize = 3;
pub const SESSION_TIMEOUT_HOURS: u64 = 24;
pub const TOKEN_EXPIRY_MINUTES: u64 = 60;

pub fn get_server_tun_name()->String{
    format!("Krypton_server_{}",std::process::id())
}
pub fn get_client_tun_name()->String{
    format!("Krypton_client_{}",std::process::id())
}

pub fn is_valid_vpn_ip(ip:&str)->bool{
    if let Ok(addr)=ip.parse::<Ipv4Addr>(){
        let octets=addr.octets();
        octets[0]==10&&octets[1]==8&&octets[2]==0
    }else{
        false
    }
}
pub fn get_ip_protocol(packet:&[u8])->Option<u8>{
    if packet.len()<20{
        return None;
    }

    if (packet[0]>>4)==4{
        Some(packet[9])
    }else if(packet[0]>>4)==6{
        Some(packet[6])
    }else{
        None
    }
}

pub fn get_protocol_name(protocol:u8)->&'static str{
    match protocol{
        PROTOCOL_ICMP => "ICMP",
        PROTOCOL_TCP => "TCP",
        PROTOCOL_UDP => "UDP",
        PROTOCOL_IPV6 => "IPv6",
        PROTOCOL_GRE => "GRE",
        PROTOCOL_ESP => "ESP",
        PROTOCOL_AH => "AH",
        _ => "Unknown",
    }
}

pub fn is_valid_packet_size(size:usize)->bool{
    size>=MIN_PACKET_SIZE&&size<=MAX_PACKET_SIZE
}

pub fn get_optimal_buffer_size(protocol:u8)->usize{
    match protocol{
        PROTOCOL_TCP=>MAX_PACKET_SIZE,
        PROTOCOL_UDP=>MAX_PACKET_SIZE,
        PROTOCOL_ICMP=>1472,
        _=>MAX_PACKET_SIZE,
    }
}

pub fn is_valid_port(port:u16)->bool{
    port>0
}

pub const PORT_HTTP:u16=80;
pub const PORT_HTTPS:u16=443;
pub const PORT_SSH:u16=22;
pub const PORT_DNS:u16=53;
pub const PORT_DHCP_SERVER:u16=67;
pub const PORT_DHCP_CLIENT:u16=68;
pub const PORT_SMTP:u16=25;
pub const PORT_POP3:u16=110;
pub const PORT_IMAP:u16=143;
pub const PORT_FTP:u16=21;
pub const PORT_TELNET:u16=23;

pub const PROTOCOL_VERSION:u8=1;
pub const MSG_AUTH_REQUEST:u8=0x01;
pub const MSG_AUTH_RESPONSE:u8=0x02;
pub const MSG_KEY_EXCHANGE:u8=0x03;
pub const MSG_VPN_DATA:u8=0x04;
pub const MSG_HEARTBEAT:u8=0x05;
pub const MSG_DISCONNECT:u8=0x06;

pub const HIGH_PRIORITY_PROTOCOLS:&[u8]=&[PROTOCOL_ICMP];
pub const MEDIUM_PRIORITY_PROTOCOLS:&[u8]=&[PROTOCOL_TCP];
pub const LOW_PRIORITY_PROTOCOLS:&[u8]=&[PROTOCOL_UDP];

pub const DEFAULT_GATEWAY:&str="10.8.0.1";
pub const DNS_SERVER:&str="10.8.0.1";

pub const ALLOW_BROADCAST:bool=true;
pub const ALLOW_MULTICAST:bool=true;
pub const DROP_INVALID_PACKETS:bool=true;


pub const LOCAL_NETWORK: &str = "192.168.1.0/24";


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password_hash: String,
    pub salt: String,
    pub created_at: u64,
    pub is_admin: bool,
    pub vpn_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminConfig {
    pub password_hash: String,
    pub salt: String,
    pub setup_complete: bool,
    pub created_at: String,
    pub last_updated: Option<String>,
    pub security_settings: SecuritySettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    pub max_failed_attempts: u32,
    pub session_timeout_hours: u32,
    pub require_strong_passwords: bool,
    pub enable_2fa: bool,
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


pub fn load_embedded_users() -> anyhow::Result<Vec<User>> {
    if EMBEDDED_USERS.trim().is_empty() {
        Ok(Vec::new())
    } else {
        serde_json::from_str(EMBEDDED_USERS)
            .map_err(|e| anyhow::anyhow!("Failed to parse embedded users: {}", e))
    }
}

pub fn load_embedded_admin_config() -> Result<AdminConfig, String> {
    if EMBEDDED_ADMIN_CONFIG.trim().is_empty() {
        Ok(AdminConfig::default())
    } else {
        serde_json::from_str(EMBEDDED_ADMIN_CONFIG)
            .map_err(|e| format!("Failed to parse embedded admin config: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vpn_ip_validation() {
        
        assert!(is_valid_vpn_ip("10.8.0.1"));
        assert!(is_valid_vpn_ip("10.8.0.255"));
        
        
        assert!(!is_valid_vpn_ip("192.168.1.1"));
        assert!(!is_valid_vpn_ip("10.9.0.1"));
        assert!(!is_valid_vpn_ip("invalid"));
    }

    #[test]
    fn test_protocol_detection() {
        
        let tcp_packet = [
            0x45, 0x00, 0x00, 0x28, 
            0x00, 0x00, 0x40, 0x00, 
            0x40, 0x06, 0x00, 0x00, 
            0x0a, 0x08, 0x00, 0x01, 
            0x0a, 0x08, 0x00, 0x02, 
        ];
        
        assert_eq!(get_ip_protocol(&tcp_packet), Some(PROTOCOL_TCP));
        assert_eq!(get_protocol_name(PROTOCOL_TCP), "TCP");
    }

    #[test]
    fn test_packet_size_validation() {
        assert!(is_valid_packet_size(64));      
        assert!(is_valid_packet_size(1500));    
        assert!(!is_valid_packet_size(10));     
        assert!(!is_valid_packet_size(2000));   
    }

    #[test]
    fn test_port_validation() {
        assert!(is_valid_port(80));       
        assert!(is_valid_port(65535));    
        assert!(!is_valid_port(0));       
    }

    #[test] 
    fn test_tun_names() {
        let server_tun_name = get_server_tun_name();
        let client_tun_name = get_client_tun_name();
        
        assert!(!server_tun_name.is_empty());
        assert!(!client_tun_name.is_empty());
        assert_ne!(server_tun_name, client_tun_name);
        assert!(server_tun_name.contains("server"));
        assert!(client_tun_name.contains("client"));
    }

    #[test]
    fn test_buffer_sizing() {
        assert_eq!(get_optimal_buffer_size(PROTOCOL_TCP), MAX_PACKET_SIZE);
        assert_eq!(get_optimal_buffer_size(PROTOCOL_UDP), MAX_PACKET_SIZE);
        assert_eq!(get_optimal_buffer_size(PROTOCOL_ICMP), 1472);
    }

    #[test]
    fn test_embedded_users_parsing() {
        let result = load_embedded_users();
        assert!(result.is_ok(), "Embedded users should parse successfully");
    }
}
use std::time::{SystemTime, UNIX_EPOCH};

#[allow(dead_code)]
pub fn get_unique_tun_name() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("warpwire_{}", timestamp)
}

pub const SERVER_TUN_ADDRESS: &str = "10.0.0.1";
pub const CLIENT_TUN_ADDRESS: &str = "10.0.0.2";

#[allow(dead_code)]
pub const TUN_MASK: &str = "255.255.255.0";

#[allow(dead_code)]
pub const UDP_PORT: u16 = 9001;

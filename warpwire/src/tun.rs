use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use wintun::Session;

pub struct TunInterface {
    session: Arc<Session>,
}

impl TunInterface {
    pub fn receive_blocking(&self) -> Result<wintun::Packet, wintun::Error> {
        self.session.receive_blocking()
    }

    pub fn send_packet(&self, data: &[u8]) -> Result<(), wintun::Error> {
        let mut packet = self.session.allocate_send_packet(data.len() as u16)?;
        packet.bytes_mut().copy_from_slice(data);
        self.session.send_packet(packet);
        Ok(())
    }
}

pub fn create_tun(name: &str, ip: &str) -> anyhow::Result<Arc<Mutex<TunInterface>>> {
    println!("🔧 Creating TUN interface: {} at {}", name, ip);
    
    // Parse IP address
    let ip_addr: Ipv4Addr = ip.parse()?;
    
    // Load WinTUN library
    let wintun = unsafe { wintun::load()? };
    
    // Create adapter using correct wintun API
    let adapter = wintun::Adapter::create(&wintun, name, "WarpWire", None)?;
    
    println!("✅ Created adapter: {}", name);
    
    // Start session
    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);
    
    // Configure IP address
    configure_interface_ip(name, ip_addr)?;
    
    let tun_interface = TunInterface { session };
    
    println!("✅ TUN interface '{}' created successfully at {}", name, ip);
    Ok(Arc::new(Mutex::new(tun_interface)))
}

fn configure_interface_ip(interface_name: &str, ip: Ipv4Addr) -> anyhow::Result<()> {
    use std::process::Command;
    
    println!("🔧 Configuring interface IP: {} -> {}", interface_name, ip);
    
    // Wait for interface to be ready
    std::thread::sleep(std::time::Duration::from_millis(1000));
    
    // Set static IP address using netsh
    let output = Command::new("netsh")
        .args(&[
            "interface", "ipv4", "set", "address",
            interface_name,
            "static",
            &ip.to_string(),
            "255.255.255.0"
        ])
        .output()?;
    
    if !output.status.success() {
        let error = String::from_utf8_lossy(&output.stderr);
        println!("⚠️  netsh failed: {}", error);
        
        // Try with name= prefix
        let alt_output = Command::new("netsh")
            .args(&[
                "interface", "ipv4", "set", "address",
                &format!("name=\"{}\"", interface_name),
                "source=static",
                &format!("addr={}", ip),
                "mask=255.255.255.0"
            ])
            .output()?;
            
        if !alt_output.status.success() {
            let alt_error = String::from_utf8_lossy(&alt_output.stderr);
            println!("⚠️  Both netsh attempts failed: {}", alt_error);
        } else {
            println!("✅ IP configured with alternative method");
        }
    } else {
        println!("✅ IP configured successfully");
    }
    
    Ok(())
}

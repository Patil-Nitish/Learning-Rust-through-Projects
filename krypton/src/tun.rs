use crate::config;
use anyhow::{Result, anyhow};
use std::sync::Arc;
use tracing::{info, error, warn};
use std::process::Command;

pub struct TunInterface {
    #[cfg(windows)]
    inner: windows_tun::WindowsTun,
    #[cfg(unix)]
    inner: unix_tun::UnixTun,
}

impl TunInterface {
    pub fn receive_blocking(&self) -> Result<Vec<u8>> {
        #[cfg(windows)]
        return self.inner.receive_blocking();
        #[cfg(unix)]
        return self.inner.receive_blocking();
    }

    pub fn send_packet(&self, data: &[u8]) -> Result<()> {
        #[cfg(windows)]
        return self.inner.send_packet(data);
        #[cfg(unix)]
        return self.inner.send_packet(data);
    }

    pub fn get_name(&self) -> &str {
        #[cfg(windows)]
        return &self.inner.name;
        #[cfg(unix)]
        return &self.inner.name;
    }
}

pub fn create_server_tun() -> Result<TunInterface> {
    let name = config::get_server_tun_name();
    create_tun(&name, config::SERVER_TUN_ADDRESS)
}

pub fn create_client_tun() -> Result<TunInterface> {
    let name = config::get_client_tun_name();
    create_tun(&name, config::CLIENT_TUN_ADDRESS)
}

pub fn create_tun(name: &str, ip: &str) -> Result<TunInterface> {
    info!("🔧 Creating TUN interface: {} at {}", name, ip);
    
    if !config::is_valid_vpn_ip(ip) {
        warn!("⚠️  IP {} is outside VPN range (10.8.0.x)", ip);
    }
    
    #[cfg(windows)]
    {
        let inner = windows_tun::create_windows_tun(name, ip)?;
        Ok(TunInterface { inner })
    }
    
    #[cfg(unix)]
    {
        let inner = unix_tun::create_unix_tun(name, ip)?;
        Ok(TunInterface { inner })
    }
    
    #[cfg(not(any(windows, unix)))]
    {
        anyhow::bail!("Unsupported platform for TUN interface");
    }
}

#[cfg(windows)]
mod windows_tun {
    use super::*;
    use std::net::Ipv4Addr;
    use wintun::Session;

    pub struct WindowsTun {
        pub name: String,
        session: Arc<Session>,
    }

    impl WindowsTun {
        pub fn receive_blocking(&self) -> Result<Vec<u8>> {
            match self.session.receive_blocking() {
                Ok(packet) => {
                    let data = packet.bytes().to_vec();
                    Ok(data)
                }
                Err(e) => {
                    error!("Windows TUN receive error: {}", e);
                    Err(e.into())
                }
            }
        }

        pub fn send_packet(&self, data: &[u8]) -> Result<()> {
            match self.session.allocate_send_packet(data.len() as u16) {
                Ok(mut packet) => {
                    packet.bytes_mut().copy_from_slice(data);
                    self.session.send_packet(packet);
                    Ok(())
                }
                Err(e) => {
                    error!("Windows TUN send error: {}", e);
                    Err(e.into())
                }
            }
        }
    }

    pub fn create_windows_tun(name: &str, ip: &str) -> Result<WindowsTun> {
        info!("🪟 Creating Windows TUN interface ");
        
        let ip_addr: Ipv4Addr = ip.parse()
            .map_err(|e| anyhow::anyhow!("Invalid IP address '{}': {}", ip, e))?;
        
        let wintun = unsafe { 
            wintun::load().map_err(|e| {
                anyhow::anyhow!("Failed to load WinTUN library: {}", e)
            })?
        };
        
        let adapter = wintun::Adapter::create(&wintun, name, "Krypton", None)
            .map_err(|e| anyhow::anyhow!("Failed to create WinTUN adapter '{}': {}", name, e))?;
        
        info!("✅ Created adapter: {}", name);
        
        let session = Arc::new(
            adapter.start_session(wintun::MAX_RING_CAPACITY)
                .map_err(|e| anyhow::anyhow!("Failed to start WinTUN session: {}", e))?
        );
        
        configure_interface_ip(name, ip_addr)?;
        
        Ok(WindowsTun { 
            name: name.to_string(),
            session,
        })
    }

    fn configure_interface_ip(interface_name: &str, ip: Ipv4Addr) -> Result<()> {
        use std::process::Command;
        
        info!("🔧 Configuring interface IP: {} -> {}", interface_name, ip);
        
        std::thread::sleep(std::time::Duration::from_millis(1000));
        
        let output = Command::new("netsh")
            .args(&[
                "interface", "ipv4", "set", "address",
                interface_name,
                "static",
                &ip.to_string(),
                config::TUN_NETMASK
            ])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to run netsh: {}", e))?;
        
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            warn!("⚠️  Primary netsh failed: {}", error);
            
            let alt_output = Command::new("netsh")
                .args(&[
                    "interface", "ipv4", "set", "address",
                    &format!("name={}", interface_name),
                    "static",
                    &ip.to_string(),
                    config::TUN_NETMASK
                ])
                .output()
                .map_err(|e| anyhow::anyhow!("Failed to run alternative netsh: {}", e))?;
            
            if !alt_output.status.success() {
                let alt_error = String::from_utf8_lossy(&alt_output.stderr);
                error!("❌ Both netsh methods failed: {}", alt_error);
                error!("💡 You may need to configure IP manually: {}", ip);
            } else {
                info!("✅ Interface IP configured successfully (alternative method)");
            }
        } else {
            info!("✅ Interface IP configured successfully");
        }
        
        Ok(())
    }
}

#[cfg(unix)]
mod unix_tun {
    use super::*;
    use std::net::Ipv4Addr;

    pub struct UnixTun {
        pub name: String,
        device: tun::TunSocket,
    }

    impl UnixTun {
        pub fn receive_blocking(&self) -> Result<Vec<u8>> {
            let mut buf = vec![0u8; config::MAX_PACKET_SIZE];
            match self.device.recv(&mut buf) {
                Ok(len) => {
                    buf.truncate(len);
                    Ok(buf)
                }
                Err(e) => {
                    error!("Unix TUN receive error: {}", e);
                    Err(e.into())
                }
            }
        }

        pub fn send_packet(&self, data: &[u8]) -> Result<()> {
            match self.device.send(data) {
                Ok(_) => Ok(()),
                Err(e) => {
                    error!("Unix TUN send error: {}", e);
                    Err(e.into())
                }
            }
        }
    }

    pub fn create_unix_tun(name: &str, ip: &str) -> Result<UnixTun> {
        info!("🐧 Creating Unix TUN interface");
        
        let ip_addr: Ipv4Addr = ip.parse()
            .map_err(|e| anyhow::anyhow!("Invalid IP address '{}': {}", ip, e))?;
        
        check_tun_permissions()?;
        
        let config = tun::Configuration::default()
            .name(name)
            .address(ip_addr)
            .netmask(config::TUN_NETMASK.parse::<Ipv4Addr>()?)
            .up();
        
        let device = tun::create(&config)
            .map_err(|e| anyhow::anyhow!("Failed to create TUN device: {}", e))?;
        
        Ok(UnixTun { 
            name: name.to_string(),
            device,
        })
    }

    fn check_tun_permissions() -> Result<()> {
        if !nix::unistd::geteuid().is_root() {
            warn!("⚠️  Not running as root - TUN creation may fail");
            warn!("💡 Try: sudo ./Krypton or setcap cap_net_admin+ep ./Krypton");
        }
        Ok(())
    }
}


#[cfg(target_os = "windows")] 
pub fn set_default_route_windows(tun_if_name: &str, gateway_ip: &str) -> Result<()> {
    info!("🔧 Setting Windows VPN routing for {}", tun_if_name);
    
    let output = Command::new("powershell")
        .args(&[
            "-Command",
            &format!(
                r#"$adapter = Get-NetAdapter | Where-Object {{ $_.Name -like '*{}*' }};
                $ifIndex = $adapter.InterfaceIndex;
                $localGateway = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {{ $_.ifIndex -ne $ifIndex }}).NextHop;
                
                # Add VPN route
                route delete 10.8.0.0 > $null 2>&1;
                route add 10.8.0.0 mask 255.255.255.0 {} if $ifIndex > $null 2>&1;
                
                # Maintain existing internet routes
                route delete 0.0.0.0 > $null 2>&1;
                route add 0.0.0.0 mask 128.0.0.0 $localGateway > $null 2>&1;
                route add 128.0.0.0 mask 128.0.0.0 $localGateway > $null 2>&1;
                
                # Add local network routes
                route add 192.168.0.0 mask 255.255.0.0 $localGateway > $null 2>&1;
                
                # Set interface metric (higher = lower priority)
                netsh interface ipv4 set interface $ifIndex metric=50 > $null 2>&1;
                
                [PSCustomObject]@{{
                    InterfaceIndex = $ifIndex;
                    LocalGateway = $localGateway 
                }} | ConvertTo-Json"#,
                tun_if_name, gateway_ip
            ),
        ])
        .output()?;

    if !output.status.success() {
        anyhow::bail!("Failed to configure routes: {}", String::from_utf8_lossy(&output.stderr));
    }

    info!("✅ VPN routing configured (split tunnel)");
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn set_default_route_linux(tun_if_name: &str, gateway_ip: &str) -> Result<()> {
    info!("🔧 Setting Linux default route: {} via {}", gateway_ip, tun_if_name);
    
    let status = Command::new("ip")
        .args(["route", "replace", "default", "via", gateway_ip, "dev", tun_if_name])
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to execute ip route command: {}", e))?;

    if status.success() {
        info!("✅ Default route updated via VPN ({} via {})", gateway_ip, tun_if_name);
        Ok(())
    } else {
        Err(anyhow::anyhow!("Failed to set default route on Linux"))
    }
}

pub fn setup_vpn_routing(tun_if_name: &str, gateway_ip: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    return set_default_route_windows(tun_if_name, gateway_ip);
    
    #[cfg(target_os = "linux")]
    return set_default_route_linux(tun_if_name, gateway_ip);
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        warn!("⚠️ Routing setup not implemented for this platform");
        Ok(())
    }
}

pub fn cleanup_vpn_routing(gateway_ip: &str) -> Result<()> {
    info!("🧹 Cleaning up VPN routing for gateway: {}", gateway_ip);
    
    #[cfg(target_os = "windows")]
    {
        
        let _ = Command::new("cmd")
            .args(["/C", "route delete 10.8.0.0"])
            .status();
            
        let _ = Command::new("cmd")
            .args(["/C", &format!("route delete 0.0.0.0 mask 128.0.0.0 {}", gateway_ip)])
            .status();
            
        let _ = Command::new("cmd")
            .args(["/C", &format!("route delete 128.0.0.0 mask 128.0.0.0 {}", gateway_ip)])
            .status();
    }
    
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("ip")
            .args(["route", "del", "10.8.0.0/24"])
            .status();
    }
    
    info!("✅ VPN routing cleanup completed");
    Ok(())
}

pub fn setup_split_tunnel_routing(
    tun_if_name: &str,
    vpn_gateway: &str,
    excluded_networks: &[&str]
) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("powershell")
            .args(&["-Command", 
                &format!("(Get-NetAdapter | Where-Object {{ $_.Name -like '*{}*' }}).InterfaceIndex", 
                tun_if_name)])
            .output()?;
            
        let if_index = String::from_utf8(output.stdout)?.trim().to_string();
        
        if if_index.is_empty() {
            anyhow::bail!("Could not find interface index for TUN device");
        }

        let _ = Command::new("cmd").args(&["/C", "route delete 0.0.0.0"]).status();
        
        Command::new("cmd").args(&["/C", 
            &format!("route add 10.8.0.0 mask 255.255.255.0 {} if {}", 
            vpn_gateway, if_index)])
            .status()?;
        
        for net in excluded_networks {
            let parts: Vec<&str> = net.split('/').collect();
            let mask = cidr_to_mask(parts[1].parse()?);
            
            Command::new("cmd").args(&["/C", 
                &format!("route add {} mask {} {}",
                parts[0], mask, "192.168.1.1")])
                .status()?;
        }

        Command::new("netsh").args(&[
            "interface", "ipv4", "set", "interface",
            &if_index, "metric=50"
        ]).status()?;
    }
    
    #[cfg(target_os = "linux")]
    {
        for net in excluded_networks {
            Command::new("ip").args(&[
                "route", "add", net, "via", 
                "192.168.1.1", "dev", "eth0"
            ]).status()?;
        }
    }
    
    Ok(())
}

fn cidr_to_mask(cidr: u8) -> String {
    let mask = (!0u32 << (32 - cidr)).to_be_bytes();
    format!("{}.{}.{}.{}", mask[0], mask[1], mask[2], mask[3])
}

#[cfg(target_os = "windows")]
pub fn optimize_windows_routing(if_index: u32) -> Result<()> {
    Command::new("netsh")
        .args(&["interface", "ipv4", "set", "interface", 
              &if_index.to_string(), "metric=50"])
        .status()?;
    Ok(())
}

pub fn set_vpn_dns(tun_if_name: &str, dns_server: &str) -> Result<()> {
    #[cfg(windows)] {
        Command::new("netsh")
            .args(&["interface", "ipv4", "set", "dns", 
                   &format!("name={}", tun_if_name), "static", dns_server])
            .status()?;
    }
    #[cfg(unix)] {
        Command::new("resolvectl")
            .args(&["dns", tun_if_name, dns_server])
            .status()?;
    }
    Ok(())
}

pub fn verify_routes() -> Result<()> {
    #[cfg(windows)] {
        let output = Command::new("cmd").args(&["/C", "route print"]).output()?;
        let routes = String::from_utf8(output.stdout)?;
        
        if !routes.contains("10.8.0.0") {
            anyhow::bail!("VPN route not found");
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn enable_ip_forwarding() -> Result<()> {
    Command::new("powershell")
        .args(&["-Command", "Set-NetIPInterface -Forwarding Enabled"])
        .status()?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn enable_ip_forwarding() -> Result<()> {
    Command::new("sysctl")
        .args(&["-w", "net.ipv4.ip_forward=1"])
        .status()?;
    Ok(())
}
#[cfg(target_os = "windows")]
pub fn restore_default_routes(tun_if_name: &str) -> Result<()> {
    info!("🔧 Restoring default routes on Windows...");
    
    let output = Command::new("powershell")
        .args(&[
            "-Command",
            &format!(
                r#"$adapter = Get-NetAdapter | Where-Object {{ $_.Name -like '*{}*' }};
                $ifIndex = $adapter.InterfaceIndex;
                $localGateway = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {{ $_.ifIndex -ne $ifIndex }}).NextHop;
                
                # Remove VPN routes
                route delete 10.8.0.0 > $null 2>&1;
                
                # Restore default route
                route delete 0.0.0.0 > $null 2>&1;
                route delete 128.0.0.0 > $null 2>&1;
                route add 0.0.0.0 mask 0.0.0.0 $localGateway > $null 2>&1;
                
                # Set interface metric back to default
                netsh interface ipv4 set interface $ifIndex metric=auto > $null 2>&1;
                
                [PSCustomObject]@{{ Success = $true }} | ConvertTo-Json"#,
                tun_if_name
            ),
        ])
        .output()?;

    if !output.status.success() {
        anyhow::bail!("Failed to restore routes: {}", String::from_utf8_lossy(&output.stderr));
    }

    info!("✅ Default routes restored");
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn restore_default_routes(tun_if_name: &str) -> Result<()> {
    info!("🔧 Restoring default routes on Linux...");
    
    let status = Command::new("ip")
        .args(["route", "replace", "default", "via", "192.168.1.1", "dev", "eth0"])
        .status()?;

    if !status.success() {
        anyhow::bail!("Failed to restore default route");
    }
    
    info!("✅ Default routes restored");
    Ok(())
}
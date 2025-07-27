


use crate::{auth, config, crypto, tun};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use tracing::{debug, error, info, instrument, warn};
use tokio::signal;
use tokio::sync::oneshot;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VpnMessage {
    AuthRequest {
        username: String,
        password: String,
        client_public_key: String,
    },
    AuthResponse {
        success: bool,
        session_token: Option<String>,
        server_public_key: Option<String>,
        vpn_ip: Option<String>,
        error: Option<String>,
    },
    KeyExchange {
        session_token: String,
        public_key: String,
    },
    VpnData {
        session_token: String,
        encrypted_payload: Vec<u8>,
    },
    Heartbeat {
        session_token: String,
    },
    Disconnect {
        session_token: String,
    },
}


pub fn get_protocol_message_types() -> Vec<u8> {
    vec![
        config::MSG_AUTH_REQUEST,
        config::MSG_AUTH_RESPONSE,
        config::MSG_KEY_EXCHANGE,
        config::MSG_VPN_DATA,
    ]
}


#[derive(Debug, Clone)]
struct NatEntry {
    original_ip: String,
    original_port: u16,
    translated_ip: String,
    translated_port: u16,
    last_used: u64,
}


struct NatTable {
    entries: Arc<Mutex<HashMap<String, NatEntry>>>,
    cleanup_interval: Duration,
}

impl NatTable {
    fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            cleanup_interval: Duration::from_secs(300),
        }
    }

    async fn translate_outbound(&self, src_ip: &str, src_port: u16) -> (String, u16) {
        let mut entries = self.entries.lock().await;
        let key = format!("{}:{}", src_ip, src_port);

        if let Some(entry) = entries.get(&key) {
            return (entry.translated_ip.clone(), entry.translated_port);
        }

        let translated_ip = "10.8.0.1".to_string();
        let translated_port = (50000..60000)
            .find(|&p| !entries.values().any(|e| e.translated_port == p))
            .unwrap_or(50000);

        entries.insert(
            key,
            NatEntry {
                original_ip: src_ip.to_string(),
                original_port: src_port,
                translated_ip: translated_ip.clone(),
                translated_port,
                last_used: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            },
        );

        (translated_ip, translated_port)
    }

    async fn translate_inbound(&self, dst_ip: &str, dst_port: u16) -> Option<(String, u16)> {
        let mut entries = self.entries.lock().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if let Some((_, entry)) = entries
            .iter_mut()
            .find(|(_, e)| e.translated_ip == dst_ip && e.translated_port == dst_port)
        {
            entry.last_used = now;
            return Some((entry.original_ip.clone(), entry.original_port));
        }
        None
    }

    async fn cleanup_expired(&self) {
        let mut entries = self.entries.lock().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        entries.retain(|_, e| now - e.last_used < self.cleanup_interval.as_secs());
    }
}


pub struct VpnServer {
    auth_manager: Arc<Mutex<auth::AuthManager>>,
    crypto_manager: Arc<Mutex<crypto::CryptoManager>>,
    server_tun: Arc<Mutex<tun::TunInterface>>,
    client_sessions: Arc<Mutex<HashMap<String, ClientSession>>>,
    nat_table: Arc<NatTable>,
    bind_addr: String,
    server_public_key: String,
    socket: Arc<UdpSocket>,
    shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: Arc<Mutex<mpsc::Receiver<()>>>,
}

#[derive(Debug, Clone)]
struct ClientSession {
    username: String,
    vpn_ip: String,
    socket_addr: SocketAddr,
    last_activity: u64,
    bytes_sent: u64,
    bytes_received: u64,
}

impl VpnServer {
    #[instrument]

    pub async fn new(bind_addr: String) -> Result<Self> {
        info!("🖥️ Initializing VPN Server on {}", bind_addr);
        tun::enable_ip_forwarding()?;
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let auth_manager = Arc::new(Mutex::new(auth::AuthManager::new()?));

        let mut crypto_manager = crypto::CryptoManager::new();
        let server_public_key = crypto_manager.init_server()?;
        let crypto_manager = Arc::new(Mutex::new(crypto_manager));

        let server_tun = Arc::new(Mutex::new(tun::create_server_tun()?));
        let socket = Arc::new(UdpSocket::bind(&bind_addr).await?);

        Ok(Self {
            auth_manager,
            crypto_manager,
            server_tun,
            client_sessions: Arc::new(Mutex::new(HashMap::new())),
            nat_table: Arc::new(NatTable::new()),
            bind_addr,
            server_public_key,
            socket,
            shutdown_tx,
            shutdown_rx: Arc::new(Mutex::new(shutdown_rx)),
        })
    }

    #[instrument(skip(self))]
    pub async fn start(&self, shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
        info!("🚀 Starting VPN Server...");

        let server = self.clone();
        let tun_task = tokio::spawn(async move { server.start_tun_forwarding().await });

        let server = self.clone();
        let udp_task = tokio::spawn(async move { server.start_udp_handling().await });

        let server = self.clone();
        let cleanup_task = tokio::spawn(async move { server.start_cleanup_task().await });

        tokio::select! {
        _ = tun_task => Ok(()),
        _ = udp_task => Ok(()),
        _ = cleanup_task => Ok(()),
        _ = async {
            shutdown_rx.await.ok();
             info!("🛑 Server shutdown requested");
             Ok::<(), anyhow::Error>(())
            } => Ok(())  
         }
    }

    async fn wait_for_shutdown(&self) {
        let mut rx = self.shutdown_rx.lock().await;
        let _ = rx.recv().await;
    }

    #[instrument(skip(self))]
    async fn start_tun_forwarding(&self) -> Result<()> {
        info!("📡 Starting TUN packet forwarding...");

        loop {
            
            let packet = {
                let tun_clone = self.server_tun.clone();
                match tokio::task::spawn_blocking(move || {
                    let tun = tun_clone.blocking_lock();
                    tun.receive_blocking()
                })
                .await
                {
                    Ok(Ok(data)) => {
                        debug!("📦 Received {} bytes from TUN", data.len());
                        data
                    }
                    Ok(Err(e)) => {
                        error!("Failed to read from TUN: {}", e);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                    Err(e) => {
                        error!("TUN task spawn error: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                }
            };

            
            if let Err(e) = self.process_inbound_packet(&packet).await {
                error!("TUN forwarding error: {}", e);
            }

            
            tokio::select! {
                _ = self.wait_for_shutdown() => break,
                _ = tokio::task::yield_now() => continue,
            }
        }

        Ok(())
    }

    async fn process_inbound_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() < 20 {
            warn!("Dropping malformed packet (length={})", packet.len());
            return Ok(());
        }

        let dest_ip = self.extract_destination_ip(packet);
        let dest_ip_clone = dest_ip.clone();
        let dest_port = self.extract_destination_port(packet);

        if let (Some(dest_ip), dest_port) = (dest_ip, dest_port) {
            if let Some((original_ip, _)) =
                self.nat_table.translate_inbound(&dest_ip, dest_port).await
            {
                if let Some(session) = self.find_session_by_ip(&original_ip).await {
                    let encrypted = {
                        let crypto = self.crypto_manager.lock().await;
                        crypto.encrypt_packet(&session.vpn_ip, packet)?
                    };
                    self.socket.send_to(&encrypted, session.socket_addr).await?;
                    return Ok(());
                }
            }
        }

        if let Some(dest_ip) = dest_ip_clone {
            if let Some(session) = self.find_session_by_ip(&dest_ip).await {
                let encrypted = {
                    let crypto = self.crypto_manager.lock().await;
                    crypto.encrypt_packet(&session.vpn_ip, packet)?
                };
                self.socket.send_to(&encrypted, session.socket_addr).await?;
            }
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn start_udp_handling(&self) -> Result<()> {
        let mut buffer = [0u8; 4096];
        loop {
            tokio::select! {
                result = self.socket.recv_from(&mut buffer) => {
                    match result {
                        Ok((len, addr)) => {
                            if let Err(e) = self.handle_client_message(&buffer[..len], addr).await {
                                error!("Client message error: {}", e);
                            }
                        }
                        Err(e) => error!("UDP recv error: {}", e),
                    }
                }
                _ = self.wait_for_shutdown() => break,
            }
        }
        Ok(())
    }

    async fn handle_client_message(&self, data: &[u8], addr: SocketAddr) -> Result<()> {
        let msg: VpnMessage = serde_json::from_slice(data)?;

        match msg {
            VpnMessage::AuthRequest {
                username,
                password,
                client_public_key,
            } => {
                let response = self
                    .handle_auth(&username, &password, &client_public_key, addr)
                    .await;
                self.socket
                    .send_to(&serde_json::to_vec(&response)?, addr)
                    .await?;
            }
            VpnMessage::VpnData {
                session_token,
                encrypted_payload,
            } => {
                self.handle_vpn_data(&session_token, &encrypted_payload)
                    .await?;
            }
            VpnMessage::Heartbeat { session_token } => {
                self.handle_heartbeat(session_token).await?;
            }
            VpnMessage::Disconnect { session_token } => {
                self.handle_disconnect(session_token).await?;
            }
            _ => warn!("Unsupported message type from {}", addr),
        }
        Ok(())
    }

    async fn handle_auth(
        &self,
        username: &str,
        password: &str,
        client_pubkey: &str,
        addr: SocketAddr,
    ) -> VpnMessage {
        let auth_result = self
            .auth_manager
            .lock()
            .await
            .authenticate(username, password);

        match auth_result {
            Ok(token) => {
                let key_result = self
                    .crypto_manager
                    .lock()
                    .await
                    .handle_client_key_exchange(&token, client_pubkey);

                match key_result {
                    Ok(_) => {
                        let vpn_ip = self.assign_vpn_ip(&token);
                        let session = ClientSession {
                            username: username.to_string(),
                            vpn_ip: vpn_ip.clone(),
                            socket_addr: addr,
                            last_activity: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                            bytes_sent: 0,
                            bytes_received: 0,
                        };
                        self.client_sessions
                            .lock()
                            .await
                            .insert(token.clone(), session);

                        VpnMessage::AuthResponse {
                            success: true,
                            session_token: Some(token),
                            server_public_key: Some(self.server_public_key.clone()),
                            vpn_ip: Some(vpn_ip),
                            error: None,
                        }
                    }
                    Err(e) => VpnMessage::AuthResponse {
                        success: false,
                        session_token: None,
                        server_public_key: None,
                        vpn_ip: None,
                        error: Some(format!("Key exchange failed: {}", e)),
                    },
                }
            }
            Err(e) => VpnMessage::AuthResponse {
                success: false,
                session_token: None,
                server_public_key: None,
                vpn_ip: None,
                error: Some(format!("Authentication failed: {}", e)),
            },
        }
    }

    fn assign_vpn_ip(&self, token: &str) -> String {
        format!("10.8.0.{}", (token.len() % 250) + 3)
    }

    
    #[instrument(skip(self, encrypted_payload))]
    async fn handle_vpn_data(&self, session_token: &str, encrypted_payload: &[u8]) -> Result<()> {
        info!("📦 Processing VPN data from session: {}", session_token);

        
        let packet = {
            let crypto_manager = self.crypto_manager.lock().await;
            match crypto_manager.decrypt_packet(session_token, encrypted_payload) {
                Ok(packet) => {
                    info!("🔓 Successfully decrypted packet: {} bytes", packet.len());
                    packet
                }
                Err(e) => {
                    error!("❌ Decryption failed: {}", e);
                    return Err(anyhow!("Decryption failed: {}", e));
                }
            }
        };

        
        if packet.len() < 20 || (packet[0] >> 4) != 4 {
            warn!(
                "⚠️ Invalid IP packet (len: {}, version: {})",
                packet.len(),
                packet[0] >> 4
            );
            return Ok(());
        }

        
        let src_ip = format!(
            "{}.{}.{}.{}",
            packet[12], packet[13], packet[14], packet[15]
        );
        let dest_ip = format!(
            "{}.{}.{}.{}",
            packet[16], packet[17], packet[18], packet[19]
        );
        info!(
            "🎯 Decrypted packet: {} -> {} ({} bytes)",
            src_ip,
            dest_ip,
            packet.len()
        );

        
        {
            let mut sessions = self.client_sessions.lock().await;
            if let Some(session) = sessions.get_mut(session_token) {
                session.last_activity = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                info!("✅ Updated activity for session: {}", session.username);
            }
        }

        
        let tun = self.server_tun.lock().await;
        match tun.send_packet(&packet) {
            Ok(_) => {
                info!("✅ Successfully forwarded packet to TUN interface");
            }
            Err(e) => {
                error!("❌ Failed to send packet to TUN: {}", e);
                return Err(anyhow!("TUN write failed: {}", e));
            }
        }

        Ok(())
    }

    
    async fn process_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.len() < 20 {
            return Ok(());
        }

        let (src_ip, dest_ip) = (
            self.extract_source_ip(packet),
            self.extract_destination_ip(packet),
        );

        match (src_ip.clone(), dest_ip.clone()) {
            
            (Some(src_ip), Some(dest_ip)) if dest_ip.starts_with("10.8.0.") => {
                if let Some(session) = self.find_session_by_ip(&dest_ip).await {
                    let encrypted = self
                        .crypto_manager
                        .lock()
                        .await
                        .encrypt_packet(&session.vpn_ip, packet)?;
                    self.socket.send_to(&encrypted, session.socket_addr).await?;
                }
            }

            
            (Some(src_ip), _) if src_ip.starts_with("10.8.0.") => {
                let src_port = self.extract_source_port(packet);
                let (trans_ip, trans_port) =
                    self.nat_table.translate_outbound(&src_ip, src_port).await;

                let mut mod_packet = packet.to_vec();
                mod_packet[12..16].copy_from_slice(&[10, 8, 0, 1]); 
                mod_packet[20..22].copy_from_slice(&trans_port.to_be_bytes()); 

                self.server_tun.lock().await.send_packet(&mod_packet)?;
            }

            
            (_, Some(dest_ip)) if dest_ip == "10.8.0.1" => {
                let dest_port = self.extract_destination_port(packet);
                if let Some((original_ip, original_port)) =
                    self.nat_table.translate_inbound(&dest_ip, dest_port).await
                {
                    if let Some(session) = self.find_session_by_ip(&original_ip).await {
                        let mut mod_packet = packet.to_vec();
                        mod_packet[16..20].copy_from_slice(
                            &original_ip
                                .split('.')
                                .map(|s| s.parse().unwrap())
                                .collect::<Vec<u8>>(),
                        );
                        mod_packet[22..24].copy_from_slice(&original_port.to_be_bytes());

                        let encrypted = self
                            .crypto_manager
                            .lock()
                            .await
                            .encrypt_packet(&session.vpn_ip, &mod_packet)?;
                        self.socket.send_to(&encrypted, session.socket_addr).await?;
                    }
                }
            }

            
            (Some(src_ip), Some(dest_ip)) if dest_ip.starts_with("192.168.") => {
                warn!("Allowing local network traffic to: {}", dest_ip);
                self.server_tun.lock().await.send_packet(packet)?;
            }

            _ => warn!(
                "Dropping unrouteable packet from {} to {}",
                src_ip.unwrap_or("unknown".into()),
                dest_ip.unwrap_or("unknown".into())
            ),
        }
        Ok(())
    }

    async fn handle_heartbeat(&self, token: String) -> Result<()> {
        if let Some(session) = self.client_sessions.lock().await.get_mut(&token) {
            session.last_activity = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            debug!("Heartbeat from {}", session.username);
        }
        Ok(())
    }

    async fn handle_disconnect(&self, token: String) -> Result<()> {
        if let Some(session) = self.client_sessions.lock().await.remove(&token) {
            info!("Disconnected {} ({})", session.username, session.vpn_ip);
            self.auth_manager.lock().await.logout(&token)?;
            self.crypto_manager.lock().await.remove_cipher(&token);
        }
        Ok(())
    }
    pub async fn get_tun_name(&self) -> String {
        let tun = self.server_tun.lock().await;
        tun.get_name().to_string()
    }

    async fn start_cleanup_task(&self) -> Result<()> {
        let mut interval = interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                    let timeout = config::SESSION_TIMEOUT_HOURS * 3600;

                    let expired: Vec<_> = self.client_sessions.lock().await
                        .iter()
                        .filter(|(_, s)| now - s.last_activity > timeout)
                        .map(|(t, _)| t.clone())
                        .collect();

                    for token in expired {
                        self.handle_disconnect(token).await?;
                    }

                    self.nat_table.cleanup_expired().await;
                }
                _ = self.wait_for_shutdown() => break,
            }
        }
        Ok(())
    }
    pub async fn shutdown(&self) -> Result<()> {
        info!("🛑 Initiating server shutdown...");
        self.shutdown_tx.send(()).await?;

        
        tokio::time::sleep(Duration::from_secs(1)).await;
        Ok(())
    }

    fn extract_source_ip(&self, packet: &[u8]) -> Option<String> {
        (packet.len() >= 16).then(|| {
            format!(
                "{}.{}.{}.{}",
                packet[12], packet[13], packet[14], packet[15]
            )
        })
    }

    fn extract_destination_ip(&self, packet: &[u8]) -> Option<String> {
        (packet.len() >= 20).then(|| {
            format!(
                "{}.{}.{}.{}",
                packet[16], packet[17], packet[18], packet[19]
            )
        })
    }

    fn extract_source_port(&self, packet: &[u8]) -> u16 {
        if packet.len() >= 22 {
            u16::from_be_bytes([packet[20], packet[21]])
        } else {
            0
        }
    }

    fn extract_destination_port(&self, packet: &[u8]) -> u16 {
        if packet.len() >= 24 {
            u16::from_be_bytes([packet[22], packet[23]])
        } else {
            0
        }
    }

    async fn find_session_by_ip(&self, ip: &str) -> Option<ClientSession> {
        self.client_sessions
            .lock()
            .await
            .values()
            .find(|s| s.vpn_ip == ip)
            .cloned()
    }
}

impl Clone for VpnServer {
    fn clone(&self) -> Self {
        Self {
            auth_manager: self.auth_manager.clone(),
            crypto_manager: self.crypto_manager.clone(),
            server_tun: self.server_tun.clone(),
            client_sessions: self.client_sessions.clone(),
            nat_table: self.nat_table.clone(),
            bind_addr: self.bind_addr.clone(),
            server_public_key: self.server_public_key.clone(),
            socket: self.socket.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
            shutdown_rx: self.shutdown_rx.clone(),
        }
    }
}


pub struct VpnClient {
    crypto_manager: Arc<Mutex<crypto::CryptoManager>>,
    client_tun: Arc<Mutex<tun::TunInterface>>,
    session_token: Option<String>,
    server_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: Arc<Mutex<mpsc::Receiver<()>>>,
    auth_manager: Arc<Mutex<auth::AuthManager>>,
    vpn_ip: String,
}
impl VpnClient {
    
    #[instrument(skip(password))]
    pub async fn new(server_addr: String, username: String, password: String) -> Result<Self> {
        info!("💻 Initializing Krypton VPN Client -> {}", server_addr);

        let crypto_manager = Arc::new(Mutex::new(crypto::CryptoManager::new()));
        let client_tun = tun::create_client_tun()?;
        info!("✅ Client TUN interface created");

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(&server_addr).await?;

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let mut client = Self {
            crypto_manager,
            client_tun: Arc::new(Mutex::new(client_tun)), 
            session_token: Some(String::new()),           
            server_addr: server_addr.parse()?,            
            socket: Arc::new(socket),                     
            shutdown_tx,                                  
            auth_manager: Arc::new(Mutex::new(auth::AuthManager::new()?)),
            vpn_ip: String::new(),
            shutdown_rx: Arc::new(Mutex::new(shutdown_rx)),
        };

        
        client.authenticate(&username, &password).await?;

        
        let tun_name = {
            let tun = client.client_tun.lock().await;
            tun.get_name().to_string()
        };

        if let Err(e) = tun::setup_vpn_routing(&tun_name, "10.8.0.1") {
            warn!("⚠️ Could not setup VPN routing: {}", e);
            info!("💡 You may need to run as Administrator for full VPN routing");
        } else {
            info!("✅ VPN routing configured - traffic will go through VPN!");
        }

        Ok(client)
    }

    #[instrument(skip(self))]
    pub async fn start(&self, shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
        info!("🚀 Starting Krypton VPN Client...");
        info!("🔗 Connected to server: {}", self.server_addr);

        
        let tun_task = self.start_tun_forwarding();
        let udp_task = self.start_udp_handling();
        let heartbeat_task = self.start_heartbeat();

        info!("📨 Starting UDP message handling...");
        info!("📡 Starting TUN packet forwarding...");
        info!("💓 Starting heartbeat...");

        
        tokio::select! {
            result = tun_task => {
                error!("TUN forwarding task ended: {:?}", result);
                result
            }
            result = udp_task => {
                error!("UDP handling task ended: {:?}", result);
                result
            }
            result = heartbeat_task => {
                error!("Heartbeat task ended: {:?}", result);
                result
            }
            _ = async {
                shutdown_rx.await.ok();
                info!("🛑 Client shutdown requested");
                Ok::<(), anyhow::Error>(())
            } => Ok(())
        }
    }
    pub async fn get_tun_name(&self) -> String {
        let tun = self.client_tun.lock().await;
        tun.get_name().to_string()
    }
    
    async fn authenticate(&mut self, username: &str, password: &str) -> Result<()> {
        info!("🔐 Authenticating with server...");

        let mut crypto_manager = self.crypto_manager.lock().await;
        let (client_public_key, _) = crypto_manager.init_client_key_exchange("temp_session")?;

        let request = VpnMessage::AuthRequest {
            username: username.to_string(),
            password: password.to_string(),
            client_public_key: client_public_key,
        };

        let response = self.send_and_receive(&request).await?;

        match response {
            VpnMessage::AuthResponse {
                success: true,
                session_token,
                vpn_ip,
                server_public_key,
                ..
            } => {
                let token = session_token.ok_or_else(|| anyhow!("No session token received"))?;
                let _server_key =
                    server_public_key.ok_or_else(|| anyhow!("No server public key received"))?;

                crypto_manager.complete_client_key_exchange(&token, password)?;

                self.session_token = Some(token);
                self.vpn_ip = vpn_ip.unwrap_or_default();
                info!("✅ Authentication successful!");
                Ok(())
            }
            VpnMessage::AuthResponse {
                success: false,
                error,
                ..
            } => Err(anyhow!(
                error.unwrap_or_else(|| "Authentication failed".to_string())
            )),
            _ => Err(anyhow!("Unexpected response from server")),
        }
    }

    async fn send_and_receive(&self, msg: &VpnMessage) -> Result<VpnMessage> {
        self.socket.send(&serde_json::to_vec(msg)?).await?;
        let mut buf = [0u8; 4096];
        let len = self.socket.recv(&mut buf).await?;
        Ok(serde_json::from_slice(&buf[..len])?)
    }

    
    #[instrument(skip(self))]
    async fn start_tun_forwarding(&self) -> Result<()> {
        info!("📡 Starting client TUN packet forwarding...");

        loop {
            
            let packet_result = tokio::time::timeout(
                Duration::from_millis(100),
                tokio::task::spawn_blocking({
                    let tun_clone = self.client_tun.clone();
                    move || {
                        let tun = tun_clone.blocking_lock();
                        tun.receive_blocking()
                    }
                }),
            )
            .await;

            match packet_result {
                Ok(Ok(Ok(packet))) => {
                    info!("📦 Client captured outbound packet: {} bytes", packet.len());

                    
                    if packet.len() >= 20 {
                        let dest_ip = format!(
                            "{}.{}.{}.{}",
                            packet[16], packet[17], packet[18], packet[19]
                        );
                        let src_ip = format!(
                            "{}.{}.{}.{}",
                            packet[12], packet[13], packet[14], packet[15]
                        );
                        info!("🎯 Packet: {} -> {}", src_ip, dest_ip);
                    }

                    if let Some(ref session_token) = self.session_token {
                        
                        let encrypted_payload = {
                            let crypto_manager = self.crypto_manager.lock().await;
                            match crypto_manager.encrypt_packet(session_token, &packet) {
                                Ok(encrypted) => encrypted,
                                Err(e) => {
                                    error!("❌ Encryption failed: {}", e);
                                    continue;
                                }
                            }
                        };

                        
                        let message = VpnMessage::VpnData {
                            session_token: session_token.clone(),
                            encrypted_payload,
                        };

                        
                        match serde_json::to_vec(&message) {
                            Ok(message_data) => {
                                if let Err(e) = self.socket.send(&message_data).await {
                                    error!("❌ Failed to send to server: {}", e);
                                } else {
                                    info!(
                                        "✅ Sent encrypted packet to server ({} bytes)",
                                        packet.len()
                                    );
                                }
                            }
                            Err(e) => error!("❌ Failed to serialize message: {}", e),
                        }
                    } else {
                        warn!("⚠️ No session token - dropping packet");
                    }
                }
                Ok(Ok(Err(_))) | Ok(Err(_)) | Err(_) => {
                    
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }

            
            tokio::select! {
                _ = self.wait_for_shutdown() => {
                    info!("📡 Client TUN forwarding shutdown requested");
                    break;
                }
                _ = tokio::task::yield_now() => continue,
            }
        }

        Ok(())
    }

    async fn start_udp_handling(&self) -> Result<()> {
        let mut buf = [0u8; 4096];
        loop {
            tokio::select! {
                result = self.socket.recv_from(&mut buf) => {
                    if let Ok((len, _)) = result {
                        if let Ok(VpnMessage::VpnData { session_token, encrypted_payload }) =
                            serde_json::from_slice::<VpnMessage>(&buf[..len])
                        {
                            if Some(&session_token) == self.session_token.as_ref() {
                                let packet = self.crypto_manager.lock().await
                                    .decrypt_packet(&session_token, &encrypted_payload)?;
                                self.client_tun.lock().await.send_packet(&packet)?;
                            }
                        }
                    }
                }
                _ = self.wait_for_shutdown() => break,
            }
        }
        Ok(())
    }

    async fn start_heartbeat(&self) -> Result<()> {
        let mut interval = interval(Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Some(token) = &self.session_token {
                        let _ = self.send_and_receive(&VpnMessage::Heartbeat {
                            session_token: token.clone(),
                        }).await;
                    }
                }
                _ = self.wait_for_shutdown() => break,
            }
        }
        Ok(())
    }

    async fn wait_for_shutdown(&self) {
        let mut rx = self.shutdown_rx.lock().await;
        let _ = rx.recv().await;
    }

    pub async fn shutdown(&self) -> Result<()> {
        info!("🛑 Starting client shutdown sequence...");
        
        
        if let Some(token) = &self.session_token {
            let _ = self
                .send_and_receive(&VpnMessage::Disconnect {
                    session_token: token.clone(),
                })
                .await;
        }
        
        
        let tun_name = {
            let tun = self.client_tun.lock().await;
            tun.get_name().to_string()
        };
        
        if let Err(e) = tun::cleanup_vpn_routing("10.8.0.1") {
            error!("⚠️ Failed to cleanup VPN routing: {}", e);
        }
        
        
        if let Err(e) = tun::restore_default_routes(&tun_name) {
            error!("⚠️ Failed to restore default routes: {}", e);
        }
        
        
        self.shutdown_tx.send(()).await?;
        
        info!("✅ Client shutdown complete");
        Ok(())
    }
}

impl Clone for VpnClient {
    fn clone(&self) -> Self {
        Self {
            auth_manager: self.auth_manager.clone(),
            crypto_manager: self.crypto_manager.clone(),
            client_tun: self.client_tun.clone(),
            session_token: self.session_token.clone(),
            server_addr: self.server_addr.clone(),
            socket: self.socket.clone(),
            vpn_ip: self.vpn_ip.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
            shutdown_rx: self.shutdown_rx.clone(),
        }
    }
}


pub async fn start_vpn_server(bind_addr: String) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    VpnServer::new(bind_addr).await?.start(shutdown_rx).await}

pub async fn start_vpn_client(
    server_addr: String,
    username: String,
    password: String,
) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    VpnClient::new(server_addr, username, password)
        .await?
        .start(shutdown_rx)
        .await
}

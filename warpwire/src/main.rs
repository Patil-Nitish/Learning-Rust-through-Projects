mod tun;
mod net;
mod config;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

#[derive(Parser)]
#[command(name = "warpwire")]
#[command(about = "A VPN tunnel implementation")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Server {
        #[arg(short, long)]
        listen: String,
    },
    Client {
        #[arg(short, long)]
        peer: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Server { listen } => {
            println!("🔌 Starting WarpWire server on {}", listen);
            
            let tun_name = format!("warpwire_{}", std::process::id());
            let tun_address = config::SERVER_TUN_ADDRESS;
            
            let tun = tun::create_tun(&tun_name, tun_address)?;
            println!("🔌 TUN '{}' up at {}", tun_name, tun_address);
            
            let socket = UdpSocket::bind(&listen).await?;
            println!("✅ Bound UDP socket to {}", listen);
            
            let peer_addr: Arc<RwLock<Option<std::net::SocketAddr>>> = Arc::new(RwLock::new(None));
            
            println!("🔌 WarpWire tunnel is running...");
            
            // TUN to UDP task
            let tun_to_udp = tun.clone();
            let socket_clone = Arc::new(socket);
            let socket_for_send = socket_clone.clone();
            let peer_addr_clone = peer_addr.clone();
            
            tokio::spawn(async move {
                let mut buf = [0u8; 1504];
                loop {
                    buf.fill(0);
                    
                    let n = match tokio::task::spawn_blocking({
                        let tun_clone = tun_to_udp.clone();
                        move || {
                            let tun = tun_clone.lock().unwrap();
                            tun.receive_blocking()
                        }
                    }).await {
                        Ok(Ok(packet)) => {
                            let data = packet.bytes();
                            if data.is_empty() {
                                continue;
                            }
                            
                            let len = std::cmp::min(data.len(), buf.len());
                            buf[..len].copy_from_slice(&data[..len]);
                            
                            if len > 0 && (buf[0] >> 4 == 4 || buf[0] >> 4 == 6) {
                                // Simple packet content print
                                println!("📦 TUN -> UDP: {} bytes, Packet: {:02X?}", len, &buf[..std::cmp::min(len, 32)]);
                                len
                            } else if len > 0 {
                                println!("⚠️  Invalid packet: {:02X?}", &buf[..std::cmp::min(len, 16)]);
                                continue;
                            } else {
                                continue;
                            }
                        },
                        Ok(Err(e)) => {
                            println!("❌ TUN read error: {}", e);
                            continue;
                        },
                        Err(e) => {
                            println!("❌ Task spawn error: {}", e);
                            continue;
                        }
                    };
                    
                    // Server mode - send to client
                    let peer_addr_read = peer_addr_clone.read().await;
                    if let Some(addr) = *peer_addr_read {
                        if let Err(e) = socket_for_send.send_to(&buf[..n], addr).await {
                            eprintln!("❌ UDP send error: {}", e);
                        } else {
                            println!("📤 SERVER: Sent {} bytes to client via UDP", n);
                        }
                    } else {
                        println!("⚠️  SERVER: No client address available, dropping {} bytes", n);
                    }
                }
            });
            
            // UDP to TUN task
            let tun_for_write = tun.clone();
            let socket_for_recv = socket_clone.clone();
            let peer_addr_for_update = peer_addr.clone();
            
            tokio::spawn(async move {
                let mut buf = [0u8; 1504];
                loop {
                    let (n, addr) = match socket_for_recv.recv_from(&mut buf).await {
                        Ok(result) => result,
                        Err(e) => {
                            println!("❌ UDP recv error: {}", e);
                            continue;
                        }
                    };
                    
                    // Update client address
                    let mut peer_addr_write = peer_addr_for_update.write().await;
                    if peer_addr_write.is_none() {
                        println!("📡 Client connected from {}", addr);
                    }
                    *peer_addr_write = Some(addr);
                    drop(peer_addr_write);
                    
                    println!("📥 UDP -> TUN: Received {} bytes from {}", n, addr);
                    
                    // Write to TUN interface
                    match tokio::task::spawn_blocking({
                        let tun_clone = tun_for_write.clone();
                        let data = buf[..n].to_vec();
                        move || {
                            let tun = tun_clone.lock().unwrap();
                            tun.send_packet(&data)
                        }
                    }).await {
                        Ok(Ok(_)) => println!("✅ Wrote {} bytes to TUN interface", n),
                        Ok(Err(e)) => println!("❌ TUN write error: {}", e),
                        Err(e) => println!("❌ Task error: {}", e),
                    }
                }
            });
            
            // Keep the main task alive
            tokio::signal::ctrl_c().await?;
        }
        
        Commands::Client { peer } => {
            println!("📡 Starting WarpWire client, connecting to {}", peer);
            
            let tun_name = format!("warpwire_{}", std::process::id());
            let tun_address = config::CLIENT_TUN_ADDRESS;
            
            let tun = tun::create_tun(&tun_name, tun_address)?;
            println!("🔌 TUN '{}' up at {}", tun_name, tun_address);
            
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            println!("✅ Bound UDP socket to 0.0.0.0:0");
            
            socket.connect(&peer).await?;
            println!("📡 Connected to peer at {}", peer);
            
            println!("🔌 WarpWire tunnel is running...");
            
            // TUN to UDP task
            let tun_to_udp = tun.clone();
            let socket_clone = Arc::new(socket);
            let socket_for_send = socket_clone.clone();
            
            tokio::spawn(async move {
                let mut buf = [0u8; 1504];
                loop {
                    buf.fill(0);
                    
                    let n = match tokio::task::spawn_blocking({
                        let tun_clone = tun_to_udp.clone();
                        move || {
                            let tun = tun_clone.lock().unwrap();
                            tun.receive_blocking()
                        }
                    }).await {
                        Ok(Ok(packet)) => {
                            let data = packet.bytes();
                            if data.is_empty() {
                                continue;
                            }
                            
                            let len = std::cmp::min(data.len(), buf.len());
                            buf[..len].copy_from_slice(&data[..len]);
                            
                            if len > 0 && (buf[0] >> 4 == 4 || buf[0] >> 4 == 6) {
                                // Simple packet content print
                                println!("📦 TUN -> UDP: {} bytes, Packet: {:02X?}", len, &buf[..std::cmp::min(len, 32)]);
                                len
                            } else if len > 0 {
                                println!("⚠️  Invalid packet: {:02X?}", &buf[..std::cmp::min(len, 16)]);
                                continue;
                            } else {
                                continue;
                            }
                        },
                        Ok(Err(e)) => {
                            println!("❌ TUN read error: {}", e);
                            continue;
                        },
                        Err(e) => {
                            println!("❌ Task spawn error: {}", e);
                            continue;
                        }
                    };
                    
                    // Client mode - send to server
                    if let Err(e) = socket_for_send.send(&buf[..n]).await {
                        eprintln!("❌ UDP send error: {}", e);
                    } else {
                        println!("📤 CLIENT: Sent {} bytes to server via UDP", n);
                    }
                }
            });
            
            // UDP to TUN task
            let tun_for_write = tun.clone();
            let socket_for_recv = socket_clone.clone();
            
            tokio::spawn(async move {
                let mut buf = [0u8; 1504];
                loop {
                    let n = match socket_for_recv.recv(&mut buf).await {
                        Ok(n) => n,
                        Err(e) => {
                            println!("❌ UDP recv error: {}", e);
                            continue;
                        }
                    };
                    
                    println!("📥 UDP -> TUN: Received {} bytes from server", n);
                    
                    // Write to TUN interface
                    match tokio::task::spawn_blocking({
                        let tun_clone = tun_for_write.clone();
                        let data = buf[..n].to_vec();
                        move || {
                            let tun = tun_clone.lock().unwrap();
                            tun.send_packet(&data)
                        }
                    }).await {
                        Ok(Ok(_)) => println!("✅ Wrote {} bytes to TUN interface", n),
                        Ok(Err(e)) => println!("❌ TUN write error: {}", e),
                        Err(e) => println!("❌ Task error: {}", e),
                    }
                }
            });
            
            // Keep the main task alive
            tokio::signal::ctrl_c().await?;
        }
    }
    
    Ok(())
}


use tokio::net::UdpSocket;
#[allow(dead_code)]
pub async fn bind_udp_socket(bind_addr: &str) -> std::io::Result<UdpSocket> {
    let socket = UdpSocket::bind(bind_addr).await?;
    println!("✅ Bound UDP socket to {}", bind_addr);
    Ok(socket)
}

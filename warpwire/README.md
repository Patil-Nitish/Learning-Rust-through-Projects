# WarpWire

A VPN tunnel implementation in Rust that creates encrypted network tunnels between peers using TUN interfaces and UDP transport.

## Overview

WarpWire is a lightweight VPN implementation that establishes point-to-point encrypted tunnels between a server and client. It creates virtual network interfaces (TUN devices) and routes IP packets through UDP sockets, demonstrating the fundamentals of VPN technology.

## Features

- **TUN Interface Management**: Creates and configures virtual network interfaces
- **UDP Transport**: Uses UDP for efficient packet transmission
- **Bidirectional Tunneling**: Full duplex communication between peers
- **Server-Client Architecture**: Clear separation of server and client roles
- **Real-time Packet Routing**: Live packet forwarding between TUN and UDP
- **Cross-Platform Support**: Works on Linux and compatible systems
- **Packet Validation**: Verifies IPv4/IPv6 packet integrity

## Prerequisites

- Rust 1.70 or higher
- Cargo
- **Root/Administrator privileges** (required for TUN interface creation)
- TUN/TAP support in kernel (Linux)

### Linux Requirements
```bash
# Ensure TUN module is loaded
sudo modprobe tun

# Verify TUN device exists
ls -l /dev/net/tun
```

## Installation

Navigate to the warpwire directory:

```bash
cd warpwire
```

Build the project:

```bash
cargo build --release
```

## Usage

### Start Server

Run the server (requires root privileges):

```bash
sudo ./target/release/warpwire server --listen 0.0.0.0:9090
```

The server will:
1. Create a TUN interface (e.g., `warpwire_12345`)
2. Configure it with IP `10.0.0.1/24`
3. Listen for UDP connections on port 9090
4. Wait for client connections

### Connect Client

In another terminal, connect the client:

```bash
sudo ./target/release/warpwire client --peer <server_ip>:9090
```

Replace `<server_ip>` with the actual server IP address.

The client will:
1. Create a TUN interface with IP `10.0.0.2/24`
2. Connect to the server via UDP
3. Establish the tunnel
4. Begin routing packets

## Network Configuration

### Server Configuration
- **TUN Interface**: `warpwire_<pid>` (auto-generated name)
- **IP Address**: `10.0.0.1/24`
- **Listen Address**: Configurable (default: `0.0.0.0:9090`)

### Client Configuration
- **TUN Interface**: `warpwire_<pid>` (auto-generated name)
- **IP Address**: `10.0.0.2/24`
- **Server Address**: Specified via `--peer` flag

## Example Session

### Terminal 1 (Server)
```bash
$ sudo ./target/release/warpwire server --listen 0.0.0.0:9090

🔌 Starting WarpWire server on 0.0.0.0:9090
🔌 TUN 'warpwire_12345' up at 10.0.0.1
✅ Bound UDP socket to 0.0.0.0:9090
🔌 WarpWire tunnel is running...

📡 Client connected from 192.168.1.100:54321
📥 UDP -> TUN: Received 84 bytes from 192.168.1.100:54321
✅ Wrote 84 bytes to TUN interface
```

### Terminal 2 (Client)
```bash
$ sudo ./target/release/warpwire client --peer 192.168.1.1:9090

📡 Starting WarpWire client, connecting to 192.168.1.1:9090
🔌 TUN 'warpwire_12346' up at 10.0.0.2
✅ Bound UDP socket to 0.0.0.0:0
📡 Connected to peer at 192.168.1.1:9090
🔌 WarpWire tunnel is running...

📦 TUN -> UDP: 84 bytes, Packet: [45, 00, 00, 54, ...]
📤 CLIENT: Sent 84 bytes to server via UDP
```

## Testing the Tunnel

Once both server and client are running:

### From Client
```bash
# Ping the server through the tunnel
ping 10.0.0.1
```

### From Server
```bash
# Ping the client through the tunnel
ping 10.0.0.2
```

### Advanced Testing
```bash
# Test with traceroute
traceroute 10.0.0.1

# Test with netcat
# Server side:
nc -l 10.0.0.1 8080

# Client side:
echo "Hello WarpWire" | nc 10.0.0.1 8080
```

## Architecture

### Components

1. **TUN Module** (`tun.rs`)
   - TUN interface creation
   - IP address configuration
   - Packet reading and writing

2. **Network Module** (`net.rs`)
   - UDP socket management
   - Packet routing logic

3. **Config Module** (`config.rs`)
   - Network configuration constants
   - IP address definitions

4. **Main Module** (`main.rs`)
   - CLI interface
   - Server/client logic
   - Packet forwarding loops

### Packet Flow

**Server Side:**
```
TUN Interface (10.0.0.1) 
    ↓ read packet
[Packet Processing]
    ↓ send via UDP
Client Socket
```

**Client Side:**
```
TUN Interface (10.0.0.2)
    ↓ read packet
[Packet Processing]
    ↓ send via UDP
Server Socket
```

## Project Structure

```
warpwire/
├── src/
│   ├── main.rs      # Main application and CLI
│   ├── tun.rs       # TUN interface management
│   ├── net.rs       # Network utilities
│   └── config.rs    # Configuration constants
├── Cargo.toml       # Dependencies
└── README.md        # This file
```

## Technical Details

### TUN Interface
- Layer 3 (Network layer) virtual interface
- Handles IP packets
- Created per-process with unique name
- Requires root privileges

### UDP Transport
- Connectionless protocol
- Low overhead
- Suitable for VPN tunneling
- Stateless operation

### Packet Validation
```rust
// Checks if packet is valid IPv4 or IPv6
if buf[0] >> 4 == 4 || buf[0] >> 4 == 6 {
    // Valid IP packet
}
```

## Dependencies

- `tokio` - Asynchronous runtime
- `anyhow` - Error handling
- `clap` - Command-line parsing
- TUN/TAP library for interface management

## Troubleshooting

### Permission Denied
```bash
# Run with sudo
sudo ./target/release/warpwire server --listen 0.0.0.0:9090
```

### TUN Device Not Found
```bash
# Load TUN kernel module
sudo modprobe tun

# Verify
lsmod | grep tun
```

### Connection Issues

**Firewall:**
```bash
# Allow UDP port 9090
sudo ufw allow 9090/udp  # Ubuntu/Debian
sudo firewall-cmd --add-port=9090/udp  # Fedora/RHEL
```

**Routing:**
```bash
# Check routing table
ip route show

# Add route if needed
sudo ip route add 10.0.0.0/24 dev warpwire_12345
```

### No Packets Being Forwarded

**Check TUN Interface:**
```bash
# List interfaces
ip addr show

# Check if TUN interface is up
ip link show warpwire_12345
```

**Check UDP Socket:**
```bash
# Verify server is listening
sudo netstat -ulnp | grep 9090
```

## Security Considerations

⚠️ **Important Notes:**

1. **No Encryption**: This implementation does NOT encrypt traffic
2. **Educational Purpose**: Designed for learning, not production use
3. **Add Encryption**: Consider using TLS or custom encryption for real use
4. **Access Control**: No authentication mechanism
5. **Network Security**: Only use on trusted networks

## Performance

### Throughput
- Depends on system resources
- Limited by UDP socket performance
- TUN overhead is minimal

### Latency
- Very low additional latency
- Suitable for real-time applications
- UDP provides low-latency transport

## Use Cases

### Learning
- Understand VPN fundamentals
- Study network tunneling
- Learn TUN/TAP interfaces

### Development
- Test network applications
- Create isolated networks
- Prototype VPN features

### Research
- Network protocol research
- Security testing
- Performance analysis

## Extending WarpWire

### Add Encryption
```rust
use aes_gcm::{Aes256Gcm, KeyInit};

// Encrypt packets before sending
let encrypted = cipher.encrypt(nonce, packet)?;
```

### Add Authentication
```rust
// Add authentication token
struct AuthToken {
    username: String,
    token: String,
}
```

### Add Compression
```rust
use flate2::Compression;

// Compress large packets
let compressed = compress_packet(packet, Compression::default())?;
```

### Multiple Clients
```rust
// Track multiple client connections
let clients: HashMap<SocketAddr, ClientInfo> = HashMap::new();
```

## Advanced Configuration

### Custom IP Ranges
Edit `config.rs`:
```rust
pub const SERVER_TUN_ADDRESS: &str = "192.168.100.1";
pub const CLIENT_TUN_ADDRESS: &str = "192.168.100.2";
```

### Custom Ports
```bash
# Use different port
./warpwire server --listen 0.0.0.0:7777
./warpwire client --peer server:7777
```

## Monitoring

### Watch Traffic
```bash
# Monitor TUN interface
sudo tcpdump -i warpwire_12345

# Monitor UDP traffic
sudo tcpdump -i eth0 udp port 9090
```

### Statistics
```bash
# Interface statistics
ip -s link show warpwire_12345

# Bandwidth monitoring
iftop -i warpwire_12345
```

## Future Enhancements

- [ ] Packet encryption (AES-GCM)
- [ ] Authentication system
- [ ] Multiple client support
- [ ] Packet compression
- [ ] Bandwidth limiting
- [ ] Quality of Service (QoS)
- [ ] IPv6 support
- [ ] WebSocket transport option
- [ ] Configuration file support

## Learning Outcomes

This project demonstrates:
- TUN/TAP interface programming
- UDP socket programming
- Asynchronous I/O with Tokio
- Network packet handling
- VPN architecture basics
- System-level programming in Rust

## License

This project is part of the Learning Rust through Projects repository.

## Contributing

Contributions are welcome! Consider adding:
- Encryption layer
- Authentication mechanism
- Support for multiple clients
- Configuration file support
- Better error handling
- Performance optimizations

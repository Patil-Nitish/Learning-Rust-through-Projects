# Krypton

A sophisticated authenticated peer-to-peer VPN with built-in key exchange for Windows and Linux platforms.

## Overview

Krypton is a full-featured VPN implementation that combines secure authentication, cryptographic key exchange, and network tunneling. It creates virtual network interfaces (TUN devices) and routes encrypted traffic between peers, providing a secure communication channel.

## Features

- **Peer-to-Peer Architecture**: Direct connection between client and server
- **User Authentication**: Secure login system with username/password
- **TUN/TAP Interface**: Creates virtual network interfaces for tunneling
- **End-to-End Encryption**: Encrypted packet transmission
- **Admin Management**: Comprehensive admin tools for user management
- **Cross-Platform**: Supports both Windows (WinTUN) and Linux (TUN/TAP)
- **Session Management**: Token-based session handling
- **Status Monitoring**: Built-in diagnostics and status commands

## Prerequisites

- Rust 1.70 or higher
- Cargo
- **Linux**: TUN/TAP kernel module (`/dev/net/tun`)
- **Windows**: WinTUN driver (`wintun.dll`)

### Linux Requirements
```bash
# Ensure TUN module is loaded
sudo modprobe tun

# Verify TUN device exists
ls -l /dev/net/tun
```

### Windows Requirements
Download WinTUN DLL from [WinTUN website](https://www.wintun.net/) and place it in the project directory.

## Installation

Navigate to the krypton directory:

```bash
cd krypton
```

Build the project:

```bash
cargo build --release
```

## Usage

### Register a User

First, create a user account:

```bash
cargo run -- register <username> <password>
```

Example:
```bash
cargo run -- register alice secretpass123
```

### Start the Server

Start the VPN server (requires admin/root privileges):

```bash
# Linux
sudo ./target/release/krypton server --listen 0.0.0.0:9001

# Windows (run as Administrator)
.\target\release\krypton.exe server --listen 0.0.0.0:9001
```

### Connect as Client

Connect to the VPN server:

```bash
# Linux
sudo ./target/release/krypton client --peer 192.168.1.100:9001 --username alice --password secretpass123

# Windows (run as Administrator)
.\target\release\krypton.exe client --peer 192.168.1.100:9001 --username alice --password secretpass123
```

## Commands

### Main Commands

```bash
# Start VPN server
krypton server [OPTIONS]
  -l, --listen <ADDRESS>  Server listen address (default: 0.0.0.0:9001)
  -v, --verbose          Enable verbose logging

# Connect as VPN client
krypton client [OPTIONS]
  -e, --peer <ADDRESS>      Server address to connect to
  -u, --username <USER>     Username for authentication
  -p, --password <PASS>     Password for authentication
  -v, --verbose            Enable verbose logging

# Register new user
krypton register <USERNAME> <PASSWORD>

# Show system status
krypton status

# Test TUN interface creation
krypton test-tun

# Test authentication system
krypton test-auth

# Test cryptographic system
krypton test-crypto
```

### Admin Commands

```bash
# Setup admin account
krypton admin setup

# Change admin password
krypton admin change

# Reset admin password
krypton admin reset

# Show admin status
krypton admin status

# Authenticate as admin
krypton admin auth
```

## Network Configuration

### Server Configuration
- **TUN Interface**: `krypton0` (or auto-generated)
- **Server IP**: `10.10.0.1/24` (default)
- **Listen Port**: `9001` (configurable)

### Client Configuration
- **TUN Interface**: `krypton1` (or auto-generated)
- **Client IP**: `10.10.0.2/24` (default)
- **Server Connection**: Configured via `--peer` flag

## Architecture

### Components

1. **TUN Module** (`tun.rs`)
   - Creates and manages virtual network interfaces
   - Platform-specific implementations for Windows and Linux
   - Handles packet reading and writing

2. **Authentication Module** (`auth.rs`)
   - User registration and login
   - Password hashing and verification
   - Session token generation

3. **Cryptographic Module** (`crypto.rs`)
   - Packet encryption and decryption
   - Key management
   - Cryptographic operations

4. **Protocol Module** (`protocol.rs`)
   - VPN protocol implementation
   - Client-server communication
   - Packet routing

5. **Admin Module** (`admin.rs`)
   - Administrative functions
   - Admin authentication
   - User management

6. **Config Module** (`config.rs`)
   - Configuration management
   - User database handling
   - Settings persistence

## Security Features

### Authentication
- Secure password hashing
- Session-based authentication
- Token-based authorization
- Admin privilege separation

### Encryption
- Packet-level encryption
- Secure key exchange
- Session-specific encryption keys

### Network Security
- Isolated network namespaces
- Controlled routing
- Traffic encryption

## Example Session

### Server Side
```
$ sudo ./target/release/krypton server

🔐 Krypton VPN - Authenticated P2P VPN
🖥️ Starting Krypton VPN Server on 0.0.0.0:9001
✅ TUN interface 'krypton0' created at 10.10.0.1/24
📡 Server listening for connections...
🔗 Client connected: alice (10.10.0.2)
🔐 Secure channel established
📦 Routing traffic for alice
```

### Client Side
```
$ sudo ./target/release/krypton client --peer 192.168.1.100:9001 -u alice -p secret

🔐 Krypton VPN - Authenticated P2P VPN
💻 Starting Krypton VPN Client -> 192.168.1.100:9001
🔐 Authenticating as alice...
✅ Authentication successful
✅ TUN interface 'krypton1' created at 10.10.0.2/24
🔗 Connected to server
🌐 VPN tunnel established
📡 Ready to route traffic
```

## Troubleshooting

### Linux Issues

**Permission Denied**
```bash
# Run with sudo
sudo ./target/release/krypton server
```

**TUN Device Not Found**
```bash
# Load TUN module
sudo modprobe tun

# Check if loaded
lsmod | grep tun
```

### Windows Issues

**WinTUN DLL Missing**
- Download `wintun.dll` from official website
- Place in same directory as executable

**Access Denied**
- Run Command Prompt as Administrator

### Connection Issues

**Client Can't Connect**
- Check firewall rules (allow port 9001)
- Verify server is running
- Check network connectivity

**Authentication Failed**
- Verify username and password
- Ensure user is registered
- Check user database exists

## Status and Diagnostics

```bash
# Check system status
cargo run -- status

# Output:
📊 Krypton VPN Status
==========================================
Version: 1.0.0
Platform: linux
Architecture: x86_64

👤 Admin Status:
Setup Complete: ✅
Admin Config: ✅ Found

🔧 Configuration:
Users Database: cryptlink_users.json
Admin Config: cryptlink_admin.json
TUN Device: ✅ Available
==========================================
```

## Project Structure

```
krypton/
├── src/
│   ├── main.rs      # Main entry point and CLI
│   ├── config.rs    # Configuration management
│   ├── tun.rs       # TUN interface handling
│   ├── auth.rs      # Authentication system
│   ├── crypto.rs    # Cryptographic operations
│   ├── protocol.rs  # VPN protocol implementation
│   └── admin.rs     # Admin functionality
├── Cargo.toml       # Dependencies
└── README.md        # This file
```

## Dependencies

- `tokio` - Asynchronous runtime
- `tracing` - Logging and diagnostics
- `clap` - Command-line parsing
- `anyhow` - Error handling
- Platform-specific TUN crates

## Performance Considerations

- **Throughput**: Depends on encryption overhead and system resources
- **Latency**: Minimal additional latency from encryption
- **CPU Usage**: Encryption/decryption requires CPU resources
- **Memory**: Moderate memory footprint for buffers

## Security Considerations

- **Production Use**: This is an educational implementation
- **Audit Required**: Should be audited before production use
- **Key Management**: Implement proper key rotation
- **Logging**: Be careful with sensitive data in logs

## Future Enhancements

- [ ] NAT traversal support
- [ ] Multiple simultaneous client connections
- [ ] Dynamic IP assignment
- [ ] Advanced routing configurations
- [ ] Traffic compression
- [ ] Quality of Service (QoS) features
- [ ] Web-based admin interface

## License

This project is part of the Learning Rust through Projects repository.

## Contributing

Contributions are welcome! Areas for improvement:
- Additional platform support (macOS)
- Performance optimizations
- Enhanced security features
- Better error handling and diagnostics

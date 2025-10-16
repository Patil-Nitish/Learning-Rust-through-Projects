# PacketSpy

A network packet capture and analysis tool built in Rust for monitoring and analyzing network traffic in real-time.

## Overview

PacketSpy is a command-line packet sniffer that captures and analyzes network traffic on selected network interfaces. It provides detailed information about IP packets, transport protocols, and network statistics with a colorful terminal interface.

## Features

- **Device Selection**: Choose from available network interfaces
- **Packet Capture**: Real-time packet sniffing with libpcap
- **Protocol Analysis**: Identifies IPv4, IPv6, TCP, UDP, ICMP packets
- **Detailed Information**: Shows source/destination addresses and ports
- **Statistics**: Comprehensive packet statistics summary
- **Configurable Duration**: Set custom capture time periods
- **Colorful Output**: Easy-to-read colored terminal display
- **Promiscuous Mode**: Capture all packets on the network segment

## Prerequisites

- Rust 1.70 or higher
- Cargo
- **libpcap** (Linux/macOS) or **WinPcap/Npcap** (Windows)
- **Administrator/Root privileges** for packet capture

### Installing Dependencies

**Linux (Ubuntu/Debian)**
```bash
sudo apt-get install libpcap-dev
```

**Linux (Fedora/RHEL)**
```bash
sudo dnf install libpcap-devel
```

**macOS**
```bash
brew install libpcap
```

**Windows**
- Install [Npcap](https://npcap.com/) or [WinPcap](https://www.winpcap.org/)

## Installation

Navigate to the packetspy directory:

```bash
cd packetspy
```

Build the project:

```bash
cargo build --release
```

## Usage

Run PacketSpy with administrator/root privileges:

**Linux/macOS**
```bash
sudo ./target/release/packetspy
```

**Windows** (Run Command Prompt as Administrator)
```bash
.\target\release\packetspy.exe
```

Or using cargo:
```bash
sudo cargo run
```

### Interactive Steps

1. **Select Network Interface**: Choose from the list of available devices
2. **Set Duration**: Enter capture duration in milliseconds
3. **View Packets**: Watch real-time packet information
4. **View Summary**: See comprehensive statistics at the end

## Example Session

```
📡 PacketSpy – Device Scanner
1. eth0 (Some("Ethernet adapter"))
2. wlan0 (Some("Wireless adapter"))
3. lo (Some("Loopback"))
Select a device number: 1

🧪 Opening device: eth0
Please enter duration in milliseconds: 5000

📡 Capturing packets for 5000 milliseconds...

📦 Packet captured: 66 bytes
🌐 IPv4: 192.168.1.100 -> 8.8.8.8 
🚚 UDP: 53251 -> 53

📦 Packet captured: 1514 bytes
🌐 IPv4: 192.168.1.100 -> 142.250.185.78 
🚚 TCP: 49832 -> 443

📊 Capture Summary
────────────────────────────────
📦 Total Packets:       127
🌐 IPv4 Packets:        120
🌍 IPv6 Packets:        5
🔁 TCP Packets:         95
📨 UDP Packets:         30
📢 ICMPv4 Packets:      2
📢 ICMPv6 Packets:      0
❗ Malformed Packets:   0
────────────────────────────

📥 Press Enter to exit...
```

## Packet Types Analyzed

### Network Layer (IP)
- **IPv4**: Internet Protocol version 4
- **IPv6**: Internet Protocol version 6

### Transport Layer
- **TCP**: Transmission Control Protocol (connections, web traffic, etc.)
- **UDP**: User Datagram Protocol (DNS, streaming, etc.)
- **ICMPv4**: Internet Control Message Protocol v4 (ping, traceroute)
- **ICMPv6**: Internet Control Message Protocol v6

## Information Captured

### For Each Packet
- Packet size in bytes
- Source and destination IP addresses
- Protocol type (TCP/UDP/ICMP)
- Source and destination ports (for TCP/UDP)
- ICMP message type (for ICMP packets)

### Summary Statistics
- Total packets captured
- Breakdown by protocol type
- Malformed packet count

## Project Structure

```
packetspy/
├── src/
│   └── main.rs      # Main application and packet analysis
├── Cargo.toml       # Dependencies
└── README.md        # This file
```

## Dependencies

- `pcap` - Packet capture library
- `etherparse` - Network packet parsing
- `colored` - Terminal color output

## Use Cases

### Network Monitoring
Monitor network traffic to understand what your system is communicating.

### Security Analysis
Identify suspicious network activity or unauthorized connections.

### Protocol Learning
Learn about network protocols by seeing real traffic.

### Troubleshooting
Debug network connectivity issues by examining packet flows.

### Performance Analysis
Identify bandwidth usage and network bottlenecks.

## Common Interfaces

- **eth0/en0**: Primary Ethernet adapter
- **wlan0/wlp**: Wireless network adapter  
- **lo**: Loopback interface (localhost traffic)
- **docker0**: Docker bridge network
- **tun0/tap0**: VPN interfaces

## Capture Modes

### Promiscuous Mode
PacketSpy enables promiscuous mode by default, allowing capture of:
- Packets destined for your machine
- Broadcast packets
- Multicast packets
- All packets on the network segment (on non-switched networks)

## Security and Legal Considerations

⚠️ **Important Warnings:**

1. **Legal**: Capturing network traffic may be illegal in some jurisdictions without proper authorization
2. **Privacy**: Be aware of privacy laws when analyzing network traffic
3. **Authorization**: Only capture traffic on networks you own or have permission to monitor
4. **Corporate Networks**: Using packet sniffers on company networks may violate policies
5. **Sensitive Data**: Captured packets may contain sensitive information

## Permissions

### Linux/macOS
Packet capture requires root privileges:
```bash
# Run with sudo
sudo ./target/release/packetspy

# Or add capabilities (Linux only)
sudo setcap cap_net_raw,cap_net_admin=eip ./target/release/packetspy
```

### Windows
Must run as Administrator:
1. Right-click Command Prompt
2. Select "Run as Administrator"
3. Navigate to project directory
4. Run the executable

## Troubleshooting

### "No suitable device found"
- Run with administrator/root privileges
- Check if network interfaces are available
- Install libpcap/Npcap

### "Permission denied"
- Linux/macOS: Use `sudo`
- Windows: Run as Administrator

### "Unable to open device"
- Device may be in use by another application
- Try a different network interface
- Restart the network interface

### "No packets captured"
- Check if interface is active and has traffic
- Try a different interface
- Increase capture duration

## Advanced Usage

### Filtering Packets
Modify the code to add BPF (Berkeley Packet Filter) filters:

```rust
capture.filter("tcp port 80 or tcp port 443", true)?;  // HTTP/HTTPS only
capture.filter("host 8.8.8.8", true)?;                 // Specific host
capture.filter("icmp", true)?;                         // ICMP only
```

### Saving Packets
Add functionality to save packets to PCAP file:

```rust
let mut savefile = capture.savefile("capture.pcap")?;
```

## Performance Tips

1. **Shorter Durations**: Start with short capture durations
2. **Specific Interfaces**: Select the most relevant interface
3. **Filters**: Use BPF filters to reduce packet volume
4. **Buffer Size**: Increase buffer size for high-traffic networks

## Statistics Interpretation

### High TCP Count
- Normal for web browsing and most applications
- Indicates connection-oriented traffic

### High UDP Count
- Common for DNS, video streaming, gaming
- Connectionless protocol traffic

### ICMP Packets
- Network diagnostics (ping, traceroute)
- Network error messages

### Malformed Packets
- Corrupted data
- Unsupported protocols
- Potential security issues

## Learning Resources

Understanding packet capture helps with:
- Network protocol learning
- Security analysis skills
- System administration
- Network troubleshooting
- Application debugging

## Future Enhancements

- [ ] Packet filtering by protocol
- [ ] Save captures to PCAP files
- [ ] Deep packet inspection
- [ ] Protocol-specific analysis
- [ ] Real-time bandwidth monitoring
- [ ] Packet replay capabilities
- [ ] Web-based GUI
- [ ] Export to various formats

## License

This project is part of the Learning Rust through Projects repository.

## Contributing

Contributions are welcome! Consider adding:
- Additional protocol support
- Packet filtering options
- Export functionality
- GUI interface
- Real-time visualization

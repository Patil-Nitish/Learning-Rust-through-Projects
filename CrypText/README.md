# CrypText

A secure, encrypted TCP chat server built with Rust featuring end-to-end encryption using X25519 key exchange and AES-256-GCM encryption.

## Overview

CrypText is an asynchronous TCP server application that enables secure, encrypted communication between a server and client. It implements modern cryptographic protocols to ensure message confidentiality and integrity.

## Features

- **End-to-End Encryption**: Uses X25519 Diffie-Hellman key exchange for secure key agreement
- **AES-256-GCM Encryption**: Military-grade encryption for message confidentiality and authenticity
- **Asynchronous I/O**: Built with Tokio for high-performance async networking
- **Real-time Chat**: Interactive bidirectional messaging between server and client
- **Connection Management**: Graceful disconnection handling and cleanup

## Prerequisites

- Rust 1.70 or higher
- Cargo

## Installation

Clone the repository and navigate to the CrypText directory:

```bash
cd CrypText
```

Build the project:

```bash
cargo build --release
```

## Usage

### Starting the Server

Run the server (listens on `127.0.0.1:8080` by default):

```bash
cargo run
```

The server will:
1. Start listening for connections
2. Perform key exchange with the connecting client
3. Establish an encrypted channel
4. Begin accepting encrypted messages

### Interacting with the Server

Once connected, the server will:
- Display received messages from the client
- Prompt you to reply
- Allow you to type `/exit` to end the session

### Commands

- `/exit` - End the chat session from the server side
- `DISCONNECT` - Command recognized when client disconnects

## Technical Details

### Cryptographic Components

- **Key Exchange**: X25519 elliptic curve Diffie-Hellman
- **Encryption**: AES-256-GCM (Galois/Counter Mode)
- **Encoding**: Base64 for key transmission

### Security Features

1. **Perfect Forward Secrecy**: Each session uses ephemeral key pairs
2. **Authenticated Encryption**: AES-GCM provides both confidentiality and authenticity
3. **Secure Key Derivation**: Shared secrets derived using X25519 ECDH

## Project Structure

```
CrypText/
├── src/
│   ├── main.rs      # Server implementation
│   ├── lib.rs       # Cryptographic functions
│   └── bin/         # Client binary (if present)
├── Cargo.toml       # Project dependencies
└── README.md        # This file
```

## Dependencies

- `tokio` - Asynchronous runtime
- `aes-gcm` - AES-GCM encryption
- `x25519-dalek` - X25519 key exchange
- `base64` - Base64 encoding
- `anyhow` - Error handling

## Example Session

```
🔐 Cryptext server running on 127.0.0.1:8080
🔗 New connection from 127.0.0.1:54321
🔐 Secure channel established with 127.0.0.1:54321

📥 127.0.0.1:54321: Hello, server!
💬 Reply to 127.0.0.1:54321: Hello, client!
```

## Security Considerations

- This is an educational project for learning Rust and cryptography
- The server accepts only one connection at a time
- Keys are generated per session and not persisted
- For production use, consider additional security measures like certificate pinning and rate limiting

## License

This project is part of the Learning Rust through Projects repository.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

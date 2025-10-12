<div align="center">

# 🦀 Learning Rust Through Projects

![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)
![Status](https://img.shields.io/badge/status-Active-success?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)
![Projects](https://img.shields.io/badge/projects-14-orange?style=for-the-badge)

**A hands-on journey through Rust programming, from basics to advanced systems programming**

[Getting Started](#-getting-started) • [Projects](#-projects) • [Technologies](#-technologies-used) • [Contributing](#-contributing)

</div>

---

## 📖 About

This repository contains a curated collection of **14 progressively complex Rust projects** built as part of a structured learning journey. Each project is designed to teach specific Rust concepts while building real-world, practical applications.

### 🎯 Learning Objectives

- **Master Rust fundamentals** through hands-on coding
- **Build confidence** with incremental complexity
- **Explore systems programming** including networking, cryptography, and security
- **Develop production-ready skills** with real-world project patterns
- **Learn by doing** - from simple CLI tools to complex networked applications

---

## 📑 Table of Contents

- [About](#-about)
- [Getting Started](#-getting-started)
- [Projects](#-projects)
  - [Beginner Projects](#beginner-projects-1-5)
  - [Intermediate Projects](#intermediate-projects-6-10)
  - [Advanced Projects](#advanced-projects-11-14)
- [Technologies Used](#-technologies-used)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [License](#-license)
- [Contact](#-contact)

---

## 🚀 Getting Started

### Prerequisites

- **Rust** (latest stable version recommended)
  - Install via [rustup](https://rustup.rs/): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Cargo** (comes with Rust)
- **Git** for cloning the repository

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Patil-Nitish/Learning-Rust-through-Projects.git
   cd Learning-Rust-through-Projects
   ```

2. **Navigate to any project**
   ```bash
   cd project-name
   ```

3. **Build and run**
   ```bash
   cargo build --release
   cargo run
   ```

### Quick Start Example

```bash
# Try the guessing game (beginner project)
cd guessing_game
cargo run

# Or try the password strength checker
cd password_prophet
cargo run
```

---

## 📚 Projects

### Beginner Projects (1-5)

Perfect for understanding Rust basics, syntax, and standard library usage.

| # | Project | Description | Key Concepts |
|---|---------|-------------|--------------|
| **01** | [`guessing_game`](./guessing_game) | Classic number guessing game - Rust's traditional first project | Variables, loops, pattern matching, user input |
| **02** | [`Temperature_converter`](./Temperature_converter) | Convert between Celsius and Fahrenheit with validation | Functions, type conversion, error handling |
| **03** | [`Task_Manager`](./Task_Manager) | Command-line todo list with persistent storage | Structs, file I/O, CRUD operations |
| **04** | [`word_frequency_counter`](./word_frequency_counter) | Analyze text files and count word occurrences | HashMaps, iterators, text processing |
| **05** | [`file_hasher`](./file_hasher) | Calculate and compare cryptographic file hashes (MD5, SHA-256) | File handling, cryptographic hashing, hex encoding |

### Intermediate Projects (6-10)

Building on fundamentals with more complex logic and external dependencies.

| # | Project | Description | Key Concepts |
|---|---------|-------------|--------------|
| **06** | [`password_prophet`](./password_prophet) | Password strength evaluator with witty AI-style feedback | String validation, pattern matching, randomization |
| **07** | [`UrlSniper`](./UrlSniper) | URL validator that detects suspicious or malformed links | Regex, URL parsing, security patterns |
| **08** | [`MetaSpy`](./MetaSpy) | Extract and inspect metadata from files and URLs | Metadata extraction, HTTP requests, data parsing |
| **09** | [`CrypText`](./CrypText) | **Real-time encrypted chat** with E2E encryption (X25519 + AES-256-GCM) | Async networking, cryptography, key exchange |
| **10** | [`passvault`](./passvault) | Secure password manager with master password protection | Encryption/decryption, secure storage, JSON serialization |

### Advanced Projects (11-14)

Systems programming, networking, and advanced cryptography implementations.

| # | Project | Description | Key Concepts |
|---|---------|-------------|--------------|
| **11** | [`packetspy`](./packetspy) | Network packet analyzer and monitoring tool | Raw sockets, packet parsing, network protocols |
| **12** | [`warpwire`](./warpwire) | VPN tunnel implementation with secure connections | TUN/TAP interfaces, IP routing, tunneling |
| **13** | [`authwall`](./authwall) | Complete authentication system with role-based admin management | User management, Argon2 hashing, access control |
| **14** | [`krypton`](./krypton) | **Production-grade authenticated P2P VPN** (Windows & Linux) | Full VPN stack, P2P networking, cross-platform development |

---

## 🛠️ Technologies Used

This repository demonstrates proficiency with various Rust libraries and technologies:

### Core Rust
- **Standard Library**: Comprehensive use of `std` for I/O, collections, and system APIs
- **Cargo**: Dependency management and build system
- **Error Handling**: `Result`, `Option`, custom error types with `anyhow`

### Networking & Async
- **tokio**: Async runtime for concurrent applications
- **TUN/TAP**: Virtual network interfaces for VPN projects
- **Sockets**: Raw socket programming for packet analysis

### Cryptography
- **aes-gcm**: Authenticated encryption (AES-256-GCM)
- **x25519-dalek**: Elliptic curve key exchange (X25519)
- **argon2**: Password hashing with modern KDF
- **sha2**: Cryptographic hash functions
- **ring**: High-performance cryptographic operations

### Serialization & Data
- **serde**: Serialization framework
- **serde_json**: JSON support
- **base64**: Binary-to-text encoding

### CLI & User Interface
- **clap**: Command-line argument parsing
- **rpassword**: Secure password input

### Platform-Specific
- **wintun**: Windows TUN driver interface
- **nix**: Unix/Linux system calls
- **libc**: Low-level C library bindings

---

## 🗂️ Project Structure

Each project follows Rust's standard cargo structure:

```
project-name/
├── Cargo.toml          # Dependencies and project metadata
├── src/
│   ├── main.rs         # Entry point
│   └── ...             # Additional modules (for larger projects)
└── README.md           # Project-specific documentation (where applicable)
```

### Design Philosophy

1. **Self-contained**: Each project is independent and runnable
2. **Progressive complexity**: Projects build on previously learned concepts
3. **Real-world applications**: Focus on practical, usable software
4. **Clean code**: Emphasis on idiomatic Rust and best practices
5. **Documentation**: Code comments explain key concepts and decisions

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! This is a learning project, so feel free to:

- 🐛 Report bugs or issues
- 💡 Suggest improvements or optimizations
- 📖 Improve documentation
- ✨ Add new example projects

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 👤 Contact

**Nitish Patil**

- GitHub: [@Patil-Nitish](https://github.com/Patil-Nitish)
- Repository: [Learning-Rust-through-Projects](https://github.com/Patil-Nitish/Learning-Rust-through-Projects)

---

## 🌟 Acknowledgments

- **The Rust Community** for excellent documentation and resources
- **The Rust Book** for foundational knowledge
- **Rustlings** for inspiring hands-on learning
- All contributors and learners who explore this repository

---

<div align="center">

**⭐ If you find this helpful, please consider giving it a star! ⭐**

Made with ❤️ and 🦀 by [Nitish Patil](https://github.com/Patil-Nitish)

</div>

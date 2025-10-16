# PassVault

A secure command-line password manager built in Rust with encryption for storing and managing your passwords safely.

## Overview

PassVault is a terminal-based password manager that securely stores website credentials with strong encryption. It uses a master password to encrypt and decrypt your stored passwords, ensuring your sensitive data remains protected.

## Features

- **Encrypted Storage**: All passwords are encrypted using a master password
- **Secure Input**: Hidden password entry for security
- **Simple Commands**: Easy-to-use command interface
- **Multiple Entries**: Store unlimited website credentials
- **Master Password Protection**: Single master password controls access
- **Local Storage**: Data stored locally on your machine

## Prerequisites

- Rust 1.70 or higher
- Cargo

## Installation

Navigate to the passvault directory:

```bash
cd passvault
```

Build the project:

```bash
cargo build --release
```

## Usage

Run PassVault:

```bash
cargo run
```

Or use the compiled binary:

```bash
./target/release/passvault
```

## First Time Setup

On first run:
1. You'll be prompted to create a master password
2. This password encrypts all your stored data
3. **Important**: Remember this password - it cannot be recovered!

## Commands

### Main Menu
```
🔐 Welcome to PassVault!
Enter master password: ********

📜 Commands: add | get | list | exit
> 
```

### Add Entry
Store a new password:
```
> add
Website: github.com
Username: myusername
Password: ********
✅ Entry saved successfully!
```

### Get Entry
Retrieve a stored password:
```
> get
Website: github.com
🔑 Credentials for github.com
Username: myusername
Password: mypassword123
```

### List Entries
View all stored websites:
```
> list
📋 Stored websites:
  - github.com
  - gmail.com
  - facebook.com
```

### Exit
Close PassVault:
```
> exit
👋 Goodbye!
```

## Example Session

```bash
$ cargo run

🔐 Welcome to PassVault!
Enter master password: ********

📜 Commands: add | get | list | exit
> add
Website: github.com
Username: johndoe
Password: ********
✅ Entry saved successfully!

📜 Commands: add | get | list | exit
> list
📋 Stored websites:
  - github.com

📜 Commands: add | get | list | exit
> get
Website: github.com
🔑 Credentials for github.com
Username: johndoe
Password: supersecretpass123

📜 Commands: add | get | list | exit
> exit
👋 Goodbye!
```

## Project Structure

```
passvault/
├── src/
│   ├── main.rs      # Application entry point
│   ├── cli.rs       # Command-line interface
│   ├── vault.rs     # Vault management and storage
│   └── crypto.rs    # Encryption/decryption logic
├── Cargo.toml       # Dependencies
└── README.md        # This file
```

## Security Features

### Encryption
- Strong encryption algorithm for password storage
- Master password never stored in plaintext
- Each entry is individually encrypted

### Password Entry
- Uses `rpassword` crate for secure, hidden password input
- Passwords never displayed on screen during entry

### Local Storage
- Data stored locally (not in cloud)
- You control your data
- No network transmission of passwords

## Data Storage

PassVault stores encrypted data in a local file. The exact location depends on your operating system:

- **Linux/macOS**: `~/.passvault/` or current directory
- **Windows**: `%USERPROFILE%\.passvault\` or current directory

## Best Practices

### Master Password
- Use a strong, memorable master password
- Don't share your master password
- Consider using a passphrase (e.g., "correct-horse-battery-staple")
- Write it down and store securely if needed

### Website Identifiers
- Use consistent naming (e.g., always use "github.com", not "GitHub")
- Consider including the full URL for specificity

### Regular Backups
- Backup the vault file regularly
- Store backups securely
- Test backup restoration periodically

### Security Hygiene
- Don't use PassVault on untrusted computers
- Lock your computer when stepping away
- Close PassVault when not actively using it

## Important Notes

⚠️ **Critical Information:**

1. **Master Password**: Cannot be recovered if forgotten
2. **Backup**: Regularly backup your vault file
3. **Updates**: Keep PassVault updated for security patches
4. **Trust**: Only use on computers you trust
5. **Shared Systems**: Avoid using on shared or public computers

## Resetting PassVault

If you forget your master password:
- **There is no recovery method**
- You will need to delete the vault file and start over
- All stored passwords will be lost
- This is by design for security

To start fresh:
```bash
# Find and delete the vault file
rm ~/.passvault/vault.enc  # Linux/macOS
# or
del %USERPROFILE%\.passvault\vault.enc  # Windows
```

## Dependencies

- `rpassword` - Secure password input
- Cryptography crates for encryption
- Standard library for file I/O

## Comparison with Other Tools

### PassVault vs Cloud Password Managers
**Advantages:**
- No subscription fees
- Complete data control
- No internet required
- Open source

**Disadvantages:**
- No cross-device sync
- Manual backup required
- CLI only (no GUI)

### PassVault vs Other CLI Managers
- Simple and straightforward
- Good for learning Rust
- Basic feature set
- Educational focus

## Troubleshooting

### "Failed to read password"
- Ensure terminal supports hidden input
- Try running in a different terminal

### "Failed to decrypt vault"
- Wrong master password entered
- Vault file may be corrupted
- Check if vault file exists

### "Permission denied"
- Check file permissions
- Ensure you have write access to storage directory

## Extending PassVault

### Add Password Generation
```rust
use rand::Rng;

fn generate_password(length: usize) -> String {
    // Implementation
}
```

### Add Categories
```rust
struct Entry {
    website: String,
    username: String,
    password: String,
    category: String,  // New field
}
```

### Add Search
```rust
fn search_entries(&self, query: &str) -> Vec<&Entry> {
    // Implementation
}
```

### Add Notes
```rust
struct Entry {
    website: String,
    username: String,
    password: String,
    notes: String,  // Additional information
}
```

## Advanced Features Ideas

- [ ] Password strength indicator
- [ ] Automatic password generation
- [ ] Password history
- [ ] Entry modification/deletion
- [ ] Export to various formats
- [ ] Import from other password managers
- [ ] Two-factor authentication
- [ ] Clipboard integration
- [ ] Auto-clear clipboard after timeout

## Security Audit

For production use, consider:
- Professional security audit
- Formal testing of encryption
- Vulnerability scanning
- Code review by security experts

## Learning Outcomes

This project demonstrates:
- File encryption/decryption
- Secure password handling
- Data serialization
- CLI application design
- Error handling
- User input validation

## License

This project is part of the Learning Rust through Projects repository.

## Contributing

Contributions are welcome! Consider adding:
- Password strength meter
- Entry editing capabilities
- Search functionality
- Export/import features
- Clipboard integration
- Password generator

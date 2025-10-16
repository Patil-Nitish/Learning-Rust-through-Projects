# AuthWall

A secure authentication system with user management, password verification, and admin capabilities built in Rust.

## Overview

AuthWall is a comprehensive command-line authentication system that provides user registration, login functionality, account lockout protection, and administrative features. It demonstrates secure password handling, cryptographic hashing, and user state management.

## Features

- **User Registration**: Create new user accounts with secure password storage
- **User Authentication**: Login with username and password verification
- **Account Lockout**: Automatic account locking after failed login attempts
- **Admin Mode**: Special administrative interface with enhanced privileges
- **Failed Attempt Tracking**: Monitor and reset failed login attempts
- **Interactive & CLI Modes**: Both menu-driven and command-line interfaces
- **User Management**: List users, check status, and reset accounts

## Prerequisites

- Rust 1.70 or higher
- Cargo

## Installation

Navigate to the authwall directory:

```bash
cd authwall
```

Build the project:

```bash
cargo build --release
```

## Usage

### Interactive Mode

Run without arguments to start the interactive menu:

```bash
cargo run
```

### Command-Line Mode

Use specific commands directly:

```bash
# Register a new user
cargo run -- register <username>

# Login as a user
cargo run -- login <username>

# List all users
cargo run -- list

# Check user status
cargo run -- status <username>

# Reset user's failed attempts (requires admin)
cargo run -- reset <username>

# Reset admin password
cargo run -- admin-reset
```

## Interactive Menu

### Main Menu Options

```
🛡️  AuthWall
────────────────────

Options:
1. Register user
2. Login
3. List users
4. User status
5. Exit
```

### Admin Mode

Access admin mode by logging in with username `root`. Admin mode provides additional capabilities:

```
🔧 Admin Mode
────────────────────

Admin Options:
1. Register user
2. Login
3. List users
4. User status
5. 🔧 Reset attempts
6. 🔄 Reset admin password
7. Exit admin mode
```

## Security Features

### Password Security
- Passwords are hashed using cryptographic algorithms
- No plaintext password storage
- Secure password input (hidden from terminal display)

### Account Lockout
- Accounts lock after 3 failed login attempts
- Locked accounts show 🔒 status
- Admin can reset failed attempts to unlock accounts

### Admin Protection
- Admin authentication required for sensitive operations
- Admin credentials stored separately
- Admin password can be reset when needed

## User States

Users are displayed with status indicators:

- ✅ **Active** - No failed attempts
- ⚠️ **Warning** - Has failed login attempts (1-2)
- 🔒 **Locked** - Account locked (3+ failed attempts)

## Project Structure

```
authwall/
├── src/
│   ├── main.rs           # Main application and CLI
│   ├── user.rs          # User data structures
│   ├── userdb.rs        # User database management
│   ├── crypto.rs        # Cryptographic operations
│   ├── auth.rs          # Authentication logic
│   ├── password_input.rs # Secure password input
│   └── admin.rs         # Admin functionality
├── Cargo.toml           # Project dependencies
└── README.md            # This file
```

## Example Session

```bash
$ cargo run

🛡️  AuthWall
────────────────────

Options:
1. Register user
2. Login
3. List users
4. User status
5. Exit

Enter choice (1-5): 1
Enter username: alice
Enter password: ********
✅ User 'alice' registered successfully

Options:
1. Register user
2. Login
3. List users
4. User status
5. Exit

Enter choice (1-5): 2
Enter username: alice
Enter password: ********
✅ Login successful
🎫 Token: 550e8400-e29b-41d4-a716-446655440000

Enter choice (1-5): 3
👥 Users (1)
────────────────────────────────────────
 1. ✅ alice (0)
```

## Dependencies

- `clap` - Command-line argument parsing
- `uuid` - Session token generation
- Additional crypto and I/O crates

## Data Persistence

AuthWall stores user data locally. The exact storage mechanism is implemented in the `userdb` module.

## Administrative Tasks

### Resetting a Locked Account

If a user is locked out:

1. Access admin mode by logging in as `root`
2. Select "Reset attempts" option
3. Enter the username to unlock
4. The user's failed attempt counter is reset to 0

### Changing Admin Password

If you forget the admin password:

1. Run `cargo run -- admin-reset`
2. Follow the prompts to set a new admin password

## Security Best Practices

When using AuthWall:

1. **Strong Passwords**: Encourage users to use strong passwords
2. **Regular Monitoring**: Review the user list regularly for suspicious activity
3. **Admin Access**: Limit admin access to trusted personnel
4. **Secure Storage**: Ensure the user database file is properly secured
5. **Backup**: Regularly backup user database

## Limitations

- Single-machine deployment
- No network-based authentication
- Basic password complexity requirements
- Limited to terminal-based interaction

## Future Enhancements

- [ ] Password complexity requirements
- [ ] Password expiration policies
- [ ] Two-factor authentication (2FA)
- [ ] Audit logging of authentication events
- [ ] Role-based access control (RBAC)
- [ ] Session management and timeout
- [ ] Account recovery mechanisms
- [ ] Password history to prevent reuse

## Learning Outcomes

This project demonstrates:
- User authentication systems
- Password hashing and verification
- State management and persistence
- CLI application design
- Security best practices in Rust

## License

This project is part of the Learning Rust through Projects repository.

## Contributing

Contributions are welcome! Consider adding:
- Enhanced password strength requirements
- Multi-factor authentication
- Audit logging
- API server mode for network authentication

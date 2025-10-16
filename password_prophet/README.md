# Password Prophet

A sassy terminal-based password strength analyzer that judges your passwords with brutal honesty and AI-powered roasts.

## Overview

Password Prophet is an entertaining yet educational tool that evaluates password strength. It checks passwords against common password databases and security criteria, then delivers its verdict with personality and humor through "AI-powered" roasting.

## Features

- **Password Strength Evaluation**: Analyzes passwords against multiple security criteria
- **Common Password Detection**: Checks against 100,000+ most-used passwords
- **Threat Level Assessment**: Color-coded security ratings
- **Entertaining Roasts**: Random, personality-filled feedback messages
- **Educational**: Teaches good password practices through humor
- **Privacy-Focused**: Passwords never leave your machine

## Prerequisites

- Rust 1.70 or higher
- Cargo
- Password database file: `100k-most-used-passwords-NCSC.txt`

## Installation

Navigate to the password_prophet directory:

```bash
cd password_prophet
```

Ensure the password database file is present:
- File: `100k-most-used-passwords-NCSC.txt`
- Contains list of common passwords (one per line)
- Can be obtained from NCSC (National Cyber Security Centre)

Build the project:

```bash
cargo build --release
```

## Usage

Run Password Prophet:

```bash
cargo run
```

Enter a password when prompted (input is visible - use test passwords only!):

```
🔐 Welcome to Password Prophet – Terminal Judgment AI
Enter your password:
MyP@ssw0rd123

🧪 Evaluation Complete:
☢ Threat Level: 🟢 GREEN – Solid. Could survive a day on the darknet.
```

## Threat Levels

### ☠ CRIMSON (Score: 0-1)
**Critical** - Extremely weak password
- Too short (< 8 characters)
- All lowercase or uppercase
- No numbers or special characters
- Found in common password database

**Example Roasts:**
- "Even your fridge could crack this."
- "I've seen stronger passwords in toddlers' diaries."
- "Your password was in the 2012 Adobe leak."

### ⚠ YELLOW (Score: 2-3)
**Warning** - Moderate password
- Minimum length met
- Some variety in characters
- May lack special characters or numbers
- Not in common database but not strong

**Example Roasts:**
- "It's like a security blanket, but with holes."
- "Better than '123456'… barely."
- "A small gust of brute force could break this."

### 🟢 GREEN (Score: 4)
**Good** - Strong password
- Good length (12+ characters)
- Mix of character types
- Includes numbers and special characters
- Not in common database

**Example Roasts:**
- "Strong-ish. I'll allow it."
- "Solid. Could survive a day on the darknet."
- "You didn't disappoint. Rare."

### 🧠 STEALTH BLACK (Score: 5)
**Excellent** - Elite password
- Excellent length
- Full character variety
- Complex composition
- Unpredictable pattern

**Example Roasts:**
- "Teach me, sensei. I kneel."
- "Even quantum computers flinch at this."
- "You are the final boss of password strength."
- "This password could bench press a truck."

## Evaluation Criteria

Password Prophet scores based on multiple factors:

| Criterion | Score | Description |
|-----------|-------|-------------|
| Length ≥ 8 chars | +1 | Basic minimum length |
| Length ≥ 12 chars | +1 | Recommended length |
| Contains numbers | +1 | Has digits 0-9 |
| Contains special chars | +1 | Has symbols (!@#$, etc.) |
| Mixed case | +1 | Both upper and lowercase |
| In common database | -1 | Found in known passwords |

**Maximum Score:** 5 (Elite)  
**Minimum Score:** 0 (Catastrophic)

## Example Sessions

### Weak Password
```
🔐 Welcome to Password Prophet – Terminal Judgment AI
Enter your password:
password

🧪 Evaluation Complete:
☢ Threat Level: ☠ CRIMSON – This one screams: 'Please hack me.'
```

### Strong Password
```
🔐 Welcome to Password Prophet – Terminal Judgment AI
Enter your password:
My$3cur3P@ssw0rd!2024

🧪 Evaluation Complete:
☢ Threat Level: 🧠 STEALTH BLACK – This password is so strong, it could survive a nuclear blast.
```

## Project Structure

```
password_prophet/
├── src/
│   └── main.rs                        # Main application logic
├── 100k-most-used-passwords-NCSC.txt  # Common passwords database
├── Cargo.toml                         # Dependencies
└── README.md                          # This file
```

## Dependencies

- `rand` - Random roast selection

## Password Database

The `100k-most-used-passwords-NCSC.txt` file contains:
- 100,000 most commonly used passwords
- Compiled by NCSC (UK National Cyber Security Centre)
- Used to identify weak, commonly-used passwords
- One password per line

## Educational Value

Password Prophet teaches:
1. **Length Matters**: Longer passwords are exponentially harder to crack
2. **Complexity Helps**: Different character types increase entropy
3. **Avoid Common Passwords**: Many people use predictable passwords
4. **Mix It Up**: Combine uppercase, lowercase, numbers, and symbols

## Password Tips

### Create Strong Passwords

✅ **DO:**
- Use 12+ characters
- Mix uppercase and lowercase
- Include numbers and special characters
- Use unique passwords for each site
- Consider passphrases: "Correct-Horse-Battery-Staple!"

❌ **DON'T:**
- Use dictionary words alone
- Use personal information (birthdays, names)
- Reuse passwords across sites
- Use simple patterns (abc123, qwerty)
- Share passwords with anyone

### Passphrase Strategy
```
Good: MyD0g!sN@medB0b&H3sBlack
Better: Correct-Horse-Battery-Staple-42!
Best: Random: aK9$mL2#pQ7@rN4!vB8
```

## Security Note

⚠️ **Important:** 
- Passwords you type ARE VISIBLE on screen
- Only test with practice passwords
- Never enter real passwords for testing
- Use a password manager for real passwords

## Extending the Tool

### Add More Criteria
```rust
// Check for sequential characters
if has_sequential_chars(password) {
    score -= 1;
}

// Check for repeated characters
if has_repeated_chars(password, 3) {
    score -= 1;
}
```

### Add Password Suggestions
```rust
fn suggest_improvement(password: &str) -> String {
    // Provide specific recommendations
}
```

### Make It Secure
```rust
use rpassword::read_password;

// Hide password input
let password = read_password()?;
```

## Entertaining Roasts

Password Prophet includes over 25 unique roast messages across all threat levels, making each evaluation entertaining and memorable. The random selection ensures users don't see the same message repeatedly.

## Use Cases

1. **Password Awareness Training**: Teach users about password security
2. **Security Workshops**: Demonstrate password strength concepts
3. **Personal Education**: Learn what makes passwords strong
4. **Team Building**: Fun security education activity
5. **CTF Events**: Password strength challenges

## Limitations

- Input is visible (not suitable for real passwords)
- Simple heuristic-based scoring
- No password manager integration
- English language only

## Future Enhancements

- [ ] Hide password input for real use
- [ ] Integration with Have I Been Pwned API
- [ ] Password generation suggestions
- [ ] Entropy calculation
- [ ] Pattern detection (keyboard walks, etc.)
- [ ] Multi-language support
- [ ] GUI version
- [ ] Browser extension

## Real-World Password Tools

For actual password management, consider:
- **1Password** - Comprehensive password manager
- **Bitwarden** - Open-source password manager
- **KeePassXC** - Local password database
- **Have I Been Pwned** - Check if passwords are compromised

## License

This project is part of the Learning Rust through Projects repository.

## Contributing

Contributions are welcome! Consider adding:
- More evaluation criteria
- Additional roast messages
- Password generation capabilities
- Integration with breach databases
- Secure input mode
- Multi-language support

## Credits

- Password database: NCSC (National Cyber Security Centre)
- Inspired by password strength meters and security awareness tools

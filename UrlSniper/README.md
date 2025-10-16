# UrlSniper

A powerful terminal-based suspicious URL analyzer built in Rust that helps detect potentially malicious or phishing URLs.

## Overview

UrlSniper is a security tool that analyzes URLs for suspicious characteristics. It evaluates URLs against multiple security heuristics including suspicious TLDs, keywords, IP addresses, and missing HTTPS to provide a threat assessment.

## Features

- **Multi-URL Analysis**: Analyze single URLs, batch input, or read from a file
- **Threat Level Assessment**: Color-coded threat levels (Safe, Low Risk, Suspicious, Malicious)
- **Multiple Detection Methods**:
  - Suspicious TLD detection
  - Suspicious keyword matching
  - IP address usage detection
  - HTTPS verification
  - URL length analysis
- **Colorful Output**: Easy-to-read colored terminal output
- **Flexible Input**: Single URL, batch mode, or file-based input

## Prerequisites

- Rust 1.70 or higher
- Cargo

## Installation

Navigate to the UrlSniper directory:

```bash
cd UrlSniper
```

Build the project:

```bash
cargo build --release
```

## Usage

### Single URL Analysis

Run without arguments for interactive single URL mode:

```bash
cargo run
```

Then enter a URL when prompted.

### Batch Mode

Analyze multiple URLs at once:

```bash
cargo run batch
```

Then enter URLs (one per line or space-separated), type `END` when finished.

### File Mode

Analyze URLs from a file named `urls.txt`:

```bash
cargo run file
```

The `urls.txt` file should contain one URL per line.

## Data Files

UrlSniper requires two data files in a `data/` directory:

1. **suspicious_tlds.txt** - List of suspicious top-level domains
2. **suspicious_keywords.txt** - List of suspicious keywords

These files should contain one entry per line.

## Threat Levels

### 🟢 Safe (Score: 0)
URL appears to be legitimate with no suspicious indicators.

### 🟡 Low Risk (Score: 1)
URL has one minor suspicious characteristic.

### ⚠ Suspicious (Score: 2-3)
URL has multiple concerning characteristics and should be approached with caution.

### ☠ Malicious (Score: 4+)
URL exhibits multiple high-risk indicators and is likely malicious.

## Detection Criteria

| Issue | Score Impact | Description |
|-------|--------------|-------------|
| Missing HTTPS | +1 | URL uses HTTP instead of HTTPS |
| Suspicious TLD | +1 | Uses a TLD commonly associated with phishing |
| Suspicious Keywords | +1 | Contains keywords often used in phishing |
| IP Address | +1 | Uses IP address instead of domain name |
| Long URL | +1 | URL exceeds 100 characters |

## Example Output

```
🔫 Welcome to URLSniper – Suspicious URL Analyzer

🔍 Analyzing 3 URLs...

🔗 URL: http://192.168.1.1/admin
☢ Threat Level: ⚠ Suspicious - Suspicious
⚠ Issue: Missing HTTPS
⚠ Issue: Uses IP address instead of domain
----------------------------------------------

🔗 URL: https://www.google.com
☢ Threat Level: 🟢 Safe - Safe
----------------------------------------------

🔗 URL: http://paypal-verify.xyz/login.php
☢ Threat Level: ☠ Malicious - Malicious
⚠ Issue: Missing HTTPS
⚠ Issue: Suspicious TLD found in URL
⚠ Issue: Contains suspicious keyword
----------------------------------------------
```

## Project Structure

```
UrlSniper/
├── src/
│   └── main.rs              # Main application logic
├── data/
│   ├── suspicious_tlds.txt      # Suspicious TLDs database
│   └── suspicious_keywords.txt  # Suspicious keywords database
├── Cargo.toml               # Project dependencies
└── README.md                # This file
```

## Dependencies

- `colored` - Terminal color output
- `regex` - Regular expression matching
- `url` - URL parsing and validation

## Use Cases

1. **Email Security**: Verify links before clicking in emails
2. **Security Awareness Training**: Demonstrate phishing URL characteristics
3. **Link Verification**: Check URLs shared on social media
4. **Security Auditing**: Batch analysis of URL lists
5. **Browser Extension Backend**: Backend for a URL checking extension

## Security Considerations

- **False Positives**: Legitimate URLs may be flagged; use judgment
- **False Negatives**: Sophisticated phishing may bypass detection
- **Not a Replacement**: Should complement, not replace, other security measures
- **Educational Tool**: Best used as part of security awareness

## Customization

### Adding Suspicious TLDs
Edit `data/suspicious_tlds.txt` and add one TLD per line:
```
.tk
.ml
.ga
.xyz
```

### Adding Suspicious Keywords
Edit `data/suspicious_keywords.txt` and add keywords:
```
verify
account-suspended
secure-login
paypal
```

## Future Enhancements

- [ ] Domain reputation checking via APIs
- [ ] Machine learning-based URL classification
- [ ] Certificate validation for HTTPS URLs
- [ ] URL redirection chain analysis
- [ ] Integration with threat intelligence feeds
- [ ] Export results to JSON/CSV

## License

This project is part of the Learning Rust through Projects repository.

## Contributing

Contributions are welcome! Consider adding:
- More sophisticated URL analysis algorithms
- API integration for real-time threat intelligence
- Support for more input formats
- Enhanced reporting capabilities

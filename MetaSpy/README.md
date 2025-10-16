# MetaSpy

A command-line tool for analyzing and scanning metadata from files, helping identify privacy and security concerns in file metadata.

## Overview

MetaSpy is a Rust-based utility that extracts and displays metadata from various file types. It helps users understand what information is embedded in their files, which can be crucial for privacy and security auditing.

## Features

- **Metadata Scanning**: Extract and display metadata from files
- **Privacy Analysis**: Identify potentially sensitive information in file metadata
- **Command-Line Interface**: Simple and intuitive CLI powered by clap
- **Sample Files**: Includes sample files for testing functionality

## Prerequisites

- Rust 1.70 or higher
- Cargo

## Installation

Navigate to the MetaSpy directory:

```bash
cd MetaSpy
```

Build the project:

```bash
cargo build --release
```

## Usage

### Basic Scanning

Scan a file to view its metadata:

```bash
cargo run -- scan <file_path>
```

Or using the compiled binary:

```bash
./target/release/MetaSpy scan <file_path>
```

### Examples

Scan a sample file:

```bash
cargo run -- scan samples/example.jpg
```

Scan any file on your system:

```bash
cargo run -- scan /path/to/your/file.pdf
```

## Commands

- `scan <path>` - Scan and display metadata from the specified file

## Project Structure

```
MetaSpy/
├── src/
│   ├── main.rs      # CLI interface and command parsing
│   └── scanner.rs   # Metadata scanning logic
├── samples/         # Sample files for testing
├── Cargo.toml       # Project dependencies
└── README.md        # This file
```

## Supported File Types

MetaSpy can analyze metadata from various file formats including:
- Images (JPEG, PNG, etc.)
- Documents (PDF, DOCX, etc.)
- Audio/Video files
- And more...

## What Metadata Can Reveal

File metadata can contain:
- **Creation and modification dates**
- **Author information**
- **GPS coordinates** (in photos)
- **Camera and device information**
- **Software used to create the file**
- **Edit history**
- **User comments and notes**

## Use Cases

1. **Privacy Auditing**: Check files before sharing to ensure no sensitive metadata is exposed
2. **Security Analysis**: Identify potential information leakage in files
3. **Digital Forensics**: Extract metadata for investigation purposes
4. **File Management**: Organize and categorize files based on metadata

## Dependencies

- `clap` - Command-line argument parsing

## Privacy Tips

After using MetaSpy to identify sensitive metadata:
- Use metadata removal tools before sharing files
- Consider the metadata implications when sharing photos and documents
- Review privacy settings in applications that create files

## Example Output

```
📊 Scanning file: photo.jpg
═══════════════════════════════════
Camera: Canon EOS 5D Mark IV
Date Taken: 2024-01-15 14:30:22
GPS Location: 37.7749° N, 122.4194° W
Software: Adobe Photoshop 2023
═══════════════════════════════════
⚠️  Warning: File contains GPS coordinates
```

## License

This project is part of the Learning Rust through Projects repository.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests to add support for more file types or enhance scanning capabilities.

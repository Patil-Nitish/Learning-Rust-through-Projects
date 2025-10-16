# File Hasher

A fast and efficient command-line tool for generating cryptographic hashes of files using SHA-256, SHA-512, or SHA-1 algorithms.

## Overview

File Hasher is a utility for computing cryptographic hash values of files. It supports multiple hashing algorithms, measures performance, and can save results to a log file for record-keeping and verification purposes.

## Features

- **Multiple Hash Algorithms**: SHA-256, SHA-512, and SHA-1 support
- **Performance Metrics**: Measures and displays hashing time in milliseconds and microseconds
- **Result Logging**: Automatically saves hash results to `hashes.txt`
- **Large File Support**: Handles files of any size
- **Simple Interface**: Easy-to-use command-line interface

## Prerequisites

- Rust 1.70 or higher
- Cargo

## Installation

Navigate to the file_hasher directory:

```bash
cd file_hasher
```

Build the project:

```bash
cargo build --release
```

## Usage

Run the program:

```bash
cargo run
```

Follow the interactive prompts:

1. Choose a hashing algorithm (1-3)
2. Enter the path to the file you want to hash
3. View the hash result and performance metrics

## Hash Algorithms

### 1. SHA-256
- **Output Size**: 256 bits (32 bytes)
- **Use Case**: General-purpose hashing, digital signatures
- **Security**: Highly secure, widely recommended

### 2. SHA-512
- **Output Size**: 512 bits (64 bytes)
- **Use Case**: High-security applications
- **Security**: More secure than SHA-256, slower on 32-bit systems

### 3. SHA-1
- **Output Size**: 160 bits (20 bytes)
- **Use Case**: Legacy systems (not recommended for security)
- **Security**: Deprecated for security purposes, vulnerable to collision attacks

## Example Session

```bash
choose a hashing algorithm:
1. SHA-256
2. SHA-512
3. SHA-1
Enter your choice (1/2/3):
1

enter the file path:
/path/to/document.pdf

Hash SHA-256:a3c2f1d8e9b7c6d5a4e3f2b1c0d9e8f7b6a5c4d3e2f1b0a9c8d7e6f5b4a3c2d1
Time taken: 45 ms (45234 μs)
Hash written to hashes.txt
```

## Output File Format

Results are appended to `hashes.txt` in the following format:

```
filename | algorithm | hash | time_in_ms
```

Example:
```
document.pdf | SHA-256 | a3c2f1d8e9b7c6d5... | 45ms
photo.jpg | SHA-512 | b4d3e2f1c0a9b8c7... | 23ms
archive.zip | SHA-1 | c5d4e3f2b1a0c9d8... | 102ms
```

## Use Cases

### File Integrity Verification
Verify that files haven't been corrupted or tampered with:
```bash
# Hash a file before transfer
cargo run
# Hash the same file after transfer
cargo run
# Compare the hashes
```

### Digital Forensics
Create hash records of files for evidence preservation.

### Duplicate Detection
Identify duplicate files by comparing their hashes.

### Security Auditing
Verify downloaded files against known-good hashes.

### Backup Verification
Ensure backup files match original files.

## Project Structure

```
file_hasher/
├── src/
│   └── main.rs      # Main application with hashing logic
├── Cargo.toml       # Project dependencies
└── README.md        # This file
```

## Dependencies

- `sha1` - SHA-1 hashing algorithm
- `sha2` - SHA-256 and SHA-512 algorithms
- `hex` - Hexadecimal encoding

## Performance Considerations

Hash computation time depends on:
- **File Size**: Larger files take longer to hash
- **Algorithm**: SHA-512 is typically slower than SHA-256
- **Storage Speed**: Faster drives (SSD vs HDD) improve performance
- **System Load**: Other processes can affect performance

### Typical Performance

| File Size | SHA-256 | SHA-512 | SHA-1 |
|-----------|---------|---------|-------|
| 1 MB | ~10 ms | ~12 ms | ~8 ms |
| 100 MB | ~500 ms | ~600 ms | ~400 ms |
| 1 GB | ~5 sec | ~6 sec | ~4 sec |

*(Times are approximate and vary by hardware)*

## Security Recommendations

### For Security Purposes
✅ **Use SHA-256** - Best balance of security and performance  
✅ **Use SHA-512** - Maximum security for critical applications  
❌ **Avoid SHA-1** - Known vulnerabilities, use only for non-security purposes

### For Integrity Checking
- SHA-256 is recommended
- SHA-1 is acceptable if only checking for accidental corruption
- Always use the same algorithm for verification

## Command-Line Enhancement

For a non-interactive version, modify the code to accept arguments:

```bash
./file_hasher --algorithm sha256 --file document.pdf
```

## Verification Example

```bash
# Hash a file
$ cargo run
1
important-file.txt
Hash SHA-256: abc123...
Hash written to hashes.txt

# Later, verify the file hasn't changed
$ cargo run
1
important-file.txt
Hash SHA-256: abc123...

# If hashes match, file is intact
```

## Error Handling

The program handles common errors:
- Invalid algorithm choice
- File not found
- File read errors
- Permission issues

## Learning Outcomes

This project demonstrates:
- File I/O operations in Rust
- Cryptographic hashing
- Performance measurement
- Error handling with `expect`
- Working with external crates
- Writing to files

## License

This project is part of the Learning Rust through Projects repository.

## Contributing

Contributions are welcome! Consider adding:
- Command-line argument support
- Multiple file hashing in batch
- Hash verification mode
- Additional hash algorithms (BLAKE3, MD5)
- Progress bar for large files
- Recursive directory hashing

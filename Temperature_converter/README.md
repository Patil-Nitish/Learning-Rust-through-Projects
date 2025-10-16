# Temperature Converter

A simple Rust program for converting temperatures between Celsius and Fahrenheit.

## Overview

Temperature Converter is a straightforward utility that demonstrates temperature conversion calculations. It converts predefined temperatures between Celsius and Fahrenheit scales, showcasing basic mathematical operations in Rust.

## Features

- **Celsius to Fahrenheit**: Convert temperatures from Celsius to Fahrenheit
- **Fahrenheit to Celsius**: Convert temperatures from Fahrenheit to Celsius
- **Accurate Conversions**: Uses precise mathematical formulas
- **Simple Implementation**: Clean, easy-to-understand code

## Prerequisites

- Rust 1.70 or higher
- Cargo

## Installation

Navigate to the Temperature_converter directory:

```bash
cd Temperature_converter
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

The program will automatically convert the hardcoded example temperatures and display the results.

## Output

```
25 C is 77 F
77 F is 25 C
```

## Conversion Formulas

### Celsius to Fahrenheit
```
F = (C × 9/5) + 32
```

### Fahrenheit to Celsius
```
C = (F - 32) × 5/9
```

## Project Structure

```
Temperature_converter/
├── src/
│   └── main.rs      # Main program with conversion functions
├── Cargo.toml       # Project configuration
├── .gitignore       # Git ignore file
└── README.md        # This file
```

## Code Example

```rust
fn cel_to_far(c: f64) -> f64 {
    (c * 9.0 / 5.0) + 32.0
}

fn far_to_cel(f: f64) -> f64 {
    (f - 32.0) * 5.0 / 9.0
}

fn main() {
    let temp_c = 25.0;
    let temp_f = 77.0;

    let f = cel_to_far(temp_c);
    let c = far_to_cel(temp_f);

    println!("{temp_c} C is {f} F");
    println!("{temp_f} F is {c} C");
}
```

## Customization

To convert different temperatures, modify the values in `main.rs`:

```rust
let temp_c = 25.0;  // Change this value
let temp_f = 77.0;  // Change this value
```

## Enhanced Versions

You can extend this program with:

### Interactive Input
```rust
use std::io;

fn main() {
    println!("Enter temperature in Celsius:");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let celsius: f64 = input.trim().parse().unwrap();
    
    let fahrenheit = cel_to_far(celsius);
    println!("{} C is {} F", celsius, fahrenheit);
}
```

### Menu-Based Converter
Add a menu to choose conversion direction:
1. Celsius to Fahrenheit
2. Fahrenheit to Celsius
3. Exit

### Additional Scales
Add support for:
- Kelvin (K = C + 273.15)
- Rankine (R = F + 459.67)

## Common Temperature Reference Points

| Description | Celsius | Fahrenheit |
|------------|---------|------------|
| Absolute Zero | -273.15°C | -459.67°F |
| Water Freezing | 0°C | 32°F |
| Room Temperature | 20-22°C | 68-72°F |
| Body Temperature | 37°C | 98.6°F |
| Water Boiling | 100°C | 212°F |

## Learning Outcomes

This project demonstrates:
- Basic Rust syntax and functions
- Working with floating-point numbers
- Mathematical operations in Rust
- String interpolation with variables
- Function parameters and return values

## Testing

To verify accuracy, test with known values:
- 0°C should equal 32°F
- 100°C should equal 212°F
- -40°C should equal -40°F (unique intersection point)

## License

This project is part of the Learning Rust through Projects repository.

## Contributing

Contributions are welcome! Consider adding:
- Interactive user input
- Command-line arguments support
- Multiple temperature scales
- Batch conversion from file
- Unit tests for conversion accuracy

# Guessing Game

A classic number guessing game implemented in Rust - a perfect beginner project for learning Rust fundamentals.

## Overview

Guessing Game is an interactive terminal game where the player tries to guess a randomly generated number between 1 and 100. The program provides feedback after each guess, helping players narrow down the correct answer.

## Features

- **Random Number Generation**: Uses the `rand` crate for cryptographically secure random numbers
- **Interactive Gameplay**: Continuous loop until the correct number is guessed
- **Helpful Hints**: Tells you if your guess is too high or too low
- **Input Validation**: Handles invalid input gracefully
- **Victory Message**: Celebrates when you guess correctly

## Prerequisites

- Rust 1.70 or higher
- Cargo

## Installation

Navigate to the guessing_game directory:

```bash
cd guessing_game
```

Build the project:

```bash
cargo build --release
```

## Usage

Run the game:

```bash
cargo run
```

### How to Play

1. The program generates a random number between 1 and 100
2. Enter your guess when prompted
3. Receive feedback: "Too small!", "Too big!", or "You win!"
4. Keep guessing until you find the correct number
5. The game ends when you guess correctly

## Example Game Session

```
Guess the number!
Please input your guess
50
You guessed: 50
Too big!

Please input your guess
25
You guessed: 25
Too small!

Please input your guess
37
You guessed: 37
Too big!

Please input your guess
31
You guessed: 31
You win!
```

## Game Mechanics

### Number Range
- Minimum: 1
- Maximum: 100
- Inclusive range (1 and 100 are possible values)

### Feedback System
- **"Too small!"** - Your guess is lower than the secret number
- **"Too big!"** - Your guess is higher than the secret number
- **"You win!"** - You've guessed the correct number

### Input Handling
- Non-numeric input is automatically skipped
- The game continues until a valid number is guessed
- Empty lines are handled gracefully

## Project Structure

```
guessing_game/
├── src/
│   └── main.rs      # Main game logic
├── Cargo.toml       # Project dependencies
└── README.md        # This file
```

## Code Breakdown

### Random Number Generation
```rust
let _secret_number = rand::thread_rng().gen_range(1..=100);
```

### Input Handling
```rust
let mut guess = String::new();
io::stdin().read_line(&mut guess).expect("Failed to read line");
```

### Number Parsing with Error Handling
```rust
let guess: u32 = match guess.trim().parse() {
    Ok(num) => num,
    Err(_) => continue,
};
```

### Comparison Logic
```rust
match guess.cmp(&_secret_number) {
    Ordering::Less => println!("Too small!"),
    Ordering::Greater => println!("Too big!"),
    Ordering::Equal => {
        println!("You win!");
        break;
    }
}
```

## Dependencies

- `rand` - Random number generation

## Learning Outcomes

This project teaches essential Rust concepts:

1. **Variables and Mutability**: Using `let` and `mut`
2. **Standard Library**: Working with `std::io` and `std::cmp`
3. **External Crates**: Using `rand` crate
4. **Error Handling**: `match` expressions and `Result` type
5. **Loops**: Using `loop` for repetitive tasks
6. **User Input**: Reading from stdin
7. **Type Conversion**: Parsing strings to numbers
8. **Comparison**: Using `Ordering` enum
9. **Pattern Matching**: `match` expressions

## Enhancements

### Add Guess Counter
Track how many attempts it took to win:

```rust
let mut attempts = 0;
// In the game loop:
attempts += 1;
// When they win:
println!("You won in {} attempts!", attempts);
```

### Add Difficulty Levels
Let players choose the range:

```rust
println!("Choose difficulty: 1) Easy (1-50) 2) Medium (1-100) 3) Hard (1-200)");
```

### Add Play Again Feature
Allow playing multiple rounds:

```rust
loop {
    // Game logic here
    println!("Play again? (y/n)");
    // Check response
}
```

### Add High Score System
Track the best (lowest) number of guesses.

## Tips for Players

### Efficient Strategy
Use binary search for optimal performance:
1. Start with 50 (middle of 1-100)
2. Adjust by half the remaining range each time
3. Guaranteed to win in 7 guesses or fewer

### Example Optimal Strategy
```
Range: 1-100, Guess: 50
Range: 51-100, Guess: 75
Range: 51-74, Guess: 62
Range: 51-61, Guess: 56
Range: 51-55, Guess: 53
Range: 51-52, Guess: 51
Found!
```

## Common Issues

### Invalid Input
If you enter non-numeric input, the game will prompt for another guess.

### No Output After Build
Make sure you're running with `cargo run`, not just `cargo build`.

## Testing Ideas

Create unit tests for game functions:
- Test number generation is within range
- Test comparison logic
- Test input parsing

## License

This project is part of the Learning Rust through Projects repository.

## Contributing

Contributions are welcome! Ideas for improvements:
- Add difficulty levels
- Track number of guesses
- Implement hints system
- Add play again functionality
- Create a GUI version
- Add sound effects
- Implement a scoring system

## Acknowledgments

This is a classic beginner project featured in [The Rust Programming Language Book](https://doc.rust-lang.org/book/ch02-00-guessing-game-tutorial.html).

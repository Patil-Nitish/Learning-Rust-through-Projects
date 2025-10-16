# Word Frequency Counter

A simple command-line tool that analyzes text and counts the frequency of each word, built as a beginner-friendly Rust project.

## Overview

Word Frequency Counter is a straightforward text analysis tool that takes a sentence as input, processes it, and displays how many times each word appears. It's an excellent project for learning basic Rust concepts like string manipulation, vectors, and iteration.

## Features

- **Word Counting**: Counts occurrences of each word in input text
- **Case Insensitive**: Treats uppercase and lowercase as the same word
- **Punctuation Handling**: Automatically removes common punctuation marks
- **Simple Output**: Displays word frequencies in a clear format
- **Interactive Input**: User-friendly command-line interface

## Prerequisites

- Rust 1.70 or higher
- Cargo

## Installation

Navigate to the word_frequency_counter directory:

```bash
cd word_frequency_counter
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

Enter a sentence when prompted and press Enter to see the results.

## Example Sessions

### Example 1: Simple Sentence
```bash
Enter a sentence:
The quick brown fox jumps over the lazy dog

Word Frequency List:
the: 2
quick: 1
brown: 1
fox: 1
jumps: 1
over: 1
lazy: 1
dog: 1
```

### Example 2: Repetitive Text
```bash
Enter a sentence:
Hello world! Hello Rust! Hello programming!

Word Frequency List:
hello: 3
world: 1
rust: 1
programming: 1
```

### Example 3: Punctuation Handling
```bash
Enter a sentence:
To be, or not to be? That is the question.

Word Frequency List:
to: 2
be: 2
or: 1
not: 1
that: 1
is: 1
the: 1
question: 1
```

## How It Works

### Algorithm Steps

1. **Input**: Read a sentence from the user
2. **Lowercase Conversion**: Convert all text to lowercase for case-insensitive comparison
3. **Punctuation Removal**: Strip out common punctuation marks (`.`, `,`, `!`, `?`, `:`, `;`)
4. **Tokenization**: Split the text into individual words
5. **Frequency Counting**: Count occurrences of each word
6. **Output**: Display the frequency list

### Code Flow

```rust
Input sentence
    ↓
Convert to lowercase
    ↓
Remove punctuation
    ↓
Split into words
    ↓
Count frequencies
    ↓
Display results
```

## Project Structure

```
word_frequency_counter/
├── src/
│   └── main.rs      # Main application logic
├── Cargo.toml       # Project configuration
└── README.md        # This file
```

## Code Explanation

### Lowercasing and Cleaning
```rust
let input = input
    .to_lowercase()
    .replace(['.',',','!','?',':',':'], " ");
```

### Word Splitting
```rust
let words: Vec<&str> = input.split_whitespace().collect();
```

### Frequency Counting
```rust
let mut freq_list: Vec<(String, usize)> = Vec::new();

for w in words {
    let mut found = false;
    
    for pair in &mut freq_list {
        if pair.0 == w {
            pair.1 += 1;
            found = true;
            break;
        }
    }
    
    if !found {
        freq_list.push((w.to_string(), 1));
    }
}
```

## Use Cases

### Text Analysis
Analyze documents, articles, or books to find most common words.

### SEO Research
Identify keyword frequency in web content.

### Writing Analysis
Understand word usage patterns in your writing.

### Language Learning
Study word frequency in foreign language texts.

### Data Processing
Process logs or text data to extract insights.

## Enhancements

### Sort by Frequency
Display words from most to least frequent:

```rust
freq_list.sort_by(|a, b| b.1.cmp(&a.1));
```

### Use HashMap
More efficient frequency counting:

```rust
use std::collections::HashMap;

let mut freq_map: HashMap<String, usize> = HashMap::new();

for word in words {
    *freq_map.entry(word.to_string()).or_insert(0) += 1;
}
```

### File Input
Read from a file instead of stdin:

```rust
use std::fs;

let contents = fs::read_to_string("input.txt")?;
```

### Exclude Common Words
Filter out stop words (the, a, an, etc.):

```rust
let stop_words = ["the", "a", "an", "and", "or", "but"];

if !stop_words.contains(&word) {
    // Count this word
}
```

### Export Results
Save results to a file:

```rust
use std::fs::File;
use std::io::Write;

let mut file = File::create("frequency.txt")?;
for (word, count) in &freq_list {
    writeln!(file, "{}: {}", word, count)?;
}
```

## Advanced Features

### Command-Line Arguments
```bash
# Analyze a file
./word_frequency_counter input.txt

# Set minimum word length
./word_frequency_counter --min-length 4 input.txt

# Show top N words
./word_frequency_counter --top 10 input.txt
```

### Multiple File Processing
```bash
# Process multiple files
./word_frequency_counter file1.txt file2.txt file3.txt
```

### Output Formats
```bash
# JSON output
./word_frequency_counter --format json input.txt

# CSV output
./word_frequency_counter --format csv input.txt
```

## Optimization

### Current Implementation
- **Time Complexity**: O(n²) - Nested loops
- **Space Complexity**: O(n) - Stores all unique words

### Optimized with HashMap
- **Time Complexity**: O(n) - Single pass
- **Space Complexity**: O(n) - Stores unique words

### Example Optimization
```rust
use std::collections::HashMap;

fn count_words_optimized(text: &str) -> HashMap<String, usize> {
    let mut frequencies = HashMap::new();
    
    for word in text.split_whitespace() {
        *frequencies.entry(word.to_lowercase()).or_insert(0) += 1;
    }
    
    frequencies
}
```

## Learning Outcomes

This project teaches:

1. **String Manipulation**: Working with text in Rust
2. **Collections**: Using vectors to store data
3. **Iteration**: Looping through collections
4. **Pattern Matching**: Finding and counting elements
5. **User Input**: Reading from stdin
6. **Basic Algorithms**: Frequency counting
7. **Data Structures**: Custom tuple structures

## Common Patterns

### Stop Words Removal
```rust
let stop_words = vec!["the", "a", "an", "and", "or", "but", "in", "on", "at"];

let words: Vec<_> = input
    .split_whitespace()
    .filter(|w| !stop_words.contains(w))
    .collect();
```

### Minimum Word Length
```rust
let words: Vec<_> = input
    .split_whitespace()
    .filter(|w| w.len() >= 3)  // Only words with 3+ characters
    .collect();
```

## Testing Ideas

Create unit tests:

```rust
#[test]
fn test_word_frequency() {
    let text = "hello world hello";
    let result = count_words(text);
    
    assert_eq!(result.get("hello"), Some(&2));
    assert_eq!(result.get("world"), Some(&1));
}

#[test]
fn test_case_insensitive() {
    let text = "Hello HELLO hello";
    let result = count_words(text);
    
    assert_eq!(result.get("hello"), Some(&3));
}
```

## Performance Considerations

### Small Texts (< 1000 words)
- Current implementation is fine
- Performance difference negligible

### Large Texts (> 10000 words)
- Consider using HashMap
- Implement streaming for very large files
- Use parallel processing for multiple files

## Real-World Applications

1. **Content Analysis**: Analyze blog posts and articles
2. **SEO Tools**: Keyword density checkers
3. **Academic Research**: Text corpus analysis
4. **Social Media**: Analyze trending topics
5. **Code Analysis**: Count identifier usage in source code

## Future Enhancements

- [ ] File input support
- [ ] Sort by frequency
- [ ] Top N most frequent words
- [ ] Stop words filtering
- [ ] Export to CSV/JSON
- [ ] Graphical visualization
- [ ] Multiple file processing
- [ ] Regular expression support
- [ ] Character encoding support
- [ ] Bigram/Trigram analysis

## License

This project is part of the Learning Rust through Projects repository.

## Contributing

Contributions are welcome! Consider adding:
- HashMap implementation for better performance
- File input/output capabilities
- Command-line argument parsing
- Additional text processing features
- Unit tests
- Documentation improvements

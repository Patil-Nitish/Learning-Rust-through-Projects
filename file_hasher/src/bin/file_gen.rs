use std::fs::File;
use std::io::{Write, BufWriter};

fn main() {
    let file = File::create("bigfile.txt").expect("Failed to create file");
    let mut writer = BufWriter::new(file);

    let line = "This is a line of text used to fill the file for hashing performance test.\n";

    // Repeat the line ~1,250,000 times to get ~100 MB
    for _ in 0..1_250_000 {
        writer.write_all(line.as_bytes()).expect("Write failed");
    }

    println!("✅ Created bigfile.txt (~100 MB)");
}

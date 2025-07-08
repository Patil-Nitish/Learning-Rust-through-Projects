use std::io;
use std::io::Write;
use std::fs::{self, OpenOptions};
use std::time::Instant;
use hex;
use sha2::{Sha256,Sha512,Digest};
use sha1::Sha1;


fn main() {
    let mut choice = String::new();
    println!("choose a hashing algorithm:");
    println!("1. SHA-256");
    println!("2. SHA-512");
    println!("3. SHA-1");
    println!("Enter your choice (1/2/3):");
    io::stdin().read_line(&mut choice).expect("failed to read line");
    let choice = choice.trim();

    let mut file_path =String::new();
    println!("enter the file path:");
    io::stdin().read_line(&mut file_path).expect("invalid file path");
    let file_path = file_path.trim();
    let start = Instant::now();

    let data = fs::read(file_path).expect("failed to read file");
    let algo = match choice{
        "1"=>{
            "SHA-256"
        }
        "2"=>{
            "SHA-512"
        }
        "3"=>{
            "SHA-1"
        }
        _=>{
            panic!("Invalid choice. Please select 1, 2, or 3.");
        }
       
       
    };
    let hash:String = hash_file(&data,algo);

    let duration = start.elapsed();
    println!("Hash {}:{}",algo,hash);
    println!("Time taken: {} ms ({} μs)",
    duration.as_millis(),
    duration.as_micros());

    write_to_file(file_path, algo, &hash, duration.as_millis());
    println!("Hash written to hashes.txt");


}

fn hash_file(d:&Vec<u8>,alg:&str) ->String{
   match alg{
        "SHA-256"=>{
            let result =Sha256::digest(d);
            hex::encode(result)
        }
        "SHA-512"=>{
            let result =Sha512::digest(d);
            hex::encode(result)
        }
        "SHA-1"=>{
            let result=Sha1::digest(d);
            hex::encode(result)
        }
        _ => {
            panic!("Unsupported algorithm: {}", alg);
        }
    }
}

fn write_to_file(filename:&str,algo:&str, hash:&str,duration_ms:u128){
    let line = format!("{} | {} | {} | {}ms\n", 
                      filename, algo, hash, duration_ms);

    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("hashes.txt")
        .expect("Unable to open or create file");

    file.write_all(line.as_bytes()).expect("Unable to write to file");
}

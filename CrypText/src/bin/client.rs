#![allow(warnings)]

use tokio::net::TcpStream;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use std::io::{stdin, stdout, Write};

use aes_gcm::{Aes256Gcm, KeyInit};
use CrypText::{generate_keypair, derive_sharedkey, encrypt_message, decrypt_message};
use x25519_dalek::PublicKey as X25519PublicKey;
use base64::{engine::general_purpose, Engine as _};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let stream = TcpStream::connect("127.0.0.1:8080").await?;
    println!("🧑‍💻 Connected to Cryptext server at 127.0.0.1:8080");

    let (reader, mut writer) = tokio::io::split(stream);
    let mut socket_reader = BufReader::new(reader);

    
    let client_keypair = generate_keypair();
    let client_pub_bytes = client_keypair.public.to_bytes();
    let client_pub_b64 = general_purpose::STANDARD.encode(client_pub_bytes);

    writer.write_all(client_pub_b64.as_bytes()).await?;
    writer.write_all(b"\n").await?;

    let mut server_pub_line = String::new();
    socket_reader.read_line(&mut server_pub_line).await?;
    let server_pub_bytes = general_purpose::STANDARD
        .decode(server_pub_line.trim())
        .expect("Invalid server key");

    let server_pub_key = X25519PublicKey::from(<[u8; 32]>::try_from(server_pub_bytes).unwrap());
    let shared_key = derive_sharedkey(client_keypair.secret, server_pub_key);
    let cipher = Aes256Gcm::new_from_slice(&shared_key).unwrap();

    println!("🔐 Secure channel established with server");

    
    let cipher_clone = cipher.clone();
    let mut socket_reader_clone = socket_reader;
    tokio::spawn(async move {
        let mut incoming_line = String::new();
        loop {
            incoming_line.clear();
            match socket_reader_clone.read_line(&mut incoming_line).await {
                Ok(0) => {
                    println!("\n🔌 Server disconnected.");
                    std::process::exit(0);
                }
                Ok(_) => {
                    let trimmed = incoming_line.trim();
                    if trimmed == "DISCONNECT" {
                        println!("\n👋 Server ended the chat.");
                        std::process::exit(0);
                    }

                    match decrypt_message(&cipher_clone, trimmed) {
                        Some(decrypted_msg) => {
                            println!("\n📥 Server: {}", decrypted_msg);
                            print!("💬 You: ");
                            stdout().flush().unwrap();
                        }
                        None => {
                            eprintln!("\n❌ Failed to decrypt message from server");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("\n❌ Lost connection to server: {e}");
                    std::process::exit(0);
                }
            }
        }
    });

    
    let mut input = String::new();
    loop {
        input.clear();
        print!("💬 You: ");
        stdout().flush().unwrap();
        stdin().read_line(&mut input).unwrap();

        let trimmed = input.trim();
        if trimmed == "/exit" {
            println!("👋 Exiting CrypText...");
            writer.write_all(b"DISCONNECT\n").await.ok();
            break;
        }

        if trimmed.is_empty() {
            continue;
        }

        let encrypted = encrypt_message(&cipher, trimmed);
        writer.write_all((encrypted + "\n").as_bytes()).await?;
    }

    Ok(())
}

#![allow(warnings)]
use tokio::net::TcpListener;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use CrypText::{decrypt_message, encrypt_message, generate_keypair, derive_sharedkey};
use std::io::{stdin, stdout, Write};
use aes_gcm::{Aes256Gcm,KeyInit};
use x25519_dalek::PublicKey as X25519PublicKey;
use base64::{engine::general_purpose, Engine as _};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("🔐 Cryptext server running on 127.0.0.1:8080");

    let (mut socket, addr) = listener.accept().await?;
    println!("🔗 New connection from {}", addr);

    let (reader, mut writer) = socket.split();
    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();

    let server_keypair = generate_keypair();
    let server_public_bytes = server_keypair.public.to_bytes();

    let mut client_public_line = String::new();
    if buf_reader.read_line(&mut client_public_line).await.unwrap() == 0 {
        println!("❌ Failed to read client public key from {}", addr);
        return Ok(());
    }

    let client_public_bytes = match general_purpose::STANDARD.decode(client_public_line.trim()) {
        Ok(bytes) => bytes,
        Err(_) => {
            eprintln!("❌ Invalid public key format from {}", addr);
            return Ok(());
        }
    };

    if client_public_bytes.len() != 32 {
        eprintln!("❌ Invalid public key length from {}", addr);
        return Ok(());
    }

    let client_public_key = X25519PublicKey::from(<[u8; 32]>::try_from(client_public_bytes).unwrap());

    let server_pub_b64 = general_purpose::STANDARD.encode(server_public_bytes);
    writer.write_all(server_pub_b64.as_bytes()).await.unwrap();
    writer.write_all(b"\n").await.unwrap();

    let shared_key = derive_sharedkey(server_keypair.secret, client_public_key);
    let cipher = Aes256Gcm::new_from_slice(&shared_key).unwrap();

    println!("🔐 Secure channel established with {}", addr);

    loop {
        line.clear();
        let bytes_read = buf_reader.read_line(&mut line).await.unwrap();
        if bytes_read == 0 {
            println!("🔌 {} disconnected", addr);
            println!("📴 Shutting down Cryptext server...");
            std::process::exit(0);
        }

        let trimmed = line.trim();

        if trimmed == "DISCONNECT" {
            println!("📴 Client ended the chat.");
            std::process::exit(0);
        }

        match decrypt_message(&cipher, trimmed) {
            Some(decrypted_msg) => {
                println!("\n📥 {}: {}", addr, decrypted_msg);
            }
            None => {
                eprintln!("❌ Failed to decrypt message from {}: Invalid format", addr);
                continue;
            }
        }

        print!("💬 Reply to {}: ", addr);
        stdout().flush().unwrap();

        let mut reply = String::new();
        if stdin().read_line(&mut reply).is_err() {
            println!("⚠️ Failed to read server input. Terminating...");
            break Ok(());
        }

        let trimmed = reply.trim();
        if trimmed == "/exit" {
            println!("👋 You ended the chat.");
            writer.write_all(b"DISCONNECT\n").await.ok();
            std::process::exit(0);
        }

        if trimmed.is_empty() {
            continue;
        }

        let encrypted_reply = encrypt_message(&cipher, trimmed);
        if let Err(e) = writer.write_all((encrypted_reply + "\n").as_bytes()).await {
            eprintln!("❌ Error sending response to {}: {}", addr, e);
            std::process::exit(0);
        }
    }
}

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use password_hash::{SaltString, rand_core::OsRng};



pub fn generate_salt() -> String {
    let mut rng = OsRng;
    SaltString::generate(&mut rng).to_string()
}

pub fn hash_password(password:&str,salt:&str)->String{
    let salt=SaltString::from_b64(salt).expect("Invalid salt format");
    let argon2=Argon2::default();

    let hash=argon2
        .hash_password(password.as_bytes(),&salt)
        .unwrap()
        .to_string();

    hash
}

pub fn verify_password(hash:&str,password:&str,_salt:&str)->bool{
    let parsed_hash=PasswordHash::new(hash).unwrap();
    Argon2::default()
        .verify_password(password.as_bytes(),&parsed_hash)
        .is_ok()
}   
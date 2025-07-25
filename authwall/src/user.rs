use serde::{Serialize,Deserialize};

#[derive(Serialize,Deserialize,Debug)]
pub struct User{
    pub username:String,
    pub password_hash:String,
    pub salt:String,
    pub failed_attempts:u8,
}
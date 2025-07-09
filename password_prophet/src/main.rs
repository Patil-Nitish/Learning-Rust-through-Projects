use rand::seq::SliceRandom;
use rand::thread_rng;
use std::collections::HashSet;
use std::fs;
use std::io;

fn load_common_password() -> HashSet<String> {
    let content = fs::read_to_string("100k-most-used-passwords-NCSC.txt")
        .expect("failed to read the common paswords");

    let mut passwords = HashSet::new();
    for line in content.lines() {
        passwords.insert(line.trim().to_string());
    }

    passwords
}

fn evaluate_password(pass: &str, common: HashSet<String>) -> u8 {
    let mut score:u8 = 0;
    if pass.len() <= 8 {
        score += 1;
    } if pass.len() <= 12 {
        score += 1;
    }  if pass.chars().any(|c| c.is_numeric()) {
        score += 1;
    }  if pass.chars().any(|c| !c.is_alphanumeric()) {
        score += 1;
    } else if pass != pass.to_lowercase() && pass != pass.to_uppercase() {
        score += 1;
    }  if common.contains(pass) {
        score = score.saturating_sub(1);
    }
    score
}

fn get_threat_level(score: u8) -> (&'static str, &'static str) {
    let roast = get_roast(score);
    match score {
        0..=1 => ("☠ CRIMSON", roast),
        2..=3 => ("⚠ YELLOW", roast),
        4 => ("🟢 GREEN", roast),
        5 => ("🧠 STEALTH BLACK", roast),
        _ => ("🌀 UNKNOWN", roast),
    }
}

fn get_roast(score: u8) -> &'static str {
    let weak_roasts = [
        "Even your fridge could crack this.",
        "I’ve seen stronger passwords in toddlers’ diaries.",
        "This one screams: ‘Please hack me.’",
        "Your password was in the 2012 Adobe leak.",
        "This password is like a welcome mat for hackers.",
    ];

    let meh_roasts = [
        "It’s like a security blanket, but with holes.",
        "This password is like a wet paper towel.",
        "You might as well write it on a sticky note.",
        "It’s not the worst, but it’s not great either.",
        "Better than '123456'… barely.",
        "A small gust of brute force could break this.",
        "It’s not bad, just… disappointing.",
    ];

    let good_roasts = [
        "Strong-ish. I’ll allow it.",
        "Solid. Could survive a day on the darknet.",
        "You didn’t disappoint. Rare.",
        "This password is like a sturdy door with a weak lock.",
    ];

    let elite_roasts = [
        "Teach me, sensei. I kneel.",
        "Even quantum computers flinch at this.",
        "You are the final boss of password strength.",
        "This password is like a fortress with a moat.",
        "You could probably sell this password for a fortune.",
        "This password is so strong, it could bench press a truck.",
        "This password is like a diamond in a sea of pebbles.",
        "This password is so strong, it could survive a nuclear blast.",
    ];

    let unknown = ["I’m speechless. That never happens."];

    let mut rng = thread_rng();

    match score {
        0..=1 => weak_roasts.choose(&mut rng).unwrap_or(&weak_roasts[0]),
        2..=3 => meh_roasts.choose(&mut rng).unwrap_or(&meh_roasts[0]),
        4 => good_roasts.choose(&mut rng).unwrap_or(&good_roasts[0]),
        5 => elite_roasts.choose(&mut rng).unwrap_or(&elite_roasts[0]),
        _ => unknown.choose(&mut rng).unwrap_or(&unknown[0]),
    }
}

fn main() {
    println!("🔐 Welcome to Password Prophet – Terminal Judgment AI");
    println!("Enter your password:");

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("failed to read password");

    let password = input.trim();
    if password.is_empty() {
        println!(" Security by silence? That’s not how this works.");
        return;
    }

    let common_passwords = load_common_password();
    let score = evaluate_password(password, common_passwords);

    let (threat_level, level_message) = get_threat_level(score);

    println!("\n🧪 Evaluation Complete:");
    println!("☢ Threat Level: {} – {}", threat_level, level_message);
}

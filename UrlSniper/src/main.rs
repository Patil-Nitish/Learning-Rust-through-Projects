use colored::*;
use regex::Regex;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{self, Write};
use url::Url;

fn load_data_files(path: &str) -> HashSet<String> {
    fs::read_to_string(path)
        .expect(format!("Failed to read file: {}", path).as_str())
        .lines()
        .map(|line| line.trim().to_string().to_lowercase())
        .filter(|line| !line.is_empty())
        .collect()
}

fn get_urls(args: Vec<String>) -> Vec<String> {
    if args.len() > 1 {
        match args[1].as_str() {
            "file" => {
                let content = fs::read_to_string("urls.txt").expect("Failed to read urls.txt");
                return content
                    .lines()
                    .map(|line| line.trim().to_string())
                    .filter(|line| !line.is_empty())
                    .collect();
            }
            "batch" => {
                println!("Enter URLs:(type 'END' to finish)");
                let mut urls = Vec::new();
                loop {
                    let mut line = String::new();
                    io::stdin().read_line(&mut line).unwrap();
                    let trimmed = line.trim();
                    if trimmed == "END" {
                        break;
                    }
                    urls.extend(trimmed.split_whitespace().map(|s| s.to_string()));
                }
                return urls;
            }
            _ => {}
        }
    }
    println!("Enter a single URL:");
    io::stdout().flush().unwrap();
    let mut url = String::new();
    io::stdin().read_line(&mut url).unwrap();
    vec![url.trim().to_string()]
}

fn analyze_url(url: &str, tlds: &HashSet<String>, keywords: &HashSet<String>) -> (u8, Vec<String>) {
    let mut score = 0;
    let mut issues = Vec::new();

    if let Ok(parsed) = Url::parse(url) {
        let domain = parsed.domain().unwrap_or("").to_lowercase();
        let path = parsed.path().to_lowercase();
        let host = parsed.host_str().unwrap_or("").to_lowercase();
        let tld = if let Some(host) = parsed.host_str() {
            host.split('.').last().unwrap_or("").to_lowercase()
        } else {
            "".to_string()
        };

        if !parsed.scheme().starts_with("https") {
            score += 1;
            issues.push("Missing HTTPS".to_string());
        }

        if tlds.iter().any(|tld| url.contains(tld)) {
            score += 1;
            issues.push("Suspicious TLD found in URL".to_string());
        }
        

        if keywords.iter().any(|k| domain.contains(k) || path.contains(k)) {
            score += 1;
            issues.push("Contains suspicious keyword".to_string());
        }

        if let Some(host) = parsed.host_str() {
            if Regex::new(r"^\d{1,3}(\.\d{1,3}){3}$")
                .unwrap()
                .is_match(host)
            {
                score += 1;
                issues.push("Uses IP address instead of domain".to_string());
            }
        }

    } else {
        issues.push("Malformed URL".to_string());
    }

    if url.len() > 100 {
        score += 1;
        issues.push("URL is unusually long".to_string());
    }

   
    (score, issues)
}


fn get_threat(score: u8) -> (&'static str, ColoredString) {
    match score {
        0 => ("🟢 Safe", "Safe".green().bold()),
        1 => ("🟡 Low Risk", "Low Risk".yellow().bold()),
        2..=3 => ("⚠ Suspicious", "Suspicious".truecolor(255, 165, 0).bold()),
        _ => ("☠ Malicious", "Malicious".red().bold()),
    }
}

fn main() {
    println!("\n🔫 Welcome to URLSniper – Suspicious URL Analyzer");

    let tlds = load_data_files("data/suspicious_tlds.txt");
    let keywords = load_data_files("data/suspicious_keywords.txt");

    let args: Vec<String> = env::args().collect();
    let urls = get_urls(args);
    if urls.is_empty() {
        println!("No URLs provided. Exiting.");
        return;
    }
    println!("\n🔍 Analyzing {} URLs...", urls.len());

    for url in urls {
        let (score, issues) = analyze_url(&url, &tlds, &keywords);
        let (label, color) = get_threat(score);
        println!("\n🔗 URL: {}", url);
        println!("☢ Threat Level: {} - {}", label, color);
        for issue in issues {
            println!("⚠ Issue: {}", issue);
        }
        println!("----------------------------------------------");
    }
}

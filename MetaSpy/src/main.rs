use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod scanner;


#[derive(Parser)]
#[command(name = "MetaSpy")]
#[command(about = "Analyze and redact metadata from files", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        path: PathBuf,
    }
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan { path } => scanner::scan(path)
    }
}

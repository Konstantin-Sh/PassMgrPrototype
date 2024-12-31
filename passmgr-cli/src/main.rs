use ciphers::bip39::{Bip39, Bip39Error};
use clap::{Parser, Subcommand};
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "passmgr-cli")]
#[command(about = "Password Manager CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new seed phrase
    GenerateSeed {
        /// Strength in bits (128, 160, 192, 224, or 256)
        #[arg(short, long, default_value_t = 256)]
        strength: u32,
    },
    /// Verify an existing seed phrase
    VerifySeed {
        /// The seed phrase to verify
        #[arg(short, long)]
        mnemonic: String,
    },
    /// Enter interactive mode
    Interactive,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateSeed { strength } => match generate_seed(strength) {
            Ok(mnemonic) => println!("Generated seed phrase:\n{}", mnemonic),
            Err(e) => eprintln!("Error generating seed phrase: {}", e),
        },
        Commands::VerifySeed { mnemonic } => match verify_seed(&mnemonic) {
            Ok(()) => println!("Seed phrase is valid!"),
            Err(e) => eprintln!("Invalid seed phrase: {}", e),
        },
        Commands::Interactive => {
            if let Err(e) = interactive_mode() {
                eprintln!("Error in interactive mode: {}", e);
            }
        }
    }
}

fn generate_seed(strength: u32) -> Result<String, Bip39Error> {
    let bip39 = Bip39::new(strength)?;
    Ok(bip39.get_mnemonic())
}

fn verify_seed(mnemonic: &str) -> Result<(), Bip39Error> {
    Bip39::from_mnemonic(mnemonic)?;
    Ok(())
}

fn interactive_mode() -> Result<(), Box<dyn std::error::Error>> {
    println!("Password Manager Interactive Mode");
    println!("--------------------------------");

    loop {
        println!("\nAvailable commands:");
        println!("1. Generate new seed phrase");
        println!("2. Verify seed phrase");
        println!("3. Exit");

        print!("\nEnter command number: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim() {
            "1" => {
                println!("\nSelect strength:");
                println!("1. 128 bits (12 words)");
                println!("2. 160 bits (15 words)");
                println!("3. 192 bits (18 words)");
                println!("4. 224 bits (21 words)");
                println!("5. 256 bits (24 words)");

                print!("\nEnter strength option: ");
                io::stdout().flush()?;

                let mut strength_input = String::new();
                io::stdin().read_line(&mut strength_input)?;

                let strength = match strength_input.trim() {
                    "1" => 128,
                    "2" => 160,
                    "3" => 192,
                    "4" => 224,
                    "5" => 256,
                    _ => {
                        println!("Invalid option, using default (256 bits)");
                        256
                    }
                };

                match generate_seed(strength) {
                    Ok(mnemonic) => println!("\nGenerated seed phrase:\n{}", mnemonic),
                    Err(e) => eprintln!("Error generating seed phrase: {}", e),
                }
            }
            "2" => {
                print!("\nEnter seed phrase to verify: ");
                io::stdout().flush()?;

                let mut mnemonic = String::new();
                io::stdin().read_line(&mut mnemonic)?;

                match verify_seed(mnemonic.trim()) {
                    Ok(()) => println!("Seed phrase is valid!"),
                    Err(e) => eprintln!("Invalid seed phrase: {}", e),
                }
            }
            "3" => break,
            _ => println!("Invalid command"),
        }
    }

    Ok(())
}

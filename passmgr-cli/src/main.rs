// passmgr-cli/src/main.rs
use clap::{Parser, Subcommand};
use crypto::{
    bip39::{Bip39, Bip39Error},
    master_keys::MasterKeys,
    master_password::{MasterPassword, MasterPasswordError},
};
use rpassword::read_password;
use std::io::{self, Write};
use storage::{Storage, StorageError};

#[derive(Parser)]
#[command(name = "passmgr")]
#[command(about = "Secure Password Manager", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize the password manager with master password
    Init {
        /// Optional seed phrase (will be generated if not provided)
        #[arg(short, long)]
        seed_phrase: Option<String>,

        /// Seed phrase strength in bits (128, 160, 192, 224, or 256)
        #[arg(short, long, default_value_t = 256)]
        strength: u32,
    },

    /// Change master password
    ChangeMasterPassword,

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

    if let Err(e) = match cli.command {
        Commands::Init {
            seed_phrase,
            strength,
        } => initialize_password_manager(seed_phrase, strength),
        Commands::ChangeMasterPassword => change_master_password(),
        Commands::GenerateSeed { strength } => generate_seed(strength)
            .map(|mnemonic| println!("Generated seed phrase:\n{}", mnemonic))
            .map_err(|e| e.into()),
        Commands::VerifySeed { mnemonic } => verify_seed(&mnemonic)
            .map(|_| println!("Seed phrase is valid!"))
            .map_err(|e| e.into()),
        Commands::Interactive => interactive_mode(),
    } {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn prompt_password(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    read_password()
}

fn initialize_password_manager(
    seed_phrase: Option<String>,
    strength: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let storage = Storage::init()?;

    // Check if already initialized
    if storage.read("system", "master_password_hash").is_ok() {
        return Err("Password manager already initialized".into());
    }

    // Get or generate seed phrase
    let seed_phrase = match seed_phrase {
        Some(phrase) => {
            Bip39::from_mnemonic(&phrase)?;
            phrase
        }
        None => {
            let bip39 = Bip39::new(strength)?;
            let phrase = bip39.get_mnemonic();
            println!("Generated seed phrase (KEEP THIS SAFE):\n{}\n", phrase);
            phrase
        }
    };

    // Set master password
    let password = prompt_password("Enter new master password: ")?;
    let confirm = prompt_password("Confirm master password: ")?;

    if password != confirm {
        return Err("Passwords do not match".into());
    }

    let master_password = MasterPassword::new(&password)?;

    // Generate and encrypt master keys
    let bip39 = Bip39::from_mnemonic(&seed_phrase)?;
    let master_keys = MasterKeys::from_entropy(&bip39.get_seed(""))?;

    // Store encrypted master keys and password hash
    let encrypted_keys = master_password.encrypt(&bincode::serialize(&master_keys)?)?;

    storage.create(storage::Record::new(
        "master_password_hash".to_string(),
        "System Data".to_string(),
        "system".to_string(),
        master_password.get_hash().as_bytes().to_vec(),
        vec![],
    ))?;

    storage.create(storage::Record::new(
        "master_keys".to_string(),
        "System Data".to_string(),
        "system".to_string(),
        encrypted_keys,
        vec![],
    ))?;

    println!("Password manager initialized successfully");
    Ok(())
}

fn change_master_password() -> Result<(), Box<dyn std::error::Error>> {
    let storage = Storage::init()?;

    // Get current master password hash and encrypted keys
    let hash_record = storage.read("system", "master_password_hash")?;
    let keys_record = storage.read("system", "master_keys")?;

    let current_hash = String::from_utf8(hash_record.data.clone())?;

    // Verify current password and decrypt master keys
    let current_password = prompt_password("Enter current master password: ")?;
    let current_mp = MasterPassword::load(&current_password, &current_hash)?;
    let master_keys: MasterKeys = bincode::deserialize(&current_mp.decrypt(&keys_record.data)?)?;

    // Set new password
    let new_password = prompt_password("Enter new master password: ")?;
    let confirm = prompt_password("Confirm new master password: ")?;

    if new_password != confirm {
        return Err("Passwords do not match".into());
    }

    let new_mp = MasterPassword::new(&new_password)?;

    // Re-encrypt master keys with new password
    let encrypted_keys = new_mp.encrypt(&bincode::serialize(&master_keys)?)?;

    // Update storage
    let mut hash_record = hash_record;
    let mut keys_record = keys_record;

    hash_record.update(None, Some(new_mp.get_hash().as_bytes().to_vec()), None);
    keys_record.update(None, Some(encrypted_keys), None);

    storage.update(hash_record)?;
    storage.update(keys_record)?;

    println!("Master password changed successfully");
    Ok(())
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
        println!("1. Initialize password manager");
        println!("2. Change master password");
        println!("3. Generate new seed phrase");
        println!("4. Verify seed phrase");
        println!("5. Exit");

        print!("\nEnter command number: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim() {
            "1" => {
                println!("\nInitializing password manager...");
                if let Err(e) = initialize_password_manager(None, 256) {
                    eprintln!("Error: {}", e);
                }
            }
            "2" => {
                println!("\nChanging master password...");
                if let Err(e) = change_master_password() {
                    eprintln!("Error: {}", e);
                }
            }
            "3" => {
                println!("\nSelect strength:");
                println!("1. 128 bits (12 words)");
                println!("2. 160 bits (15 words)");
                println!("3. 192 bits (18 words)");
                println!("4. 224 bits (21 words)");
                println!("5. 256 bits (24 words)");

                print!("\nEnter strength option (default: 5): ");
                io::stdout().flush()?;

                let mut strength_input = String::new();
                io::stdin().read_line(&mut strength_input)?;

                let strength = match strength_input.trim() {
                    "1" => 128,
                    "2" => 160,
                    "3" => 192,
                    "4" => 224,
                    _ => 256,
                };

                match generate_seed(strength) {
                    Ok(mnemonic) => println!("\nGenerated seed phrase:\n{}", mnemonic),
                    Err(e) => eprintln!("Error: {}", e),
                }
            }
            "4" => {
                print!("\nEnter seed phrase to verify: ");
                io::stdout().flush()?;

                let mut mnemonic = String::new();
                io::stdin().read_line(&mut mnemonic)?;

                match verify_seed(mnemonic.trim()) {
                    Ok(()) => println!("Seed phrase is valid!"),
                    Err(e) => eprintln!("Invalid seed phrase: {}", e),
                }
            }
            "5" => break,
            _ => println!("Invalid command"),
        }
    }

    Ok(())
}

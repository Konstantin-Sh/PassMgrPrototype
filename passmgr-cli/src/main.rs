use clap::{Parser, Subcommand};
use crypto::{
    bip39::{Bip39, Bip39Error},
    structures::CipherOption,
    MasterKeys,
};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
};
use storage::{
    structures::{Atributes, Item, Record},
    user_db::UserDb,
};

// ... keep existing Cli and Commands structs ...

#[derive(Parser)]
#[command(name = "passmgr-cli")]
#[command(about = "Password Manager CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start interactive mode
    Interactive,
    // ... keep existing subcommands ...
}

fn main() {
    let cli = Cli::parse();
    if let Commands::Interactive = cli.command {
        if let Err(e) = interactive_mode() {
            eprintln!("Error: {e}");
        }
    }
}

enum AppState<'a> {
    StartScreen,
    OpenDbScreen,
    CreateNewScreen,
    WorkScreen(&'a UserSession),
    NewRecordScreen(&'a UserSession, Record),
}

struct UserSession {
    user_db: UserDb<'static>,
    // master_keys: MasterKeys,
    db_path: PathBuf,
}

fn interactive_mode() -> Result<(), Box<dyn std::error::Error>> {
    let mut state = AppState::StartScreen;

    loop {
        match state {
            AppState::StartScreen => {
                println!("\nPassword Manager - Main Menu");
                println!("1. Open existing database");
                println!("2. Create new database");
                println!("3. Restore from server");
                println!("4. Exit");

                match prompt("Choose option: ")?.as_str() {
                    "1" => state = AppState::OpenDbScreen,
                    "2" => state = AppState::CreateNewScreen,
                    "3" => unimplemented!("Server restore not implemented"),
                    "4" => break,
                    _ => println!("Invalid option"),
                }
            }

            AppState::OpenDbScreen => {
                let mnemonic = prompt("Enter seed phrase: ")?;
                let db_path = confirm_db_path()?;
                // TODO refactor to remove dirty hacks
                let master_keys_owned = create_master_keys(&mnemonic)?;
                let master_keys: &'static MasterKeys = Box::leak(Box::new(master_keys_owned));

                let cipher_chain = vec![
                    CipherOption::AES256,
                    CipherOption::XChaCha20,
                    CipherOption::Kuznyechik,
                ];

                let user_db = UserDb::new(
                    &db_path,
                    u128::from_le_bytes(master_keys.user_id),
                    &master_keys,
                    cipher_chain,
                )?;
                let user_session_owned = UserSession {
                    user_db,
                    //master_keys,
                    db_path,
                };
                let user_session: &'static UserSession = Box::leak(Box::new(user_session_owned));

                state = AppState::WorkScreen(&user_session);
            }

            AppState::CreateNewScreen => {
                let strength = select_entropy_strength()?;
                let bip39 = Bip39::new(strength)?;
                let mnemonic = bip39.get_mnemonic();

                println!("Your new seed phrase:\n{}\n", mnemonic);
                if !confirm_n("Did you save the seed phrase securely? [y/N] ")? {
                    println!("Operation canceled");
                    state = AppState::StartScreen;
                    continue;
                }

                let db_path = confirm_db_path()?;
                // TODO refactor to remove dirty hacks
                let master_keys_owned = create_master_keys(&mnemonic)?;
                let master_keys: &'static MasterKeys = Box::leak(Box::new(master_keys_owned));

                let cipher_chain = vec![
                    CipherOption::AES256,
                    CipherOption::XChaCha20,
                    CipherOption::Kuznyechik,
                ];

                let user_db = UserDb::new(
                    &db_path,
                    u128::from_le_bytes(master_keys.user_id),
                    &master_keys,
                    cipher_chain,
                )?;
                let user_session_owned = UserSession {
                    user_db,
                    //master_keys,
                    db_path,
                };
                let user_session: &'static UserSession = Box::leak(Box::new(user_session_owned));

                state = AppState::WorkScreen(&user_session);
            }

            AppState::WorkScreen(session) => {
                println!("\nDatabase Management");
                println!("1. List all records");
                println!("2. Show record by ID");
                println!("3. Show password by ID");
                println!("4. Create new record");
                println!("5. Update record (unimplemented)");
                println!("6. Delete record");
                println!("7. Sync with server (unimplemented)");
                println!("8. Register on server (unimplemented)");
                println!("9. Return to main menu");

                match prompt("Choose option: ")?.as_str() {
                    "1" => list_records(&session.user_db)?,
                    "2" => show_record(&session.user_db)?,
                    "3" => show_password(&session.user_db)?,
                    "4" => {
                        state = AppState::NewRecordScreen(
                            session,
                            Record {
                                icon: String::new(),
                                created: current_timestamp(),
                                updated: current_timestamp(),
                                fields: Vec::new(),
                            },
                        )
                    }
                    "6" => delete_record(&session.user_db)?,
                    "9" => state = AppState::StartScreen,
                    _ => println!("Invalid option or unimplemented feature"),
                }
            }

            AppState::NewRecordScreen(session, mut record) => {
                record = build_record(record)?;

                let record_id = session.user_db.create(record.clone())?;
                println!("Created new record with ID: {}", record_id);
                state = AppState::WorkScreen(session);
            }
        }
    }
    Ok(())
}

// Helper functions

fn prompt(message: &str) -> io::Result<String> {
    print!("{}", message);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn confirm_n(message: &str) -> io::Result<bool> {
    let input = prompt(message)?.to_lowercase();
    Ok(input == "y" || input == "yes")
}
fn confirm_y(message: &str) -> io::Result<bool> {
    let input = prompt(message)?.to_lowercase();
    if input.to_lowercase().starts_with('n') {
        Ok(false)
    } else {
        Ok(true)
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn confirm_db_path() -> io::Result<PathBuf> {
    let default_path = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("passmgr_db");

    println!("Default DB path: {}", default_path.display());

    if confirm_y("Use default path? [Y/n] ")? {
        Ok(default_path)
    } else {
        let custom_path = prompt("Enter custom path: ")?;
        Ok(PathBuf::from(custom_path))
    }
}

fn create_master_keys(mnemonic: &str) -> Result<MasterKeys, Bip39Error> {
    let bip39 = Bip39::from_mnemonic(mnemonic)?;
    // TODO bug with entropy len < 32 and error handling
    MasterKeys::from_entropy(&bip39.get_entropy())
        .map_err(|e| Bip39Error::PassmgrCliError(e.to_string()))
}

fn select_entropy_strength() -> io::Result<u32> {
    println!("Select entropy strength:");
    // println!("1. 128 bits (12 words)");
    // println!("2. 160 bits (15 words)");
    // println!("3. 192 bits (18 words)");
    // println!("4. 224 bits (21 words)");
    println!("5. only 256 bits (24 words)");

    match prompt("Your choice: ")?.as_str() {
        // "1" => Ok(128),
        // "2" => Ok(160),
        // "3" => Ok(192),
        // "4" => Ok(224),
        "5" => Ok(256),
        _ => {
            println!("Invalid selection, using 256 bits");
            Ok(256)
        }
    }
}

// Record management functions

fn list_records(user_db: &UserDb) -> Result<(), Box<dyn std::error::Error>> {
    let records = user_db.list_records()?;
    println!("\nStored Record IDs:");
    for id in records {
        println!("- {}", id);
    }
    Ok(())
}

fn show_record(user_db: &UserDb) -> Result<(), Box<dyn std::error::Error>> {
    let record_id = prompt("Enter record ID: ")?;
    let record = user_db.read(record_id.parse()?)?;

    println!("\nRecord Details:");
    for item in record.fields {
        println!("[{}]", item.title);
        println!("Value: {}", mask_value(&item.value, &item.types));
        if !item.types.is_empty() {
            println!("Attributes: {}", format_attributes(&item.types));
        }
        println!();
    }
    Ok(())
}

fn show_password(user_db: &UserDb) -> Result<(), Box<dyn std::error::Error>> {
    let record_id = prompt("Enter record ID: ")?;
    let record = user_db.read(record_id.parse()?)?;

    println!("\nRecord Hidden Details:");
    for item in record.fields {
        if item.types.contains(&Atributes::Hide) {
            println!("[{}]", item.title);
            println!("Value: {}", &item.value);
        }
    }
    println!();
    Ok(())
}

fn delete_record(user_db: &UserDb) -> Result<(), Box<dyn std::error::Error>> {
    let record_id = prompt("Enter record ID to delete: ")?;
    user_db.delete(record_id.parse()?)?;
    println!("Record deleted successfully");
    Ok(())
}

fn build_record(mut record: Record) -> Result<Record, Box<dyn std::error::Error>> {
    for title in &["Name", "URL", "Login", "Password", "Note"] {
        if confirm_y(&format!("Add {} field? [Y/n] ", title))? {
            let value = prompt(&format!("Enter {}: ", title))?;
            let mut attributes = Vec::new();

            if *title == "Password" {
                attributes.push(Atributes::Hide);
                if confirm_n("Enable copy protection? [y/N] ")? {
                    attributes.push(Atributes::Copy);
                }
            }

            record.fields.push(Item {
                title: title.to_string(),
                value,
                types: attributes,
            });
        }
    }

    while confirm_n("Add custom field? [y/N] ")? {
        let title = prompt("Enter field title: ")?;
        let value = prompt("Enter field value: ")?;
        record.fields.push(Item {
            title,
            value,
            types: Vec::new(),
        });
    }

    Ok(record)
}

fn mask_value(value: &str, attributes: &[Atributes]) -> String {
    if attributes.contains(&Atributes::Hide) {
        "*".repeat(value.len())
    } else {
        value.to_string()
    }
}

fn format_attributes(attributes: &[Atributes]) -> String {
    attributes
        .iter()
        .map(|a| match a {
            Atributes::Hide => "Hidden",
            Atributes::Copy => "Copy-protected",
            Atributes::Reload => "Auto-reload",
        })
        .collect::<Vec<_>>()
        .join(", ")
}

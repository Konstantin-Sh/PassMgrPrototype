use clap::{Parser, Subcommand};
use crypto::UserId;
use crypto::{
    bip39::{Bip39, Bip39Error},
    master_keys::AssymetricKeypair,
    structures::CipherOption,
    MasterKeys,
};
use passmgr_rpc::rpc_passmgr::{
    rpc_passmgr_client::RpcPassmgrClient, AuthChallengeRequest, AuthChallengeResponse, AuthRequest,
    DeleteAllRequest, GetAllRequest, GetListRequest, RegisterRequest, SetOneRequest,
};
use std::{
    io::{self, Write},
    path::PathBuf,
};
use storage::{
    structures::{Atributes, CipherRecord, Item, Record},
    user_db::UserDb,
};
use tonic::transport::Channel;

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
    Refactor,
    // ... keep existing subcommands ...
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    // if let Commands::Interactive = cli.command {
    //     if let Err(e) = interactive_mode().await {
    //         eprintln!("Error: {e}");
    //     }
    // }
    match cli.command {
        Commands::Interactive => {
            if let Err(e) = interactive_mode().await {
                eprintln!("Error: {e}");
            }
        }
        _ => println!("Invalid option or unimplemented feature"),
    }
}

enum AppState<'a> {
    StartScreen,
    OpenDbScreen,
    CreateNewScreen,
    WorkScreen(&'a UserSession),
    ServerStuff(&'a UserSession),
    NewRecordScreen(&'a UserSession, Record),
}

struct UserSession {
    user_db: UserDb<'static>,
    // db_path: PathBuf,
}

struct ServerSession {
    client: Option<RpcPassmgrClient<Channel>>,
    auth_token: Option<String>,
    user_id: UserId,
    server_key: [u8; 32],
    key_pairs: Option<AssymetricKeypair>,
}

async fn interactive_mode() -> Result<(), Box<dyn std::error::Error>> {
    let mut state = AppState::StartScreen;
    let mut server = ServerSession {
        client: None,
        auth_token: None,
        user_id: [0; 32], // TODO block uid=0 or Option and server_key also
        server_key: [0u8; 32],
        key_pairs: None,
    };

    loop {
        match state {
            AppState::StartScreen => {
                println!("\nPassword Manager - Main Menu");
                println!("1. Open existing database");
                println!("2. Create new database");
                //println!("3. Restore from server");
                println!("0. Exit");

                match prompt("Choose option: ")?.as_str() {
                    "1" => state = AppState::OpenDbScreen,
                    "2" => state = AppState::CreateNewScreen,
                    //"3" => unimplemented!("Server restore not implemented"),
                    "0" => break,
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

                let user_db =
                    UserDb::new(&db_path, master_keys.user_id, &master_keys, cipher_chain)?;
                server.user_id = master_keys.user_id;
                server.server_key = master_keys.server_key;
                server.key_pairs = Some(AssymetricKeypair::generate_dilithium2(
                    &master_keys.dilithium_seed,
                ));

                // let user_session_owned = UserSession { user_db, db_path };
                let user_session_owned = UserSession { user_db };
                let user_session: &'static UserSession = Box::leak(Box::new(user_session_owned));

                state = AppState::WorkScreen(user_session);
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

                let user_db =
                    UserDb::new(&db_path, master_keys.user_id, &master_keys, cipher_chain)?;
                server.user_id = master_keys.user_id;
                server.server_key = master_keys.server_key;
                server.key_pairs = Some(AssymetricKeypair::generate_dilithium2(
                    &master_keys.dilithium_seed,
                ));

                // let user_session_owned = UserSession { user_db, db_path };
                let user_session_owned = UserSession { user_db };
                let user_session: &'static UserSession = Box::leak(Box::new(user_session_owned));

                state = AppState::WorkScreen(user_session);
            }

            AppState::WorkScreen(session) => {
                println!("\nDatabase Management");
                println!("1. List all records");
                println!("2. Show record by ID");
                println!("3. Show password by ID");
                println!("4. Create new record");
                println!("5. Update record (unimplemented)");
                println!("6. Delete record");
                // 7 - free
                println!("8. Server Management");
                println!("0. Return to main menu");

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
                    "8" => state = AppState::ServerStuff(session),
                    "0" => state = AppState::StartScreen,
                    _ => println!("Invalid option or unimplemented feature"),
                }
            }

            AppState::NewRecordScreen(session, mut record) => {
                record = build_record(record)?;

                let record_id = session.user_db.create(record.clone())?;
                println!("Created new record with ID: {}", record_id);
                state = AppState::WorkScreen(session);
            }
            AppState::ServerStuff(session) => {
                println!("\nServer Management");
                println!("1. Connect to Server");
                println!("2. Register on Server");
                println!("3. Auth...");
                println!("4. Sync with Server");
                println!("5. List records id from Server");
                println!("");
                println!("7. Delete all records from Server");
                println!("");
                println!("0. Return to DB managment");

                match prompt("Choose option: ")?.as_str() {
                    "1" => {
                        if server.client.is_none() {
                            connect_to_server(&mut server).await?;
                            println!("Connected successfully!");
                        } else {
                            println!("Already connected!");
                        }
                    }
                    "2" => {
                        register_on_server(&mut server).await?;
                        println!("Registered successfully!");
                    }
                    "3" => {
                        if server.auth_token.is_none() {
                            authenticate(&mut server).await?;
                            println!("Auth... successfully!");
                        } else {
                            println!("Already auth!");
                        }
                    }
                    "4" => {
                        // TODO Create struct ServerStuff
                        sync_with_server(&mut server, session).await?;
                        println!("Sync completed!");
                    }
                    "5" => {
                        println!("--------------------------");
                        get_all_ids_server(&mut server).await?;
                        println!("--------------------------");
                    }
                    "7" => {
                        if confirm_n("Remove all records [y/N]")? {
                            delete_all_on_server(&mut server).await?;
                            println!("All records deleted on server");
                        } else {
                            println!("Uh, Saved");
                        }
                    }
                    "0" => state = AppState::WorkScreen(session),
                    _ => println!("Invalid option or unimplemented feature"),
                }
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

// Server communication =========================================================

async fn connect_to_server(server: &mut ServerSession) -> Result<(), Box<dyn std::error::Error>> {
    let channel = tonic::transport::Channel::from_static("http://127.0.0.1:50051")
        .connect()
        .await?;
    server.client = Some(RpcPassmgrClient::new(channel));
    Ok(())
}
async fn register_on_server(server: &mut ServerSession) -> Result<(), Box<dyn std::error::Error>> {
    // TODO Refactor
    if server.user_id == [0; 32] {
        panic!("uninit var: server: ServerSession")
    };

    // let keypair = Keypair::generate(Some(&seed));
    // let keypair = dilithium2::Keypair::generate(Some(&server.user_id));
    let pub_key = match &server.key_pairs {
        Some(pk) => &pk.dilithium_keypair.public,
        None => panic!("No public key found"),
    };

    let request = RegisterRequest {
        user_id: server.user_id.to_vec(),
        server_key: server.server_key.to_vec(),
        pub_key: pub_key.bytes.to_vec(),
    };
    match &mut server.client {
        Some(client) => client
            .register(request)
            .await?
            .into_inner()
            .success
            .then_some(())
            .ok_or("Server registration failed".into()),
        None => unimplemented!(),
    }
}

// passmgr-cli/src/main.rs
async fn sync_with_server(
    server: &mut ServerSession,
    session: &UserSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_token = match &server.auth_token {
        Some(c) => c,
        None => return Err("No auth token provided".into()),
    };
    // 1. Get server records
    let server_records = match &mut server.client {
        Some(client) => {
            client
                .get_all(GetAllRequest {
                    user_id: server.user_id.to_vec(),
                    auth_token: auth_token.to_string(), // Use actual auth flow
                })
                .await?
                .into_inner()
                .records
        }
        None => unimplemented!(),
    };

    // 2. Compare with local
    let local_records = session.user_db.list_records()?;

    // 3. Conflict resolution
    for server_record in server_records {
        let local_exists = local_records.contains(&server_record.id);
        if !local_exists || server_record.ver > session.user_db.storage.get(server_record.id)?.ver {
            // Update local
            //TODO Implement

            session.user_db.storage.up(
                server_record.id,
                &CipherRecord {
                    user_id: server.user_id,
                    cipher_record_id: server_record.id,
                    ver: server_record.ver,
                    cipher_options: vec![], // TODO Fix problev with cipher_options
                    data: server_record.data,
                },
            )?;
        }
    }

    // 4. Push local changes
    match &mut server.client {
        Some(client) => {
            for local_id in local_records {
                let local_record = session.user_db.storage.get(local_id)?;
                client
                    .set_one(SetOneRequest {
                        user_id: server.user_id.to_vec(),
                        auth_token: auth_token.to_string(),
                        record: Some(passmgr_rpc::rpc_passmgr::Record {
                            id: local_id,
                            ver: local_record.ver,
                            user_id: server.user_id.to_vec(),
                            data: local_record.data,
                        }),
                    })
                    .await?;
            }
        }
        None => unimplemented!(),
    }

    Ok(())
}
async fn authenticate(server: &mut ServerSession) -> Result<(), Box<dyn std::error::Error>> {
    // Convert the Option into a Result, returning an error if it's None.
    let client: &mut RpcPassmgrClient<Channel> = match &mut server.client {
        Some(c) => c,
        None => return Err("No client provided".into()),
    };
    let challenge = client
        .auth_challenge(AuthChallengeRequest {
            user_id: server.user_id.to_vec(),
        })
        .await?;

    let keypair = match &server.key_pairs {
        Some(pk) => &pk.dilithium_keypair,
        None => panic!("No public key found"),
    };
    let challenge_signature = keypair.sign(&challenge.into_inner().challenge);
    // TODO remove comment
    // Use the unwrapped client to perform authentication.
    let response = client
        .authenticate(AuthRequest {
            user_id: server.user_id.to_vec(),
            challenge_signature: challenge_signature.to_vec(),
        })
        .await?;
    server.auth_token = Some(response.into_inner().auth_token);
    Ok(())
}

async fn delete_all_on_server(
    server: &mut ServerSession,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_token = match &server.auth_token {
        Some(c) => c,
        None => return Err("No auth token provided".into()),
    };
    match &mut server.client {
        Some(client) => {
            client
                .delete_all(DeleteAllRequest {
                    user_id: server.user_id.to_vec(),
                    auth_token: auth_token.to_string(),
                })
                .await?;
        }
        None => unimplemented!(),
    }

    Ok(())
}

async fn get_all_ids_server(server: &mut ServerSession) -> Result<(), Box<dyn std::error::Error>> {
    let auth_token = match &server.auth_token {
        Some(c) => c,
        None => return Err("No auth token provided".into()),
    };
    // 1. Get server records
    let server_records = match &mut server.client {
        Some(client) => {
            client
                .get_list(GetListRequest {
                    user_id: server.user_id.to_vec(),
                    auth_token: auth_token.to_string(), // Use actual auth flow
                })
                .await?
                .into_inner()
                .record_i_ds
        }
        None => unimplemented!(),
    };
    for item in server_records {
        println!("{:?}", item);
    }
    Ok(())
}

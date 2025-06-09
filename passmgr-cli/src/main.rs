use clap::{Parser, Subcommand};
use crypto::UserId;
use crypto::{
    bip39::{Bip39, Bip39Error},
    master_keys::AssymetricKeypair,
    structures::CipherOption,
    MasterKeys,
};
use passmgr_rpc::rpc_passmgr::GetNonceRequest;
use passmgr_rpc::rpc_passmgr::{
    rpc_passmgr_client::RpcPassmgrClient, AuthSignature, DeleteAllRequest, DeleteByIdRequest,
    GetAllRequest, GetByIdRequest, GetListRequest, RegisterRequest, SetOneRequest,
    SetRecordsRequest,
};
use std::{
    io::{self, Write},
    path::PathBuf,
};
use storage::{
    structures::{Atributes, CipherRecord, Item, Record},
    user_db::UserDb,
};
use thiserror::Error;
use tonic::transport::Channel;

// Define a custom error type with thiserror
#[derive(Debug, Error)]
pub enum PassmgrError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("BIP39 error: {0}")]
    Bip39(#[from] Bip39Error),

    #[error("Parse error: {0}")]
    Parse(#[from] std::num::ParseIntError),

    #[error("Tonic transport error: {0}")]
    TonicTransport(#[from] tonic::transport::Error),

    #[error("Tonic status error: {0}")]
    TonicStatus(#[from] tonic::Status),

    #[error("User database error: {0}")]
    UserDb(String),

    #[error("Server error: {0}")]
    Server(String),

    #[error("{0}")]
    Generic(String),
}

// For convenience in converting string errors
impl From<String> for PassmgrError {
    fn from(s: String) -> Self {
        PassmgrError::Generic(s)
    }
}

impl From<&str> for PassmgrError {
    fn from(s: &str) -> Self {
        PassmgrError::Generic(s.to_string())
    }
}

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
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
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
    RestoreDbScreen,
    WorkScreen(&'a UserSession),
    ServerStuff(&'a UserSession),
    NewRecordScreen(&'a UserSession, Record),
}

struct UserSession {
    user_db: UserDb<'static>,
}

struct ServerSession {
    client: Option<RpcPassmgrClient<Channel>>,
    user_id: UserId,
    key_pairs: Option<AssymetricKeypair>,
    nonce: u64,
}

impl ServerSession {
    fn sign_request<T>(&self, request_data: &T) -> Result<AuthSignature, PassmgrError>
    where
        T: prost::Message,
    {
        let keypair = match &self.key_pairs {
            Some(pk) => &pk.dilithium_keypair,
            None => return Err(PassmgrError::Server("No keypair found".into())),
        };

        let mut sign_data = Vec::new();
        sign_data.extend_from_slice(&self.nonce.to_be_bytes());

        // Encode request data
        let mut request_bytes = Vec::new();
        request_data
            .encode(&mut request_bytes)
            .map_err(|e| format!("Failed to encode request: {}", e))?;
        sign_data.extend_from_slice(&request_bytes);

        let signature = keypair.sign(&sign_data);
        let auth_data = AuthSignature {
            user_id: self.user_id.to_vec(),
            nonce: self.nonce,
            signature: signature.to_vec(),
        };

        let _ = self.nonce.wrapping_add(1);

        Ok(auth_data)
    }
}

async fn interactive_mode() -> Result<(), PassmgrError> {
    let mut state = AppState::StartScreen;
    let mut server = ServerSession {
        client: None,
        user_id: [0; 32],
        key_pairs: None,
        nonce: 0,
    };

    loop {
        match state {
            AppState::StartScreen => {
                println!("\nPassword Manager - Main Menu");
                println!("1. Open existing database");
                println!("2. Create new database");
                println!("3. Restore database from server");
                println!("0. Exit");

                match prompt("Choose option: ")?.as_str() {
                    "1" => state = AppState::OpenDbScreen,
                    "2" => state = AppState::CreateNewScreen,
                    "3" => state = AppState::RestoreDbScreen,
                    "0" => break,
                    _ => println!("Invalid option"),
                }
            }

            AppState::OpenDbScreen => {
                let mnemonic = prompt("Enter seed phrase: ")?;
                let db_path = confirm_db_path()?;
                let master_keys_owned = create_master_keys(&mnemonic)?;
                let master_keys: &'static MasterKeys = Box::leak(Box::new(master_keys_owned));

                let cipher_chain = vec![
                    CipherOption::AES256,
                    CipherOption::XChaCha20,
                    CipherOption::Kuznyechik,
                ];

                let user_db =
                    UserDb::new(&db_path, master_keys.user_id, &master_keys, cipher_chain)
                        .map_err(|e| PassmgrError::UserDb(e.to_string()))?;
                server.user_id = master_keys.user_id;
                server.key_pairs = Some(AssymetricKeypair::generate_dilithium2(
                    &master_keys.dilithium_seed,
                ));

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
                let master_keys_owned = create_master_keys(&mnemonic)?;
                let master_keys: &'static MasterKeys = Box::leak(Box::new(master_keys_owned));

                let cipher_chain = vec![
                    CipherOption::AES256,
                    CipherOption::XChaCha20,
                    CipherOption::Kuznyechik,
                ];

                let user_db =
                    UserDb::new(&db_path, master_keys.user_id, &master_keys, cipher_chain)
                        .map_err(|e| PassmgrError::UserDb(e.to_string()))?;
                server.user_id = master_keys.user_id;
                server.key_pairs = Some(AssymetricKeypair::generate_dilithium2(
                    &master_keys.dilithium_seed,
                ));

                let user_session_owned = UserSession { user_db };
                let user_session: &'static UserSession = Box::leak(Box::new(user_session_owned));

                state = AppState::WorkScreen(user_session);
            }

            AppState::RestoreDbScreen => {
                let mnemonic = prompt("Enter seed phrase: ")?;
                let db_path = confirm_db_path()?;
                let master_keys_owned = create_master_keys(&mnemonic)?;
                let master_keys: &'static MasterKeys = Box::leak(Box::new(master_keys_owned));

                let cipher_chain = vec![
                    CipherOption::AES256,
                    CipherOption::XChaCha20,
                    CipherOption::Kuznyechik,
                ];

                let user_db =
                    UserDb::new(&db_path, master_keys.user_id, &master_keys, cipher_chain)
                        .map_err(|e| PassmgrError::UserDb(e.to_string()))?;
                server.user_id = master_keys.user_id;
                server.key_pairs = Some(AssymetricKeypair::generate_dilithium2(
                    &master_keys.dilithium_seed,
                ));

                let user_session_owned = UserSession { user_db };
                let user_session: &'static UserSession = Box::leak(Box::new(user_session_owned));

                // Restore from server
                if server.client.is_none() {
                    connect_to_server(&mut server).await?;
                    println!("Connected successfully!");
                } else {
                    println!("Already connected!");
                }

                server.nonce = get_nonce_from_server(&mut server).await?;

                sync_with_server(&mut server, user_session).await?;
                println!("Sync completed!");

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

                let record_id = session
                    .user_db
                    .create(record.clone())
                    .map_err(|e| PassmgrError::UserDb(e.to_string()))?;
                println!("Created new record with ID: {}", record_id);
                state = AppState::WorkScreen(session);
            }

            AppState::ServerStuff(session) => {
                println!("\nServer Management");
                println!("1. Connect to Server");
                println!("2. Register on Server");
                println!("3. Sync with Server");
                println!("4. List records id from Server");
                println!("");
                println!("7. Delete all records from Server");
                println!("");
                println!("0. Return to DB managment");

                match prompt("Choose option: ")?.as_str() {
                    "1" => {
                        if server.client.is_none() {
                            connect_to_server(&mut server).await?;
                            println!("Connected successfully!");
                            server.nonce = get_nonce_from_server(&mut server).await?;
                        } else {
                            println!("Already connected!");
                        }
                    }
                    "2" => {
                        register_on_server(&mut server).await?;
                        println!("Registered successfully!");
                    }
                    "3" => {
                        sync_with_server(&mut server, session).await?;
                        println!("Sync completed!");
                    }
                    "4" => {
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

fn prompt(message: &str) -> Result<String, PassmgrError> {
    print!("{}", message);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn confirm_n(message: &str) -> Result<bool, PassmgrError> {
    let input = prompt(message)?.to_lowercase();
    Ok(input == "y" || input == "yes")
}

fn confirm_y(message: &str) -> Result<bool, PassmgrError> {
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

fn confirm_db_path() -> Result<PathBuf, PassmgrError> {
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

fn create_master_keys(mnemonic: &str) -> Result<MasterKeys, PassmgrError> {
    let bip39 = Bip39::from_mnemonic(mnemonic)?;
    MasterKeys::from_entropy(&bip39.get_entropy()).map_err(|e| PassmgrError::Generic(e.to_string()))
}

fn select_entropy_strength() -> Result<u32, PassmgrError> {
    println!("Select entropy strength:");
    println!("5. only 256 bits (24 words)");

    match prompt("Your choice: ")?.as_str() {
        "5" => Ok(256),
        _ => {
            println!("Invalid selection, using 256 bits");
            Ok(256)
        }
    }
}

// Record management functions

fn list_records(user_db: &UserDb) -> Result<(), PassmgrError> {
    let records = user_db
        .list_records()
        .map_err(|e| PassmgrError::UserDb(e.to_string()))?;
    println!("\nStored Record IDs:");
    for id in records {
        println!("- {}", id);
    }
    Ok(())
}

fn show_record(user_db: &UserDb) -> Result<(), PassmgrError> {
    let record_id = prompt("Enter record ID: ")?;
    let record = user_db
        .read(record_id.parse()?)
        .map_err(|e| PassmgrError::UserDb(e.to_string()))?;

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

fn show_password(user_db: &UserDb) -> Result<(), PassmgrError> {
    let record_id = prompt("Enter record ID: ")?;
    let record = user_db
        .read(record_id.parse()?)
        .map_err(|e| PassmgrError::UserDb(e.to_string()))?;

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

fn delete_record(user_db: &UserDb) -> Result<(), PassmgrError> {
    let record_id = prompt("Enter record ID to delete: ")?;
    user_db
        .delete(record_id.parse()?)
        .map_err(|e| PassmgrError::UserDb(e.to_string()))?;
    println!("Record deleted successfully");
    Ok(())
}

fn build_record(mut record: Record) -> Result<Record, PassmgrError> {
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

// Server communication

async fn connect_to_server(server: &mut ServerSession) -> Result<(), PassmgrError> {
    let channel = tonic::transport::Channel::from_static("http://127.0.0.1:50051")
        .connect()
        .await?;
    server.client = Some(RpcPassmgrClient::new(channel));
    Ok(())
}

async fn register_on_server(server: &mut ServerSession) -> Result<(), PassmgrError> {
    if server.user_id == [0; 32] {
        return Err(PassmgrError::Server("Uninitialized user ID".into()));
    }

    let pub_key = match &server.key_pairs {
        Some(pk) => &pk.dilithium_keypair.public,
        None => return Err(PassmgrError::Server("No public key found".into())),
    };

    let request = RegisterRequest {
        user_id: server.user_id.to_vec(),
        pub_key: pub_key.bytes.to_vec(),
    };

    match &mut server.client {
        Some(client) => {
            let response = client.register(request).await?;
            let inner = response.into_inner();
            if !inner.success {
                return Err(PassmgrError::Server("Server registration failed".into()));
            }
            server.nonce = inner.nonce;

            Ok(())
        }
        None => Err(PassmgrError::Server("Not connected to server".into())),
    }
}

async fn get_nonce_from_server(server: &mut ServerSession) -> Result<u64, PassmgrError> {
    let request = GetNonceRequest {
        user_id: server.user_id.to_vec(),
    };

    match &mut server.client {
        Some(client) => {
            let response = client.get_nonce(request).await?;
            Ok(response.into_inner().nonce)
        }
        None => Err(PassmgrError::Server("Not connected to server".into())),
    }
}

async fn sync_with_server(
    server: &mut ServerSession,
    session: &UserSession,
) -> Result<(), PassmgrError> {
    // 1. Create request for get_all
    let request = GetAllRequest { auth: None };
    let auth = server.sign_request(&request)?;
    let request_with_auth = GetAllRequest { auth: Some(auth) };

    // 2. Get server records - get client reference only for this operation
    let server_records = {
        let client = match &mut server.client {
            Some(client) => client,
            None => return Err(PassmgrError::Server("Not connected to server".into())),
        };

        client
            .get_all(request_with_auth)
            .await?
            .into_inner()
            .records
    };

    // 3. Compare with local records
    let local_records = session
        .user_db
        .list_records()
        .map_err(|e| PassmgrError::UserDb(e.to_string()))?;

    // 4. Conflict resolution
    for server_record in server_records {
        let local_exists = local_records.contains(&server_record.id);
        if !local_exists {
            // Create missing record locally
            session
                .user_db
                .storage
                .set(
                    server_record.id,
                    &CipherRecord {
                        user_id: server.user_id,
                        cipher_record_id: server_record.id,
                        ver: server_record.ver,
                        cipher_options: vec![], // Using the same cipher options as local DB
                        data: server_record.data,
                    },
                )
                .map_err(|e| PassmgrError::UserDb(e.to_string()))?;
        } else {
            // Check if server version is newer
            let local_record = session
                .user_db
                .storage
                .get(server_record.id)
                .map_err(|e| PassmgrError::UserDb(e.to_string()))?;
            if server_record.ver > local_record.ver {
                // Update local record
                session
                    .user_db
                    .storage
                    .up(
                        server_record.id,
                        &CipherRecord {
                            user_id: server.user_id,
                            cipher_record_id: server_record.id,
                            ver: server_record.ver,
                            cipher_options: vec![], // Using the same cipher options as local DB
                            data: server_record.data,
                        },
                    )
                    .map_err(|e| PassmgrError::UserDb(e.to_string()))?;
            }
        }
    }

    // 5. Push local changes
    for local_id in local_records {
        let local_record = session
            .user_db
            .storage
            .get(local_id)
            .map_err(|e| PassmgrError::UserDb(e.to_string()))?;
        let record = passmgr_rpc::rpc_passmgr::Record {
            id: local_id,
            ver: local_record.ver,
            user_id: server.user_id.to_vec(),
            data: local_record.data,
        };

        let request = SetOneRequest {
            auth: None,
            record: Some(record),
        };
        let auth = server.sign_request(&request)?;
        let request_with_auth = SetOneRequest {
            auth: Some(auth),
            record: request.record,
        };

        // Get client reference only for this operation
        let client = match &mut server.client {
            Some(client) => client,
            None => return Err(PassmgrError::Server("Not connected to server".into())),
        };

        client.set_one(request_with_auth).await?;
    }

    Ok(())
}

async fn delete_all_on_server(server: &mut ServerSession) -> Result<(), PassmgrError> {
    let request = DeleteAllRequest { auth: None };
    let auth = server.sign_request(&request)?;
    let request_with_auth = DeleteAllRequest { auth: Some(auth) };

    let client = match &mut server.client {
        Some(client) => client,
        None => return Err(PassmgrError::Server("Not connected to server".into())),
    };

    client.delete_all(request_with_auth).await?;
    Ok(())
}

async fn get_all_ids_server(server: &mut ServerSession) -> Result<(), PassmgrError> {
    let request = GetListRequest { auth: None };
    let auth = server.sign_request(&request)?;
    let request_with_auth = GetListRequest { auth: Some(auth) };

    let client = match &mut server.client {
        Some(client) => client,
        None => return Err(PassmgrError::Server("Not connected to server".into())),
    };

    let response = client.get_list(request_with_auth).await?;
    let records = response.into_inner().record_i_ds;

    for record in records {
        println!("ID: {}, Version: {}", record.id, record.ver);
    }
    Ok(())
}

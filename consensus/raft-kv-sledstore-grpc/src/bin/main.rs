use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use openraft::Config;
use raft_kv_sledstore_grpc::grpc::app_service::AppServiceImpl;
use raft_kv_sledstore_grpc::grpc::raft_service::RaftServiceImpl;
use raft_kv_sledstore_grpc::network::Network;
use raft_kv_sledstore_grpc::protobuf::app_service_server::AppServiceServer;
use raft_kv_sledstore_grpc::protobuf::raft_service_server::RaftServiceServer;
use raft_kv_sledstore_grpc::typ::Raft;
use raft_kv_sledstore_grpc::LogStore;
use raft_kv_sledstore_grpc::StateMachineStore;
use tonic::transport::Server;
use tracing::info;


// use rocksdb::ColumnFamilyDescriptor;
// use rocksdb::Options;
// use rocksdb::DB;


#[derive(Parser, Clone, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Opt {
    #[clap(long)]
    pub id: u64,

    #[clap(long)]
    /// Network address to bind the server to (e.g., "127.0.0.1:50051")
    pub addr: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing first, before any logging happens
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_file(true)
        .with_line_number(true)
        .init();

    // Parse the parameters passed by arguments.
    let options = Opt::parse();
    let node_id = options.id;
    let addr = options.addr;

    // Create a configuration for the raft instance.
    let config = Arc::new(
        Config {
            heartbeat_interval: 500,
            election_timeout_min: 1500,
            election_timeout_max: 3000,
            ..Default::default()
        }
        .validate()?,
    );


    // Create sled_db
    let data_dir = dirs::data_dir()
    .unwrap_or_else(|| PathBuf::from("."))
    .join("data").join(node_id.to_string());
    std::fs::create_dir_all(&data_dir)?;
    let db = Arc::new(sled::open(data_dir)?);

    // Create rocks_db
    // let mut db_opts = Options::default();
    // db_opts.create_missing_column_families(true);
    // db_opts.create_if_missing(true);
    // let meta = ColumnFamilyDescriptor::new("meta", Options::default());
    // let logs = ColumnFamilyDescriptor::new("logs", Options::default());

    // let db = DB::open_cf_descriptors(&db_opts, data_dir, vec![meta, logs]).unwrap();
    // let db = Arc::new(db);

    // Create stores and network
    let log_store = LogStore::new(db);
    let state_machine_store = Arc::new(StateMachineStore::default());
    let network = Network {};

    // Create Raft instance
    let raft = Raft::new(node_id, config.clone(), network, log_store, state_machine_store.clone()).await?;

    // Create the management service with raft instance
    let internal_service = RaftServiceImpl::new(raft.clone());
    let api_service = AppServiceImpl::new(raft, state_machine_store);

    // Start server
    let server_future = Server::builder()
        .add_service(RaftServiceServer::new(internal_service))
        .add_service(AppServiceServer::new(api_service))
        .serve(addr.parse()?);

    info!("Node {node_id} starting server at {addr}");
    server_future.await?;

    Ok(())
}

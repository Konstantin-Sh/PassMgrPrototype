use std::path::PathBuf;
use std::sync::Arc;

use openraft::Config;
use tonic::transport::Server;
use tracing::info;

use crate::grpc::app_service::AppServiceImpl;
use crate::grpc::raft_service::RaftServiceImpl;
use crate::network::Network;
use crate::pb::app_service_server::AppServiceServer;
use crate::pb::raft_service_server::RaftServiceServer;
use crate::store::LogStore;
use crate::store::StateMachineStore;
use crate::typ::*;
use crate::NodeId;


pub async fn start_raft_app(node_id: NodeId, http_addr: String) -> Result<(), Box<dyn std::error::Error>> {
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
        .serve(http_addr.parse()?);

    info!("Node {node_id} starting server at {http_addr}");
    server_future.await?;

    Ok(())
}

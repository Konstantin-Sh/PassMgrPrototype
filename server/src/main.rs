use crypto::UserId;
use crystals_dilithium::dilithium2;
use passmgr_rpc::rpc_passmgr::rpc_passmgr_server::{RpcPassmgr, RpcPassmgrServer};
use passmgr_rpc::rpc_passmgr::{
    AuthChallengeRequest, AuthChallengeResponse, AuthRequest, AuthResponse, CloseRequest,
    CloseResponse, DeleteAllRequest, DeleteByIdRequest, DeleteResponse, GetAllRequest,
    GetByIdRequest, GetListRequest, OneRecordResponse, Record, RecordId, RecordListResponse,
    RecordsResponse, RegisterRequest, RegisterResponse, SetOneRequest, SetOneResponse,
    SetRecordsRequest, SetRecordsResponse,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use storage::db::Storage;
use storage::error::StorageError;
use tonic::{Request, Response, Status};
use uuid::Uuid;
// pub mod passmgr {
//     tonic::include_proto!("passmgr.server");
// }

struct PassmgrService {
    auth_db: sled::Db,
    data_dir: PathBuf,
    sessions: Mutex<HashMap<String, (UserId, Instant)>>,
}

impl PassmgrService {
    fn new(auth_db_path: PathBuf, data_dir: PathBuf) -> anyhow::Result<Self> {
        let auth_db = sled::open(auth_db_path)?;
        std::fs::create_dir_all(&data_dir)?;

        Ok(Self {
            auth_db,
            data_dir,
            sessions: Mutex::new(HashMap::new()),
        })
    }

    fn validate_session(&self, auth_token: &str) -> Result<UserId, Status> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| Status::internal("Failed to access sessions"))?;

        let (user_id, expiry) = sessions
            .get(auth_token)
            .ok_or_else(|| Status::unauthenticated("Invalid or expired session"))?;

        if *expiry < Instant::now() {
            // Remove expired session
            drop(sessions);
            let mut sessions = self
                .sessions
                .lock()
                .map_err(|_| Status::internal("Failed to access sessions"))?;
            sessions.remove(auth_token);
            return Err(Status::unauthenticated("Session expired"));
        }

        Ok(*user_id)
    }

    fn get_user_storage(&self, user_id: UserId) -> Result<Storage, Status> {
        let hex_id = user_id.iter().fold(String::new(), |mut acc, b| {
            acc.push_str(&format!("{:02x}", b));
            acc
        });
        let user_data_dir = self.data_dir.join(hex_id);
        Storage::open(&user_data_dir, user_id)
            .map_err(|e| Status::internal(format!("Failed to open user storage: {}", e)))
    }
}

#[tonic::async_trait]
impl RpcPassmgr for PassmgrService {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        let req = request.into_inner();
        let user_id: UserId = req
            .user_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("Invalid user_id length"))?;

        if self
            .auth_db
            .get(user_id.to_vec())
            .map_err(|e| Status::internal(format!("Failed to access auth database: {}", e)))?
            .is_some()
        {
            return Err(Status::already_exists("User already registered"));
        }

        // TODO remove
        // self.auth_db
        //     .insert(user_id.to_vec(), req.server_key.as_slice())
        //     .map_err(|e| Status::internal(format!("Failed to register user: {}", e)))?;

        self.auth_db
            .insert(user_id.to_vec(), req.pub_key.as_slice())
            .map_err(|e| Status::internal(format!("Failed to register user: {}", e)))?;

        let hex_id = user_id.iter().fold(String::new(), |mut acc, b| {
            acc.push_str(&format!("{:02x}", b));
            acc
        });

        let user_data_dir = self.data_dir.join(hex_id);
        std::fs::create_dir_all(&user_data_dir).map_err(|e| {
            Status::internal(format!("Failed to create user data directory: {}", e))
        })?;

        Ok(Response::new(RegisterResponse { success: true }))
    }

    async fn auth_challenge(
        &self,
        request: Request<AuthChallengeRequest>,
    ) -> Result<Response<AuthChallengeResponse>, Status> {
        let req = request.into_inner();
        let user_id: UserId = req
            .user_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("Invalid user_id length"))?;

        let challenge = Uuid::new_v4().as_bytes().to_vec();

        // Store challenge in auth_db with key "challenge_{user_id}"
        let challenge_key = [b"challenge_".as_ref(), &user_id[..]].concat();
        self.auth_db
            .insert(challenge_key, &*challenge)
            .map_err(|e| Status::internal(format!("Failed to store challenge: {}", e)))?;

        Ok(Response::new(AuthChallengeResponse { challenge }))
    }

    async fn authenticate(
        &self,
        request: Request<AuthRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let req = request.into_inner();
        let user_id: UserId = req
            .user_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("Invalid user_id length"))?;

        // Retrieve and remove the stored challenge
        let challenge_key = [b"challenge_".as_ref(), &user_id[..]].concat();
        let challenge = self
            .auth_db
            .get(&challenge_key)
            .map_err(|e| Status::internal(format!("Failed to retrieve challenge: {}", e)))?
            .ok_or_else(|| Status::unauthenticated("No challenge found for user"))?;
        self.auth_db
            .remove(&challenge_key)
            .map_err(|e| Status::internal(format!("Failed to remove challenge: {}", e)))?;

        // Fetch the user's public key
        let public_key_bytes = self
            .auth_db
            .get(user_id.to_vec())
            .map_err(|e| Status::internal(format!("Failed to retrieve user: {}", e)))?
            .ok_or_else(|| Status::not_found("User not found"))?;

        // Deserialize the public key
        let public_key = dilithium2::PublicKey::from_bytes(&public_key_bytes);
        // .map_err(|e| Status::internal(format!("Failed to parse public key: {}", e)))?;

        // Verify the signature
        let is_valid = public_key.verify(&challenge, &req.challenge_signature);
        // .map_err(|e| Status::internal(format!("Signature verification failed: {}", e)))?;

        if !is_valid {
            return Err(Status::unauthenticated("Invalid challenge signature"));
        }

         // TODO need to create auth token using Dilithium
        // Generate auth token (existing code)
        let auth_token = Uuid::new_v4().to_string();
        let expiry = Instant::now() + Duration::from_secs(3600);
        self.sessions
            .lock()
            .map_err(|_| Status::internal("Failed to update sessions"))?
            .insert(auth_token.clone(), (user_id, expiry));

        Ok(Response::new(AuthResponse { auth_token }))
    }

    async fn close_session(
        &self,
        request: Request<CloseRequest>,
    ) -> Result<Response<CloseResponse>, Status> {
        let req = request.into_inner();
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| Status::internal("Failed to access sessions"))?;
        sessions.remove(&req.auth_token);
        Ok(Response::new(CloseResponse {}))
    }

    async fn get_list(
        &self,
        request: Request<GetListRequest>,
    ) -> Result<Response<RecordListResponse>, Status> {
        let req = request.into_inner();
        let user_id = self.validate_session(&req.auth_token)?;
        let storage = self.get_user_storage(user_id)?;

        let records = storage
            .list_ids_with_metadata()
            .map_err(|e| Status::internal(e.to_string()))?;
        // TODO research about user_id from DB
        let record_i_ds = records
            .into_iter()
            .map(|(id, ver, _)| RecordId {
                id,
                ver,
                user_id: user_id.to_vec(),
            })
            .collect();

        Ok(Response::new(RecordListResponse { record_i_ds }))
    }

    async fn get_by_id(
        &self,
        request: Request<GetByIdRequest>,
    ) -> Result<Response<OneRecordResponse>, Status> {
        let req = request.into_inner();
        let user_id = self.validate_session(&req.auth_token)?;
        let storage = self.get_user_storage(user_id)?;

        let record = storage.get(req.cipher_record_id).map_err(|e| match e {
            StorageError::StorageDataNotFound(_) => Status::not_found("Record not found"),
            _ => Status::internal(e.to_string()),
        })?;

        Ok(Response::new(OneRecordResponse {
            record: Some(Record {
                id: record.cipher_record_id,
                ver: record.ver,
                user_id: user_id.to_vec(),
                data: record.data,
            }),
        }))
    }

    async fn get_all(
        &self,
        request: Request<GetAllRequest>,
    ) -> Result<Response<RecordsResponse>, Status> {
        let req = request.into_inner();
        let user_id = self.validate_session(&req.auth_token)?;
        let storage = self.get_user_storage(user_id)?;

        let record_ids = storage
            .list_ids()
            .map_err(|e| Status::internal(e.to_string()))?;

        let mut records: Vec<Record> = Vec::new();
        for record_id in record_ids {
            let record = storage
                .get(record_id)
                .map_err(|e| Status::internal(e.to_string()))?;
            let new_record = Record {
                id: record.cipher_record_id,
                ver: record.ver,
                user_id: user_id.to_vec(),
                data: record.data,
            };
            records.push(new_record);
        }
        Ok(Response::new(RecordsResponse { records }))
    }

    async fn set_one(
        &self,
        request: Request<SetOneRequest>,
    ) -> Result<Response<SetOneResponse>, Status> {
        let req = request.into_inner();
        let user_id = self.validate_session(&req.auth_token)?;
        let storage = self.get_user_storage(user_id)?;

        let record = req
            .record
            .ok_or(Status::invalid_argument("Missing record"))?;
        let cipher_record = storage::structures::CipherRecord {
            user_id,
            cipher_record_id: record.id,
            ver: record.ver,
            cipher_options: vec![], // Adjust based on client's cipher chain
            data: record.data,
        };

        storage
            .set(record.id, &cipher_record)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(SetOneResponse {}))
    }

    async fn set_records(
        &self,
        request: Request<SetRecordsRequest>,
    ) -> Result<Response<SetRecordsResponse>, Status> {
        let req = request.into_inner();
        let user_id = self.validate_session(&req.auth_token)?;
        let storage = self.get_user_storage(user_id)?;

        for record in req.records {
            let cipher_record = storage::structures::CipherRecord {
                user_id,
                cipher_record_id: record.id,
                ver: record.ver,
                cipher_options: vec![], // Adjust based on client's cipher chain
                data: record.data,
            };
            storage
                .set(record.id, &cipher_record)
                .map_err(|e| Status::internal(e.to_string()))?;
        }
        Ok(Response::new(SetRecordsResponse {}))
    }

    async fn delete_by_id(
        &self,
        request: Request<DeleteByIdRequest>,
    ) -> Result<Response<DeleteResponse>, Status> {
        let req = request.into_inner();
        let user_id = self.validate_session(&req.auth_token)?;
        let storage = self.get_user_storage(user_id)?;

        storage
            .remove(req.record_id)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(DeleteResponse {}))
    }
    async fn delete_all(
        &self,
        request: Request<DeleteAllRequest>,
    ) -> Result<Response<DeleteResponse>, Status> {
        let req = request.into_inner();
        let user_id = self.validate_session(&req.auth_token)?;
        let storage = self.get_user_storage(user_id)?;
        let records = storage
            .list_ids()
            .map_err(|e| Status::internal(e.to_string()))?;
        for record_id in records {
            storage
                .remove(record_id)
                .map_err(|e| Status::internal(e.to_string()))?;
        }
        Ok(Response::new(DeleteResponse {}))
    }
    // Implement other methods similarly...
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_db_path = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("auth_db");
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("data");

    let service = PassmgrService::new(auth_db_path, data_dir)?;

    let addr = "0.0.0.0:50051".parse()?;
    let server = RpcPassmgrServer::new(service);

    println!("Server listening on {}", addr);

    tonic::transport::Server::builder()
        .add_service(server)
        .serve(addr)
        .await?;

    Ok(())
}

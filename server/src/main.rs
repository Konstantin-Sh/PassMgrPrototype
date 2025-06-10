use bincode::{deserialize, serialize};
use crypto::UserId;
use crystals_dilithium::dilithium2;
use passmgr_rpc::rpc_passmgr::rpc_passmgr_server::{RpcPassmgr, RpcPassmgrServer};
use passmgr_rpc::rpc_passmgr::{
    AuthSignature, DeleteAllRequest, DeleteByIdRequest, DeleteResponse, GetAllRequest,
    GetByIdRequest, GetListRequest, GetNonceRequest, GetNonceResponse, OneRecordResponse, Record,
    RecordId, RecordListResponse, RecordsResponse, RegisterRequest, RegisterResponse,
    SetOneRequest, SetOneResponse, SetRecordsRequest, SetRecordsResponse,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use storage::db::Storage;
use storage::error::StorageError;
use tonic::{Request, Response, Status};

struct PassmgrService {
    auth_db: sled::Db,
    data_dir: PathBuf,
}

#[derive(Deserialize, Serialize)]
struct AuthEntry {
    nonce: u64,
    public_key: Vec<u8>,
}

impl PassmgrService {
    fn new(auth_db_path: PathBuf, data_dir: PathBuf) -> anyhow::Result<Self> {
        let auth_db = sled::open(auth_db_path)?;
        std::fs::create_dir_all(&data_dir)?;

        Ok(Self { auth_db, data_dir })
    }

    fn validate_auth<T>(
        &self,
        auth: &AuthSignature,
        request_without_auth: &T,
        method_name: &str,
    ) -> Result<UserId, Status>
    where
        T: prost::Message,
    {
        let user_id: UserId = auth
            .user_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("Invalid user_id length"))?;

        // Retrieve AuthEntry
        let auth_entry_bytes = self
            .auth_db
            .get(&user_id)
            .map_err(|e| Status::internal(format!("Failed to retrieve user: {}", e)))?
            .ok_or_else(|| Status::not_found("User not found"))?;

        let auth_entry: AuthEntry = deserialize(&auth_entry_bytes)
            .map_err(|_| Status::internal("Auth entry deserialization failed"))?;

        // Verify nonce
        if auth.nonce != auth_entry.nonce {
            return Err(Status::invalid_argument("Invalid nonce"));
        }

        let public_key = dilithium2::PublicKey::from_bytes(&auth_entry.public_key);

        // Verify signature start
        let mut sign_data = method_name.as_bytes().to_vec();
        sign_data.extend_from_slice(&auth.nonce.to_be_bytes());

        // Encode request data
        sign_data.extend_from_slice(&request_without_auth.encode_to_vec());

        let is_valid = public_key.verify(&sign_data, &auth.signature);
        if !is_valid {
            return Err(Status::unauthenticated("Invalid signature"));
        }

        // Increment and store new nonce
        let _ = auth_entry.nonce.wrapping_add(1);

        self.auth_db
            .insert(user_id.to_vec(), serialize(&auth_entry).unwrap())
            .map_err(|e| Status::internal(format!("Failed to save nonce: {}", e)))?;

        Ok(user_id)
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
        let nonce: u64 = rand::thread_rng().gen();
        let auth_entry = AuthEntry {
            public_key: req.pub_key,
            nonce,
        };

        self.auth_db
            .insert(user_id.to_vec(), serialize(&auth_entry).unwrap())
            .map_err(|e| Status::internal(format!("Failed to register user: {}", e)))?;

        let hex_id = user_id.iter().fold(String::new(), |mut acc, b| {
            acc.push_str(&format!("{:02x}", b));
            acc
        });

        let user_data_dir = self.data_dir.join(hex_id);
        std::fs::create_dir_all(&user_data_dir).map_err(|e| {
            Status::internal(format!("Failed to create user data directory: {}", e))
        })?;

        Ok(Response::new(RegisterResponse {
            success: true,
            nonce,
        }))
    }

    async fn get_nonce(
        &self,
        request: Request<GetNonceRequest>,
    ) -> Result<Response<GetNonceResponse>, Status> {
        let req = request.into_inner();
        let user_id: UserId = req.user_id[..]
            .try_into()
            .map_err(|_| Status::invalid_argument("Invalid user_id length"))?;

        let auth_entry_bytes = self
            .auth_db
            .get(&user_id)
            .map_err(|e| Status::internal(format!("Failed to retrieve user: {}", e)))?
            .ok_or_else(|| Status::not_found("User not found"))?;

        let auth_entry: AuthEntry = deserialize(&auth_entry_bytes)
            .map_err(|_| Status::internal("Auth entry deserialization failed"))?;

        Ok(Response::new(GetNonceResponse {
            nonce: auth_entry.nonce,
        }))
    }

    async fn get_list(
        &self,
        request: Request<GetListRequest>,
    ) -> Result<Response<RecordListResponse>, Status> {
        let req = request.into_inner();
        let mut cloned_req = req.clone();
        cloned_req.auth = None;

        let user_id = self.validate_auth(
            req.auth
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("Missing auth"))?,
            &cloned_req,
            "GetList",
        )?;

        let storage = self.get_user_storage(user_id)?;

        let records = storage
            .list_ids_with_metadata()
            .map_err(|e| Status::internal(e.to_string()))?;

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
        let mut cloned_req = req.clone();
        cloned_req.auth = None;

        let user_id = self.validate_auth(
            req.auth
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("Missing auth"))?,
            &cloned_req,
            "GetById",
        )?;

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
        let mut cloned_req = req.clone();
        cloned_req.auth = None;

        let user_id = self.validate_auth(
            req.auth
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("Missing auth"))?,
            &cloned_req,
            "GetAll",
        )?;

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
        let mut cloned_req = req.clone();
        cloned_req.auth = None;

        let user_id = self.validate_auth(
            req.auth
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("Missing auth"))?,
            &cloned_req,
            "SetOne",
        )?;

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
        let mut cloned_req = req.clone();
        cloned_req.auth = None;

        let user_id = self.validate_auth(
            req.auth
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("Missing auth"))?,
            &cloned_req,
            "SetRecords",
        )?;

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
        let mut cloned_req = req.clone();
        cloned_req.auth = None;

        let user_id = self.validate_auth(
            req.auth
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("Missing auth"))?,
            &cloned_req,
            "DeleteById",
        )?;

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
        let mut cloned_req = req.clone();
        cloned_req.auth = None;

        let user_id = self.validate_auth(
            req.auth
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("Missing auth"))?,
            &cloned_req,
            "DeleteAll",
        )?;

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

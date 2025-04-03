use std::error::Error;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::ops::RangeBounds;
use std::sync::Arc;

use bincode::{deserialize, serialize};
use byteorder::BigEndian;
use byteorder::ReadBytesExt;
use byteorder::WriteBytesExt;
use meta::StoreMeta;
use openraft::alias::EntryOf;
use openraft::alias::LogIdOf;
use openraft::alias::VoteOf;
use openraft::entry::RaftEntry;
use openraft::storage::IOFlushed;
use openraft::storage::RaftLogStorage;
use openraft::LogState;
use openraft::OptionalSend;
use openraft::RaftLogReader;
use openraft::RaftTypeConfig;
use openraft::StorageError;

use sled::Db;

#[derive(Debug, Clone)]
pub struct SledLogStore<C>
where C: RaftTypeConfig
{
    db: Arc<Db>,
    meta: sled::Tree,
    logs: sled::Tree,
    _p: PhantomData<C>,
}

impl<C> SledLogStore<C>
where C: RaftTypeConfig
{
    pub fn new(db: Arc<Db>) -> Self {
        // db.cf_handle("meta").expect("column family `meta` not found");
        // db.cf_handle("logs").expect("column family `logs` not found");
        let meta = db.open_tree("meta").expect("tree meta open failed");
        let logs = db.open_tree("logs").expect("tree logs open failed");
        
        Self {
            db,
            meta,
            logs,
            _p: Default::default(),
        }
    }

    /// Get a store metadata.
    ///
    /// It returns `None` if the store does not have such a metadata stored.
    fn get_meta<M: StoreMeta<C>>(&self) -> Result<Option<M::Value>, StorageError<C>> {
        // let bytes = self.db.get_cf(self.cf_meta(), M::KEY).map_err(M::read_err)?;

        // let Some(bytes) = bytes else {
        //     return Ok(None);
        // };

        // let t = serde_json::from_slice(&bytes).map_err(M::read_err)?;

        // Ok(Some(t))
        let store_tree = &self.meta;
        let ivec = store_tree.get(M::KEY).map_err(M::read_err)?;

        let Some(ivec) = ivec else {
            return Ok(None);
        };

        

        let val = deserialize(&ivec).map_err(M::read_err)?;
        Ok(Some(val))
    }

    /// Save a store metadata.
    fn put_meta<M: StoreMeta<C>>(&self, value: &M::Value) -> Result<(), StorageError<C>> {
        // let json_value = serde_json::to_vec(value).map_err(|e| M::write_err(value, e))?;

        // self.db.put_cf(self.cf_meta(), M::KEY, json_value).map_err(|e| M::write_err(value, e))?;
        let store_tree = &self.meta;
        let bin_value = serialize(value).map_err(|e| M::write_err(value, e))?;
        store_tree.insert(M::KEY, bin_value).map_err(|e| M::write_err(value, e))?;

        Ok(())
    }
}

impl<C> RaftLogReader<C> for SledLogStore<C>
where C: RaftTypeConfig
{
    // async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
    //     &mut self,
    //     range: RB,
    // ) -> Result<Vec<C::Entry>, StorageError<C>> {
    //     let start = match range.start_bound() {
    //         std::ops::Bound::Included(x) => id_to_bin(*x),
    //         std::ops::Bound::Excluded(x) => id_to_bin(*x + 1),
    //         std::ops::Bound::Unbounded => id_to_bin(0),
    //     };

    //     let mut res = Vec::new();

    //     let it = self.db.iterator_cf(self.cf_logs(), rocksdb::IteratorMode::From(&start, Direction::Forward));
    //     for item_res in it {
    //         let (id, val) = item_res.map_err(read_logs_err)?;

    //         let id = bin_to_id(&id);
    //         if !range.contains(&id) {
    //             break;
    //         }

    //         let entry: EntryOf<C> = serde_json::from_slice(&val).map_err(read_logs_err)?;

    //         assert_eq!(id, entry.index());

    //         res.push(entry);
    //     }
    //     Ok(res)
    // }
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<C::Entry>, StorageError<C>> {
        let start_bound = range.start_bound();
        let start = match start_bound {
            std::ops::Bound::Included(x) => id_to_bin(*x),
            std::ops::Bound::Excluded(x) => id_to_bin(*x + 1),
            std::ops::Bound::Unbounded => id_to_bin(0),
        };
        let logs_tree = &self.logs;
        let logs = logs_tree
            .range::<&[u8], _>(start.as_slice()..)
            .map(|el_res| {
                // TODO remove expect
                // let (id, val) = el_res.map_err(read_logs_err)?;
                let el = el_res.expect("Failed read log entry");
                let id = el.0;
                let val = el.1;

                // let entry: StorageResult<Entry<_>> = serde_json::from_slice(&val).map_err(|e| StorageError::IO {
                //     source: StorageIOError::read_logs(&e),
                // });
                // serde_json::from_slice
                // TODO remove expect
                let entry: EntryOf<C> = deserialize(&val).expect("bad");
    
                let id = bin_to_id(&id);

                //assert_eq!(Ok(id), entry.as_ref().map(|e| e.log_id.index));
                assert_eq!(id, entry.index());
                (id, entry)
            })
            .take_while(|(id, _)| range.contains(id))
            .map(|x| x.1)
            .collect();
        Ok(logs)
    }

    async fn read_vote(&mut self) -> Result<Option<VoteOf<C>>, StorageError<C>> {
        self.get_meta::<meta::Vote>()
    }
}

impl<C> RaftLogStorage<C> for SledLogStore<C>
where C: RaftTypeConfig
{
    type LogReader = Self;

    // async fn get_log_state(&mut self) -> Result<LogState<C>, StorageError<C>> {
    //     let last = self.db.iterator_cf(self.cf_logs(), rocksdb::IteratorMode::End).next();

    //     let last_log_id = match last {
    //         None => None,
    //         Some(res) => {
    //             let (_log_index, entry_bytes) = res.map_err(read_logs_err)?;
    //             let ent = serde_json::from_slice::<EntryOf<C>>(&entry_bytes).map_err(read_logs_err)?;
    //             Some(ent.log_id())
    //         }
    //     };

    //     let last_purged_log_id = self.get_meta::<meta::LastPurged>()?;

    //     let last_log_id = match last_log_id {
    //         None => last_purged_log_id.clone(),
    //         Some(x) => Some(x),
    //     };

    //     Ok(LogState {
    //         last_purged_log_id,
    //         last_log_id,
    //     })
    // }
    async fn get_log_state(&mut self) -> Result<LogState<C>, StorageError<C>> {
        let last_purged = self.get_meta::<meta::LastPurged>()?;

        let logs_tree = &self.logs;
        let last_ivec_kv = logs_tree.last().map_err(read_logs_err)?;
        let (_, ent_ivec) = if let Some(last) = last_ivec_kv {
            last
        } else {
            return Ok(LogState {
                last_purged_log_id: last_purged.clone(),
                last_log_id: last_purged,
            });
        };

        let last_ent: EntryOf<C> = deserialize(&ent_ivec).map_err(read_logs_err)?;
        
        let last_log_id = Some(last_ent.log_id());
        // TODO clone? compare to rocksdb version
        let last_log_id = std::cmp::max(last_log_id, last_purged.clone());
        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id,
        })
    }


    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &VoteOf<C>) -> Result<(), StorageError<C>> {
        self.put_meta::<meta::Vote>(vote)?;
        // self.db.flush_wal(true).map_err(|e| StorageError::write_vote(&e))?;
        self.db.flush_async().await.map_err(|e| StorageError::write_vote(&e))?;
        Ok(())
    }

    async fn append<I>(&mut self, entries: I, callback: IOFlushed<C>) -> Result<(), StorageError<C>>
    where I: IntoIterator<Item = EntryOf<C>> + Send {
        let logs_tree = &self.logs;
        let mut batch = sled::Batch::default();

        for entry in entries {
            let id = id_to_bin(entry.index());
            assert_eq!(bin_to_id(&id), entry.index());
            let bin_value = serialize(&entry).map_err(|e| StorageError::write_logs(&e))?;
            // batch.insert(id.as_slice(), value);
            batch.insert(id, bin_value);
            // self.db
            //     .put_cf(
            //         self.cf_logs(),
            //         id,
            //         serde_json::to_vec(&entry).map_err(|e| StorageError::write_logs(&e))?,
            //     )
            //     .map_err(|e| StorageError::write_logs(&e))?;
        }

        logs_tree.apply_batch(batch).map_err(|e| StorageError::write_logs(&e))?;

        //self.db.flush_wal(true).map_err(|e| StorageError::write_logs(&e))?;

        logs_tree.flush_async().await.map_err(|e| StorageError::write_logs(&e))?;

        // If there is error, the callback will be dropped.
        callback.io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(&mut self, log_id: LogIdOf<C>) -> Result<(), StorageError<C>> {
        tracing::debug!("truncate: [{:?}, +oo)", log_id);

        let from = id_to_bin(log_id.index());
        let to = id_to_bin(0xff_ff_ff_ff_ff_ff_ff_ff);
        //self.db.delete_range_cf(self.cf_logs(), &from, &to).map_err(|e| StorageError::write_logs(&e))?;
        //self.db.flush_wal(true).map_err(|e| StorageError::write_logs(&e))?;
        let logs_tree = &self.logs;
        let entries = logs_tree.range::<&[u8], _>(from.as_slice()..to.as_slice());
        let mut batch_del = sled::Batch::default();
        for entry_res in entries {
            let entry = entry_res.map_err(read_logs_err)?;
            batch_del.remove(entry.0);
        }
        logs_tree.apply_batch(batch_del).map_err(|e| StorageError::write_logs(&e))?;
        logs_tree.flush_async().await.map_err(|e| StorageError::write_logs(&e))?;
        
        Ok(())
    }

    async fn purge(&mut self, log_id: LogIdOf<C>) -> Result<(), StorageError<C>> {
        tracing::debug!("delete_log: [0, {:?}]", log_id);

        // Write the last-purged log id before purging the logs.
        // The logs at and before last-purged log id will be ignored by openraft.
        // Therefore, there is no need to do it in a transaction.
        self.put_meta::<meta::LastPurged>(&log_id)?;

        let from = id_to_bin(0);
        let to = id_to_bin(log_id.index());

        //self.db.delete_range_cf(self.cf_logs(), &from, &to).map_err(|e| StorageError::write_logs(&e))?;

        let logs_tree = &self.logs;
        let entries = logs_tree.range::<&[u8], _>(from.as_slice()..=to.as_slice());
        let mut batch_del = sled::Batch::default();
        for entry_res in entries {
            let entry = entry_res.map_err(read_logs_err)?;
            batch_del.remove(entry.0);
        }
        logs_tree.apply_batch(batch_del).map_err(|e| StorageError::write_logs(&e))?;

        logs_tree.flush_async().await.map_err(|e| StorageError::write_logs(&e))?;
        // ??? Purging does not need to be persistent.
        Ok(())
    }
}

/// Metadata of a raft-store.
///
/// In raft, except logs and state machine, the store also has to store several piece of metadata.
/// This sub mod defines the key-value pairs of these metadata.
mod meta {
    use openraft::alias::LogIdOf;
    use openraft::alias::VoteOf;
    use openraft::AnyError;
    use openraft::ErrorSubject;
    use openraft::ErrorVerb;
    use openraft::RaftTypeConfig;
    use openraft::StorageError;

    /// Defines metadata key and value
    pub(crate) trait StoreMeta<C>
    where C: RaftTypeConfig
    {
        /// The key used to store in rocksdb
        const KEY: &'static str;

        /// The type of the value to store
        type Value: serde::Serialize + serde::de::DeserializeOwned;

        /// The subject this meta belongs to, and will be embedded into the returned storage error.
        fn subject(v: Option<&Self::Value>) -> ErrorSubject<C>;

        fn read_err(e: impl std::error::Error + 'static) -> StorageError<C> {
            StorageError::new(Self::subject(None), ErrorVerb::Read, AnyError::new(&e))
        }

        fn write_err(v: &Self::Value, e: impl std::error::Error + 'static) -> StorageError<C> {
            StorageError::new(Self::subject(Some(v)), ErrorVerb::Write, AnyError::new(&e))
        }
    }

    pub(crate) struct LastPurged {}
    pub(crate) struct Vote {}

    impl<C> StoreMeta<C> for LastPurged
    where C: RaftTypeConfig
    {
        const KEY: &'static str = "last_purged_log_id";
        type Value = LogIdOf<C>;

        fn subject(_v: Option<&Self::Value>) -> ErrorSubject<C> {
            ErrorSubject::Store
        }
    }
    impl<C> StoreMeta<C> for Vote
    where C: RaftTypeConfig
    {
        const KEY: &'static str = "vote";
        type Value = VoteOf<C>;

        fn subject(_v: Option<&Self::Value>) -> ErrorSubject<C> {
            ErrorSubject::Vote
        }
    }
}

/// converts an id to a byte vector for storing in the database.
/// Note that we're using big endian encoding to ensure correct sorting of keys
fn id_to_bin(id: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);
    buf.write_u64::<BigEndian>(id).unwrap();
    buf
}

fn bin_to_id(buf: &[u8]) -> u64 {
    (&buf[0..8]).read_u64::<BigEndian>().unwrap()
}

fn read_logs_err<C>(e: impl Error + 'static) -> StorageError<C>
where C: RaftTypeConfig {
    StorageError::read_logs(&e)
}
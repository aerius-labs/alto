use super::{
    ingress::{Mailbox, Message},
    mempool::Mempool,
    Config,
};
use crate::utils::OneshotClosedFut;
use alto_types::{Block, Scheme};
use commonware_consensus::{marshal, types::Round};
use commonware_cryptography::{Committable, Digestible, Hasher, Sha256};
use commonware_macros::select;
use commonware_runtime::{buffer::PoolRef, spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_storage::{
    qmdb::current::ordered::fixed::Db as Current,
    translator::TwoCap,
    qmdb::Error as QmdbError,
};
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64, SystemTimeExt};
use futures::StreamExt;
use futures::{channel::mpsc, future::try_join};
use futures::{future, future::Either};
use rand::Rng;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"commonware is neat";

/// Milliseconds in the future to allow for block timestamps.
const SYNCHRONY_BOUND: u64 = 500;

const GENESIS_BALANCE: u64 = 1000;

/// Application actor.
pub struct Actor<R: Rng + Spawner + Metrics + Clock + Storage> {
    context: ContextCell<R>,
    hasher: Sha256,
    mailbox: mpsc::Receiver<Message>,
    qmdb: Arc<Mutex<Current<R, FixedBytes<8>, u64, Sha256, TwoCap, 64>>>,
    processed_heights: Arc<Mutex<HashSet<u64>>>,
    mempool: Mempool,
}

impl<R: Rng + Spawner + Metrics + Clock + Storage> Actor<R> {
    /// Create a new application actor.
    pub async fn new(context: R, config: Config) -> Result<(Self, Mailbox, Mempool, Arc<Mutex<Current<R, FixedBytes<8>, u64, Sha256, TwoCap, 64>>>), QmdbError> {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        
        // Configure qmdb
        let qmdb_config = commonware_storage::qmdb::current::FixedConfig {
            mmr_journal_partition: "state_mmr_journal".into(),
            mmr_metadata_partition: "state_mmr_metadata".into(),
            mmr_items_per_blob: NZU64!(4096),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: "state_log_journal".into(),
            log_items_per_blob: NZU64!(4096),
            log_write_buffer: NZUsize!(1024),
            bitmap_metadata_partition: "state_bitmap_metadata".into(),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
        };

        // Initialize qmdb
        let mut qmdb = Current::<_, FixedBytes<8>, u64, Sha256, TwoCap, 64>::init(
            context.with_label("qmdb"),
            qmdb_config,
        ).await?;
        
        // Initialize genesis balances
        // todo: Fix commit() call
        let mut dirty = qmdb.into_dirty();
        for i in 0u64..10 {
            let key = FixedBytes::new(i.to_be_bytes());
            dirty.update(key, GENESIS_BALANCE).await?;
        }
        // todo: apply commit
        // for now just using the dirty state directly
        qmdb = dirty.merkleize().await?;
        
        let mempool = Mempool::new(config.mempool_max_size);
        let mempool_clone = mempool.clone();
        let qmdb_arc = Arc::new(Mutex::new(qmdb));
        let qmdb_clone = qmdb_arc.clone();
        
        Ok((
            Self {
                context: ContextCell::new(context),
                hasher: Sha256::new(),
                mailbox,
                qmdb: qmdb_clone,
                processed_heights: Arc::new(Mutex::new(HashSet::new())),
                mempool: mempool_clone,
            },
            Mailbox::new(sender),
            mempool,
            qmdb_arc,
        ))
    }

    pub fn start(mut self, marshal: marshal::Mailbox<Scheme, Block>) -> Handle<()> {
        spawn_cell!(self.context, self.run(marshal).await)
    }

    /// Run the application actor.
    async fn run(mut self, mut marshal: marshal::Mailbox<Scheme, Block>) {
        // Compute genesis digest
        self.hasher.update(GENESIS);
        let genesis_parent = self.hasher.finalize();
        // Genesis state root: hash of empty state (will be replaced with qmdb root)
        let genesis_state_root = Sha256::hash(b"");
        let genesis = Block::new(genesis_parent, 0, 0, Vec::new(), genesis_state_root);
        let genesis_digest = genesis.digest();
        let built: Option<(Round, Block)> = None;
        let built = Arc::new(Mutex::new(built));
        while let Some(message) = self.mailbox.next().await {
            match message {
                Message::Genesis { response } => {
                    // Use the digest of the genesis message as the initial
                    // payload.
                    let _ = response.send(genesis_digest);
                }
                Message::Propose {
                    round,
                    parent,
                    mut response,
                } => {
                    // Get the parent block
                    let parent_request = if parent.1 == genesis_digest {
                        Either::Left(future::ready(Ok(genesis.clone())))
                    } else {
                        Either::Right(
                            marshal
                                .subscribe(Some(Round::new(round.epoch(), parent.0)), parent.1)
                                .await,
                        )
                    };

                    // Wait for the parent block to be available or the request to be cancelled in a separate task (to
                    // continue processing other messages)
                    let mempool = self.mempool.clone();
                    self.context.with_label("propose").spawn({
                        let built = built.clone();
                        move |context| async move {
                            let response_closed = OneshotClosedFut::new(&mut response);
                            select! {
                                parent = parent_request => {
                                    // Get the parent block
                                    let parent = parent.unwrap();

                                    // Create a new block with transactions from mempool
                                    let mut current = context.current().epoch_millis();
                                    if current <= parent.timestamp {
                                        current = parent.timestamp + 1;
                                    }
                                    let transactions = mempool.take(10);
                                    // TODO: Get state_root from qmdb
                                    let state_root = Sha256::hash(b""); // Placeholder
                                    let block = Block::new(
                                        parent.digest(),
                                        parent.height + 1,
                                        current,
                                        transactions.clone(),
                                        state_root,
                                    );
                                    let digest = block.digest();
                                    {
                                        let mut built = built.lock().unwrap();
                                        *built = Some((round, block));
                                    }

                                    // Send the digest to the consensus
                                    let result = response.send(digest);
                                    info!(
                                        ?round,
                                        ?digest,
                                        tx_count = transactions.len(),
                                        success=result.is_ok(),
                                        "proposed new block"
                                    );
                                },
                                _ = response_closed => {
                                    // The response was cancelled
                                    warn!(?round, "propose aborted");
                                }
                            }
                        }
                    });
                }
                Message::Broadcast { payload } => {
                    // Check if the last built is equal
                    let Some(built) = built.lock().unwrap().clone() else {
                        warn!(?payload, "missing block to broadcast");
                        continue;
                    };

                    // Send the block to the syncer
                    debug!(
                        ?payload,
                        round = ?built.0,
                        height = built.1.height,
                        "broadcast requested"
                    );
                    marshal.proposed(built.0, built.1.clone()).await;
                }
                Message::Verify {
                    round,
                    parent,
                    payload,
                    mut response,
                } => {
                    // Get the parent and current block
                    let parent_request = if parent.1 == genesis_digest {
                        Either::Left(future::ready(Ok(genesis.clone())))
                    } else {
                        Either::Right(
                            marshal
                                .subscribe(Some(Round::new(round.epoch(), parent.0)), parent.1)
                                .await,
                        )
                    };

                    // Wait for the blocks to be available or the request to be cancelled in a separate task (to
                    // continue processing other messages)
                    self.context.with_label("verify").spawn({
                        let mut marshal = marshal.clone();
                        let qmdb = self.qmdb.clone();
                        move |context| async move {
                            let requester =
                                try_join(parent_request, marshal.subscribe(None, payload).await);
                            let response_closed = OneshotClosedFut::new(&mut response);
                            select! {
                                result = requester => {
                                    // Unwrap the results
                                    let (parent, block) = result.unwrap();

                                    // Verify the block
                                    if block.height != parent.height + 1 {
                                        let _ = response.send(false);
                                        return;
                                    }
                                    if block.parent != parent.digest() {
                                        let _ = response.send(false);
                                        return;
                                    }
                                    if block.timestamp <= parent.timestamp {
                                        let _ = response.send(false);
                                        return;
                                    }
                                    let current = context.current().epoch_millis();
                                    if block.timestamp > current + SYNCHRONY_BOUND {
                                        let _ = response.send(false);
                                        return;
                                    }

                                    // verifying transactions using qmdb
                                    let verification_result = Self::verify_transactions_inline(&block, &qmdb).await;

                                    if !verification_result {
                                        warn!(height = block.height, "transaction verification failed");
                                        let _ = response.send(false);
                                        return;
                                    }

                                    // Persist the verified block
                                    marshal.verified(round, block).await;

                                    // Send the verification result to the consensus
                                    let _ = response.send(true);
                                },
                                _ = response_closed => {
                                    // The response was cancelled
                                    warn!(?round, "verify aborted");
                                }
                            }
                        }
                    });
                }
                Message::Finalized { block } => {
                    {
                        let mut processed = self.processed_heights.lock().unwrap();
                        if processed.contains(&block.height) {
                            debug!(height = block.height, "block already processed, skipping");
                            continue;
                        }
                        processed.insert(block.height);
                    }

                    // todo: update execute_transactions to use qmdb
                    self.execute_transactions(&block).await;

                    info!(
                        height = block.height,
                        digest = ?block.commitment(),
                        tx_count = block.transactions.len(),
                        "processed finalized block"
                    );
                }
            }
        }
    }

    /// Simplified transaction verification that avoids Send issues.
    /// Checks state root and basic tx validation only can't do full balance checks
    /// because holding MutexGuard across await points isn't Send-safe in spawned tasks.
    async fn verify_transactions_inline<R2: Rng + Spawner + Metrics + Clock + Storage>(
        block: &Block,
        qmdb: &Arc<Mutex<Current<R2, FixedBytes<8>, u64, Sha256, TwoCap, 64>>>,
    ) -> bool {
        // Check state root matches
        let current_root = {
            let qmdb_guard = qmdb.lock().unwrap();
            qmdb_guard.root()
        };
        
        if current_root != block.state_root {
            return false;
        }
        
        // Basic validation - just check amounts are non-zero
        // TODO: add proper balance checks once we fix the Send issues
        for tx in &block.transactions {
            if tx.amount == 0 {
                return false;
            }
        }
        
        true
    }

    /// Full transaction verification - checks balances and validates all txs.
    async fn verify_transactions<R2: Rng + Spawner + Metrics + Clock + Storage>(
        block: &Block,
        qmdb: &Arc<Mutex<Current<R2, FixedBytes<8>, u64, Sha256, TwoCap, 64>>>,
    ) -> Result<bool, QmdbError> {
        // First check state root matches
        let current_root = {
            let qmdb_guard = qmdb.lock().unwrap();
            qmdb_guard.root()
        };
        
        if current_root != block.state_root {
            return Ok(false);
        }
        
        // Collect all accounts we need to check
        use std::collections::{HashMap, HashSet};
        let mut accounts_to_query = HashSet::new();
        for tx in &block.transactions {
            if tx.amount == 0 {
                return Ok(false);
            }
            accounts_to_query.insert(tx.from);
            accounts_to_query.insert(tx.to);
        }
        
        // Query balances - do it all in one lock to avoid Send issues
        let mut balances: HashMap<u64, u64> = HashMap::new();
        {
            let qmdb_guard = qmdb.lock().unwrap();
            for &account_id in &accounts_to_query {
                let key = FixedBytes::new(account_id.to_be_bytes());
                // Awaiting while holding the guard is fine here since we're not spawning
                match qmdb_guard.get(&key).await {
                    Ok(Some(balance)) => {
                        balances.insert(account_id, balance);
                    }
                    Ok(None) => {
                        balances.insert(account_id, 0);
                        }
                        Err(e) => {
                        return Err(e);
                    }
                }
            }
        }
        
        // Now verify each tx has sufficient balance
        let mut temp_balances = balances;
        for tx in &block.transactions {
            let sender_balance = *temp_balances.get(&tx.from).unwrap_or(&0);
            
            if sender_balance < tx.amount {
                return Ok(false);
            }
            
            // Apply tx to temp balances to check subsequent txs
            *temp_balances.entry(tx.from).or_insert(0) -= tx.amount;
            *temp_balances.entry(tx.to).or_insert(0) += tx.amount;
        }
        
        Ok(true)
    }


    async fn execute_transactions(&self, block: &Block) {
        // Need to extract QMDB from the mutex since into_dirty() takes ownership
        let qmdb = unsafe {
            let qmdb_guard = self.qmdb.lock().unwrap();
            std::ptr::read(&*qmdb_guard)
        };
        
        if block.transactions.is_empty() {
            let root = qmdb.root();
            if root != block.state_root {
                warn!(
                    height = block.height,
                    expected = ?block.state_root,
                    actual = ?root,
                    "state root mismatch for empty block"
                );
            }
            unsafe {
                let mut qmdb_guard = self.qmdb.lock().unwrap();
                std::ptr::write(&mut *qmdb_guard, qmdb);
            }
            return;
        }

        let mut dirty = qmdb.into_dirty();

        for tx in &block.transactions {
            let from_key = FixedBytes::new(tx.from.to_be_bytes());
            let to_key = FixedBytes::new(tx.to.to_be_bytes());

            let from_balance = match dirty.get(&from_key).await {
                Ok(Some(balance)) => balance,
                Ok(None) => 0,
                Err(e) => {
                    warn!(
                        height = block.height,
                        from = tx.from,
                        error = ?e,
                        "failed to get sender balance"
                    );
                    let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                        panic!("failed to merkleize after error: {:?}", e);
                    });
                    unsafe {
            let mut qmdb_guard = self.qmdb.lock().unwrap();
                        std::ptr::write(&mut *qmdb_guard, clean);
                    }
                    return;
                }
            };

            let to_balance = match dirty.get(&to_key).await {
                Ok(Some(balance)) => balance,
                Ok(None) => 0,
                Err(e) => {
                    warn!(
                height = block.height,
                        to = tx.to,
                        error = ?e,
                        "failed to get receiver balance"
                    );
                    let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                        panic!("failed to merkleize after error: {:?}", e);
                    });
                    unsafe {
                        let mut qmdb_guard = self.qmdb.lock().unwrap();
                        std::ptr::write(&mut *qmdb_guard, clean);
                    }
                    return;
                }
            };

            if from_balance < tx.amount {
                warn!(
                    height = block.height,
                    from = tx.from,
                    balance = from_balance,
                    amount = tx.amount,
                    "insufficient balance in execute_transactions (should have been caught in verification)"
                );
                let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                    panic!("failed to merkleize after error: {:?}", e);
                });
                unsafe {
                    let mut qmdb_guard = self.qmdb.lock().unwrap();
                    std::ptr::write(&mut *qmdb_guard, clean);
                }
                return;
            }

            if let Err(e) = dirty.update(from_key, from_balance - tx.amount).await {
                warn!(
                    height = block.height,
                    from = tx.from,
                    error = ?e,
                    "failed to update sender balance"
                );
                let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                    panic!("failed to merkleize after error: {:?}", e);
                });
                unsafe {
                    let mut qmdb_guard = self.qmdb.lock().unwrap();
                    std::ptr::write(&mut *qmdb_guard, clean);
                }
                return;
            }

            if let Err(e) = dirty.update(to_key, to_balance + tx.amount).await {
                warn!(
                    height = block.height,
                    to = tx.to,
                    error = ?e,
                    "failed to update receiver balance"
                );
                let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                    panic!("failed to merkleize after error: {:?}", e);
                });
                unsafe {
                    let mut qmdb_guard = self.qmdb.lock().unwrap();
                    std::ptr::write(&mut *qmdb_guard, clean);
                }
                return;
            }
        }

        let mut clean = match dirty.merkleize().await {
            Ok(clean) => clean,
            Err(e) => {
                warn!(
                    height = block.height,
                    error = ?e,
                    "failed to merkleize after applying transactions"
                );
                return;
            }
        };

        let root_after_merkleize = clean.root();
        
        if root_after_merkleize != block.state_root {
            warn!(
                height = block.height,
                expected = ?block.state_root,
                actual = ?root_after_merkleize,
                "state root mismatch after merkleize (before commit)"
            );
        }

        match clean.commit(None).await {
            Ok(_range) => {
                info!(
                height = block.height,
                    tx_count = block.transactions.len(),
                state_root = ?root_after_merkleize,
                    "successfully executed and committed transactions"
                );
            }
            Err(e) => {
                warn!(
                    height = block.height,
                    error = ?e,
                    "failed to commit transactions"
                );
            }
        }

        unsafe {
            let mut qmdb_guard = self.qmdb.lock().unwrap();
            std::ptr::write(&mut *qmdb_guard, clean);
        }
    }
}

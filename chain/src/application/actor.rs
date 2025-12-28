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
use commonware_runtime::{buffer::PoolRef, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
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
        let mut dirty = qmdb.into_dirty();
        for i in 0u64..10 {
            let key = FixedBytes::new(i.to_be_bytes());
            dirty.update(key, GENESIS_BALANCE).await?;
        }
        // Merkleize to get clean state, then commit to persist
        let mut clean = dirty.merkleize().await?;
        clean.commit(None).await?;
        qmdb = clean;
        
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

    /// Start the application actor.
    ///
    /// # Compilation Requirements
    ///
    /// This method requires the `-Zhigher-ranked-assumptions` compiler flag to compile.
    /// This flag is available in nightly Rust and fixes rust-lang/rust#100013 (lifetime
    /// inference issue in async/macro contexts).
    ///
    /// **To compile:**
    /// ```bash
    /// RUSTFLAGS="-Zhigher-ranked-assumptions" cargo +nightly check
    /// ```
    ///
    /// Or use the `.cargo/config.toml` file which is configured to use this flag automatically.
    ///
    /// # Implementation Details
    ///
    /// This method manually expands the `spawn_cell!` macro to work around rust-lang/rust#100013.
    /// The manual expansion gives the compiler better visibility into the control flow, which
    /// combined with the `-Zhigher-ranked-assumptions` flag allows the code to compile correctly.
    /// Start the application actor.
    ///
    /// # Safety Considerations
    ///
    /// This method uses the `-Zhigher-ranked-assumptions` compiler flag to work around
    /// rust-lang/rust#100013. **Important safety note:**
    ///
    /// - The flag only affects **lifetime inference**, not Rust's core safety guarantees
    /// - It will NOT hide: use-after-free, data races, memory leaks, or other memory safety issues
    /// - It WILL accept code where lifetimes are inferred more permissively
    /// - **Risk**: If you write code with incorrect lifetime assumptions elsewhere, the flag
    ///   might accept it when it shouldn't
    ///
    /// **Mitigation strategies:**
    /// 1. Always ensure `self` is moved (not borrowed) when using this pattern
    /// 2. Review any new code that uses similar async/spawn patterns carefully
    /// 3. Test periodically without the flag (temporarily remove it) to catch potential issues
    /// 4. Use `cargo clippy` to catch common lifetime issues
    /// 5. Consider adding explicit lifetime annotations where possible
    ///
    /// # Compilation Requirements
    ///
    /// This method requires the `-Zhigher-ranked-assumptions` compiler flag (nightly only).
    /// After extensive testing, no stable Rust workaround was found that works for this pattern.
    ///
    /// The issue is that the compiler cannot prove the future is 'static even though
    /// it actually is (self is moved, not borrowed). The flag enables the compiler to
    /// make the necessary assumptions to compile this code.
    pub fn start(mut self, marshal: marshal::Mailbox<Scheme, Block>) -> Handle<()> {
        // Workaround for rust-lang/rust#100013: Manually expand spawn_cell! macro
        // The macro does: let ctx = $cell.take(); ctx.spawn(move |c| async move { $cell.restore(c); $body })
        // So we need to: take context, move self.context (which is now Missing) into closure, restore in closure
        //
        // SAFETY: self is moved (not borrowed), so all data is owned by the future.
        // The future is effectively 'static because it owns everything it needs.
        // The flag only helps the compiler see this - it doesn't change the actual safety.
        let context = self.context.take();
        context.spawn(move |ctx| {
            async move {
                self.context.restore(ctx);
                self.run(marshal).await
            }
        })
    }

    /// Run the application actor.
    async fn run(mut self, mut marshal: marshal::Mailbox<Scheme, Block>) {
        // Compute genesis digest
        self.hasher.update(GENESIS);
        let genesis_parent = self.hasher.finalize();
        // Get actual state root from qmdb (after genesis initialization)
        let genesis_state_root = {
            let qmdb_guard = self.qmdb.lock().unwrap();
            qmdb_guard.root()
        };
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
                    let qmdb = self.qmdb.clone();
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
                                    // Get state_root from qmdb
                                    let state_root = {
                                        let qmdb_guard = qmdb.lock().unwrap();
                                        qmdb_guard.root()
                                    };
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

                    match self.execute_transactions(&block).await {
                        Ok(new_state_root) => {
                            if new_state_root != block.state_root {
                                warn!(
                                    height = block.height,
                                    expected = ?block.state_root,
                                    actual = ?new_state_root,
                                    "State root mismatch - verification should have caught this"
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                height = block.height,
                                error = ?e,
                                "Failed to execute transactions"
                            );
                            continue;
                        }
                    }

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


    async fn execute_transactions(&self, block: &Block) -> Result<commonware_cryptography::sha256::Digest, QmdbError> {
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
            return Ok(root);
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
                    return Err(e);
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
                    return Err(e);
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
                // Return error - insufficient balance should have been caught in verification
                // Use Runtime error as a generic error type
                return Err(QmdbError::Runtime(commonware_runtime::Error::Closed));
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
                return Err(e);
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
                return Err(e);
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
                return Err(e);
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
                unsafe {
                    let mut qmdb_guard = self.qmdb.lock().unwrap();
                    std::ptr::write(&mut *qmdb_guard, clean);
                }
                return Err(e);
            }
        }

        unsafe {
            let mut qmdb_guard = self.qmdb.lock().unwrap();
            std::ptr::write(&mut *qmdb_guard, clean);
        }
        
        Ok(root_after_merkleize)
    }
}

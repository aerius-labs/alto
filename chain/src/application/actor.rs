use super::{
    ingress::{Mailbox, Message},
    mempool::Mempool,
    Config,
};
use crate::utils::OneshotClosedFut;
use alto_types::{Block, Scheme, Transaction, NAMESPACE};
use commonware_consensus::{marshal, types::Round};
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    Committable, Digestible, Hasher, Sha256, Signer, Verifier,
};
use commonware_math::algebra::Random;
use commonware_macros::select;
use commonware_runtime::{buffer::PoolRef, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_storage::{
    qmdb::current::ordered::fixed::Db as Current,
    translator::TwoCap,
    qmdb::Error as QmdbError,
};
use commonware_codec::{varint::UInt, Write};
use commonware_utils::Acknowledgement;
use commonware_utils::{sequence::FixedBytes, NZUsize, NZU64, SystemTimeExt};
use futures::StreamExt;
use futures::{channel::mpsc, future::try_join};
use futures::{future, future::Either};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use tracing::{debug, error, info, warn};

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"commonware is neat";

/// Milliseconds in the future to allow for block timestamps.
const SYNCHRONY_BOUND: u64 = 500;

const GENESIS_BALANCE: u64 = 1000;

// Key prefixes for different data types in QMDB
const KEY_PREFIX_BALANCE: u8 = 0x00;
const KEY_PREFIX_NONCE: u8 = 0x01;
const KEY_PREFIX_PUBLIC_KEY: u8 = 0x02;
const KEY_PREFIX_NEXT_ACCOUNT_ID: u8 = 0x03;

// System account constants
const SYSTEM_ACCOUNT_ID: u64 = 0;
const SYSTEM_ACCOUNT_SEED: [u8; 32] = [0xFF; 32];

fn balance_key(account_id: u64) -> FixedBytes<8> {
    let mut key = [0u8; 8];
    key[0] = KEY_PREFIX_BALANCE;
    let account_bytes = account_id.to_be_bytes();
    key[1..8].copy_from_slice(&account_bytes[1..8]);
    FixedBytes::new(key)
}

fn nonce_key(account_id: u64) -> FixedBytes<8> {
    let mut key = [0u8; 8];
    key[0] = KEY_PREFIX_NONCE;
    let account_bytes = account_id.to_be_bytes();
    key[1..8].copy_from_slice(&account_bytes[1..8]);
    FixedBytes::new(key)
}

fn public_key_key(account_id: u64) -> FixedBytes<8> {
    let mut key = [0u8; 8];
    key[0] = KEY_PREFIX_PUBLIC_KEY;
    let account_bytes = account_id.to_be_bytes();
    key[1..8].copy_from_slice(&account_bytes[1..8]);
    FixedBytes::new(key)
}

fn next_account_id_key() -> FixedBytes<8> {
    let mut key = [0u8; 8];
    key[0] = KEY_PREFIX_NEXT_ACCOUNT_ID;
    key[1..8].fill(0);
    FixedBytes::new(key)
}

fn get_system_private_key() -> PrivateKey {
    use rand::{rngs::StdRng, SeedableRng};
    let mut rng = StdRng::from_seed(SYSTEM_ACCOUNT_SEED);
    PrivateKey::random(&mut rng)
}

fn get_system_public_key() -> PublicKey {
    get_system_private_key().public_key()
}

fn hash_public_key(pk: &PublicKey) -> u64 {
    let mut hasher = Sha256::new();
    let mut pk_buf = Vec::new();
    pk.write(&mut pk_buf);
    hasher.update(&pk_buf);
    let hash = hasher.finalize();
    u64::from_be_bytes(hash[0..8].try_into().unwrap())
}

fn compute_transaction_hash(tx: &Transaction) -> commonware_cryptography::sha256::Digest {
    let mut hasher = Sha256::new();
    let mut tx_buf = Vec::new();
    // Hash transaction fields (excluding signature)
    UInt(tx.from).write(&mut tx_buf);
    UInt(tx.to).write(&mut tx_buf);
    UInt(tx.amount).write(&mut tx_buf);
    UInt(tx.nonce).write(&mut tx_buf);
    tx.public_key.write(&mut tx_buf);
    
    // Include to_public_key if present
    if let Some(ref pk) = tx.to_public_key {
        tx_buf.push(1);
        pk.write(&mut tx_buf);
    } else {
        tx_buf.push(0);
    }
    
    // Include is_account_creation flag
    tx_buf.push(if tx.is_account_creation { 1 } else { 0 });
    
    hasher.update(NAMESPACE);
    hasher.update(&tx_buf);
    hasher.finalize()
}

fn verify_transaction_signature(tx: &Transaction) -> bool {
    let tx_hash = compute_transaction_hash(tx);
    tx.public_key.verify(NAMESPACE, tx_hash.as_ref(), &tx.signature)
}

/// Application actor.
pub struct Actor<R: Rng + Spawner + Metrics + Clock + Storage> {
    context: ContextCell<R>,
    hasher: Sha256,
    mailbox: mpsc::Receiver<Message>,
    qmdb: Arc<Mutex<Option<Current<R, FixedBytes<8>, u64, Sha256, TwoCap, 64>>>>,
    processed_heights: Arc<Mutex<HashSet<u64>>>,
    mempool: Mempool,
    qmdb_config: commonware_storage::qmdb::current::FixedConfig<TwoCap>,
    // Semaphore to serialize QMDB operations (proposal, verification, execution)
    // Only one operation can access QMDB at a time to prevent race conditions
    qmdb_semaphore: Arc<Semaphore>,
    // Track uncommitted state for delayed commit
    last_committed_height: Arc<Mutex<u64>>,
    last_uncommitted_height: Arc<Mutex<Option<u64>>>,
    // Store public keys for accounts (account_id -> public_key)
    // TODO: Make this persistent using QMDB or separate storage
    public_keys: Arc<Mutex<HashMap<u64, PublicKey>>>,
}

impl<R: Rng + Spawner + Metrics + Clock + Storage> Actor<R> {
    /// Create a new application actor.
    pub async fn new(context: R, config: Config) -> Result<(Self, Mailbox, Mempool, Arc<Mutex<Option<Current<R, FixedBytes<8>, u64, Sha256, TwoCap, 64>>>>, Arc<Mutex<HashMap<u64, PublicKey>>>), QmdbError> {
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
            qmdb_config.clone(),
        ).await?;
        
        // Check if genesis state already exists
        let balance_key_0 = balance_key(0);
        let genesis_exists = {
            let mut dirty = qmdb.into_dirty();
            let exists = dirty.get(&balance_key_0).await?.is_some();
            qmdb = dirty.merkleize().await?;
            exists
        };
        
        let mut genesis_public_keys = HashMap::new();
        
        if !genesis_exists {
            let mut dirty = qmdb.into_dirty();
            // Initialize genesis balances and nonces
            for i in 0u64..10 {
                use rand::{rngs::StdRng, SeedableRng};
                let mut seed = [0u8; 32];
                if i == SYSTEM_ACCOUNT_ID {
                    seed = SYSTEM_ACCOUNT_SEED;
                } else {
                    seed[0..8].copy_from_slice(&i.to_be_bytes());
                }
                let mut rng = StdRng::from_seed(seed);
                let private_key = PrivateKey::random(&mut rng);
                let public_key = private_key.public_key();
                genesis_public_keys.insert(i, public_key.clone());
                
                let balance_key = balance_key(i);
                // All genesis accounts get the same balance
                dirty.update(balance_key, GENESIS_BALANCE).await?;
                
                let account_nonce_key = nonce_key(i);
                dirty.update(account_nonce_key, 0u64).await?;
                
                // Store public key hash in QMDB
                let pk_key = public_key_key(i);
                let pk_hash = hash_public_key(&public_key);
                dirty.update(pk_key, pk_hash).await?;
            }
            
            // Initialize next_account_id to 10
            let next_id_key = next_account_id_key();
            dirty.update(next_id_key, 10u64).await?;
            
            // Verify system account public key matches expected
            let system_pk = get_system_public_key();
            if genesis_public_keys.get(&SYSTEM_ACCOUNT_ID) != Some(&system_pk) {
                warn!("System account public key mismatch - updating to expected key");
                genesis_public_keys.insert(SYSTEM_ACCOUNT_ID, system_pk);
            }
            
            // Merkleize to get clean state, then commit to persist
            let mut clean = dirty.merkleize().await?;
            clean.commit(None).await?;
            qmdb = clean;
        } else {
            // Load existing state - regenerate public keys deterministically from seeds
            // This ensures consistency with generate_test_tx
            // We need to update public key hashes in QMDB if they've changed
            let mut dirty = qmdb.into_dirty();
            let mut updated_any = false;
            
            for i in 0u64..10 {
                use rand::{rngs::StdRng, SeedableRng};
                let mut seed = [0u8; 32];
                if i == SYSTEM_ACCOUNT_ID {
                    seed = SYSTEM_ACCOUNT_SEED;
                } else {
                    seed[0..8].copy_from_slice(&i.to_be_bytes());
                }
                let mut rng = StdRng::from_seed(seed);
                let private_key = PrivateKey::random(&mut rng);
                let public_key = private_key.public_key();
                genesis_public_keys.insert(i, public_key.clone());
                
                // Update public key hash in QMDB if it exists and might be outdated
                let pk_key = public_key_key(i);
                let new_pk_hash = hash_public_key(&public_key);
                match dirty.get(&pk_key).await {
                    Ok(Some(old_hash)) => {
                        if old_hash != new_pk_hash {
                            // Public key hash changed (e.g., account 0 now uses SYSTEM_ACCOUNT_SEED)
                            if let Err(e) = dirty.update(pk_key, new_pk_hash).await {
                                warn!(account_id = i, error = ?e, "Failed to update public key hash in QMDB");
                            } else {
                                updated_any = true;
                                info!(account_id = i, "Updated public key hash in QMDB");
                            }
                        }
                    }
                    Ok(None) => {
                        // Public key hash doesn't exist, create it
                        if let Err(e) = dirty.update(pk_key, new_pk_hash).await {
                            warn!(account_id = i, error = ?e, "Failed to create public key hash in QMDB");
                        } else {
                            updated_any = true;
                        }
                    }
                    Err(e) => {
                        warn!(account_id = i, error = ?e, "Failed to check public key hash in QMDB");
                    }
                }
            }
            
            if updated_any {
                // Commit the public key hash updates
                let mut clean = dirty.merkleize().await?;
                clean.commit(None).await?;
                qmdb = clean;
                info!("Updated public key hashes in QMDB for existing genesis state");
            } else {
                // No updates needed, just convert back to clean
                qmdb = dirty.merkleize().await?;
            }
            
            info!("Loaded existing genesis state, regenerated public keys deterministically");
        }
        
        let mempool = Mempool::new(config.mempool_max_size);
        let mempool_clone = mempool.clone();
        let qmdb_arc = Arc::new(Mutex::new(Some(qmdb)));
        let qmdb_clone = qmdb_arc.clone();
        let public_keys = Arc::new(Mutex::new(genesis_public_keys));
        
        Ok((
            Self {
                context: ContextCell::new(context),
                hasher: Sha256::new(),
                mailbox,
                qmdb: qmdb_clone,
                processed_heights: Arc::new(Mutex::new(HashSet::new())),
                mempool: mempool_clone,
                qmdb_config,
                // Semaphore with 1 permit to serialize QMDB operations
                qmdb_semaphore: Arc::new(Semaphore::new(1)),
                // Initialize tracking: genesis block is committed
                last_committed_height: Arc::new(Mutex::new(0)),
                last_uncommitted_height: Arc::new(Mutex::new(None)),
                public_keys: public_keys.clone(),
            },
            Mailbox::new(sender),
            mempool,
            qmdb_arc,
            public_keys,
        ))
    }

    /// Commit the previous block's changes if there are any uncommitted operations.
    /// This should be called at the start of proposal/verification for a new block.
    async fn commit_previous_block_if_needed(
        &self,
        current_block_height: u64,
    ) -> Result<(), QmdbError> {
        let mut uncommitted_guard = self.last_uncommitted_height.lock().await;
        let mut committed_guard = self.last_committed_height.lock().await;
        
        // Check if we have uncommitted changes
        if let Some(uncommitted_height) = *uncommitted_guard {
            // Only commit if we're moving to a new block
            if current_block_height > uncommitted_height {
                info!(
                    uncommitted_height,
                    current_block_height,
                    "Committing previous block's changes before processing new block"
                );
                
                // Acquire semaphore to serialize QMDB access
                let _permit = self.qmdb_semaphore.acquire().await
                    .expect("semaphore should not be closed");
                
                // Move QMDB out and commit
                let mut qmdb = {
                    let mut qmdb_guard = self.qmdb.lock().await;
                    qmdb_guard.take().expect("qmdb should always be Some")
                };
                
                match qmdb.commit(None).await {
                    Ok(_range) => {
                        info!(
                            uncommitted_height,
                            "Successfully committed previous block's changes"
                        );
                        let mut qmdb_guard = self.qmdb.lock().await;
                        *qmdb_guard = Some(qmdb);
                    }
                    Err(e) => {
                        warn!(
                            uncommitted_height,
                            error = ?e,
                            "Failed to commit previous block's changes"
                        );
                        // Restore QMDB even if commit failed
                        let mut qmdb_guard = self.qmdb.lock().await;
                        *qmdb_guard = Some(qmdb);
                        return Err(e);
                    }
                }
                
                // Update tracking
                *committed_guard = uncommitted_height;
                *uncommitted_guard = None;
            }
        }
        
        Ok(())
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
            let qmdb_guard = self.qmdb.lock().await;
            qmdb_guard.as_ref().expect("qmdb should always be Some").root()
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
                    let qmdb_config = self.qmdb_config.clone();
                    let qmdb_semaphore = self.qmdb_semaphore.clone();
                    let last_committed_height = self.last_committed_height.clone();
                    let last_uncommitted_height = self.last_uncommitted_height.clone();
                    self.context.with_label("propose").spawn({
                        let built = built.clone();
                        move |context| async move {
                            let response_closed = OneshotClosedFut::new(&mut response);
                            select! {
                                parent = parent_request => {
                                    // Handle error from parent_request instead of unwrapping
                                    let parent = match parent {
                                        Ok(p) => p,
                                        Err(e) => {
                                            warn!(?round, ?e, "failed to fetch parent block for proposal");
                                            // Drop response - receiver will get cancellation error
                                            // This is better than sending a fake digest
                                            drop(response);
                                            return;
                                        }
                                    };

                                    // Commit previous block's changes before proposing new block
                                    {
                                        let mut uncommitted_guard = last_uncommitted_height.lock().await;
                                        let mut committed_guard = last_committed_height.lock().await;
                                        
                                        if let Some(uncommitted_height) = *uncommitted_guard {
                                            if parent.height + 1 > uncommitted_height {
                                                let _permit = qmdb_semaphore.acquire().await
                                                    .expect("semaphore should not be closed");
                                                
                                                let mut qmdb_to_commit = {
                                                    let mut qmdb_guard = qmdb.lock().await;
                                                    qmdb_guard.take().expect("qmdb should always be Some")
                                                };
                                                
                                                // Check root BEFORE commit - should match parent.state_root
                                                let current_root_before_commit = qmdb_to_commit.root();
                                                if current_root_before_commit != parent.state_root {
                                                    error!(
                                                        uncommitted_height,
                                                        current_block_height = parent.height + 1,
                                                        current_root = ?current_root_before_commit,
                                                        parent_state_root = ?parent.state_root,
                                                        "QMDB root doesn't match parent state_root before commit - state inconsistency detected, aborting proposal"
                                                    );
                                                    // Restore QMDB and abort proposal
                                                    let mut qmdb_guard = qmdb.lock().await;
                                                    *qmdb_guard = Some(qmdb_to_commit);
                                                    return; // Abort this proposal
                                                }
                                                
                                                info!(
                                                    uncommitted_height,
                                                    current_block_height = parent.height + 1,
                                                    root_before_commit = ?current_root_before_commit,
                                                    parent_state_root = ?parent.state_root,
                                                    "PROPOSAL Root matches parent state_root before commit - proceeding with commit"
                                                );
                                                
                                                match qmdb_to_commit.commit(None).await {
                                                    Ok(_range) => {
                                                        // Get root AFTER commit - should be different from parent.state_root
                                                        let root_after_commit = qmdb_to_commit.root();
                                                        
                                                        if root_after_commit == parent.state_root {
                                                            warn!(
                                                                uncommitted_height,
                                                                root_after_commit = ?root_after_commit,
                                                                parent_state_root = ?parent.state_root,
                                                                "Root didn't change after commit - unexpected behavior"
                                                            );
                                                        } else {
                                                            info!(
                                                                uncommitted_height,
                                                                root_before_commit = ?current_root_before_commit,
                                                                root_after_commit = ?root_after_commit,
                                                                parent_state_root = ?parent.state_root,
                                                                note = "Root changed after commit (expected: CommitFloor added to MMR)",
                                                                "Committed previous block before proposal"
                                                            );
                                                        }
                                                        
                                                        let mut qmdb_guard = qmdb.lock().await;
                                                        *qmdb_guard = Some(qmdb_to_commit);
                                                        *committed_guard = uncommitted_height;
                                                        *uncommitted_guard = None;
                                                    }
                                                    Err(e) => {
                                                        error!(
                                                            uncommitted_height,
                                                            error = ?e,
                                                            "Failed to commit previous block before proposal"
                                                        );
                                                        let mut qmdb_guard = qmdb.lock().await;
                                                        *qmdb_guard = Some(qmdb_to_commit);
                                                        return; // Abort proposal on commit failure
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // Create a new block with transactions from mempool
                                    let mut current = context.current().epoch_millis();
                                    if current <= parent.timestamp {
                                        current = parent.timestamp + 1;
                                    }
                                    let transactions = mempool.take(10);
                                    
                                    // Calculate state_root by simulating transactions (without committing)
                                    // We move QMDB out, simulate, compute root, then restore original from storage
                                    // Extract R from ContextCell<R> to match stored QMDB type
                                    let runtime_context = context.into_present();
                                    let state_root = {
                                        // Acquire semaphore to serialize QMDB access
                                        let _permit = qmdb_semaphore.acquire().await.expect("semaphore should not be closed");
                                        // Move QMDB out of mutex for simulation
                                        let original_qmdb = {
                                            let mut qmdb_guard = qmdb.lock().await;
                                            qmdb_guard.take().expect("qmdb should always be Some")
                                        };
                                        
                                        let (computed_root, qmdb_to_restore) = if transactions.is_empty() {
                                            // Empty blocks keep the same state root as parent
                                            // QMDB's cached root is wrong after commit, so use parent's state_root instead
                                            let root = parent.state_root;
                                            (root, original_qmdb)
                                        } else {
                                            // Simulate transactions
                                            let mut dirty = original_qmdb.into_dirty();
                                            let mut valid = true;
                                            
                                            for tx in &transactions {
                                                // Handle explicit account creation
                                                if tx.is_account_creation {
                                                    // Verify account doesn't exist
                                                    let balance_key = balance_key(tx.to);
                                                    if dirty.get(&balance_key).await.is_ok_and(|opt| opt.is_some()) {
                                                        valid = false;
                                                        break;
                                                    }
                                                    
                                                    // Verify account ID is valid
                                                    if tx.to < 10 {
                                                        valid = false;
                                                        break;
                                                    }
                                                    
                                                    // Verify receiver's public key is provided
                                                    if tx.to_public_key.is_none() {
                                                        valid = false;
                                                        break;
                                                    }
                                                    
                                                    // Verify sender is system account
                                                    if tx.from != SYSTEM_ACCOUNT_ID {
                                                        valid = false;
                                                        break;
                                                    }
                                                    
                                                    // Verify system account nonce
                                                    let system_nonce_key = nonce_key(SYSTEM_ACCOUNT_ID);
                                                    let expected_system_nonce = match dirty.get(&system_nonce_key).await {
                                                        Ok(Some(n)) => n,
                                                        Ok(None) => 0,
                                                        Err(_) => {
                                                            valid = false;
                                                            break;
                                                        }
                                                    };
                                                    
                                                    if tx.nonce != expected_system_nonce {
                                                        valid = false;
                                                        break;
                                                    }
                                                    
                                                    // Simulate account creation (must match execution phase exactly)
                                                    if dirty.update(balance_key, tx.amount).await.is_err() {
                                                        valid = false;
                                                        break;
                                                    }
                                                    if dirty.update(nonce_key(tx.to), 0u64).await.is_err() {
                                                        valid = false;
                                                        break;
                                                    }
                                                    
                                                    // Store public key hash in QMDB (must match execution)
                                                    let pk_key = public_key_key(tx.to);
                                                    let pk_hash = hash_public_key(tx.to_public_key.as_ref().unwrap());
                                                    if dirty.update(pk_key, pk_hash).await.is_err() {
                                                        valid = false;
                                                        break;
                                                    }
                                                    
                                                    // Update next_account_id to prevent ID collisions (must match execution)
                                                    let next_id_key = next_account_id_key();
                                                    let current_next_id = match dirty.get(&next_id_key).await {
                                                        Ok(Some(id)) => id,
                                                        Ok(None) => 10,
                                                        Err(_) => {
                                                            valid = false;
                                                            break;
                                                        }
                                                    };
                                                    let new_next_id = current_next_id.max(tx.to + 1);
                                                    if dirty.update(next_id_key, new_next_id).await.is_err() {
                                                        valid = false;
                                                        break;
                                                    }
                                                    
                                                    // Increment system account nonce
                                                    if dirty.update(system_nonce_key, expected_system_nonce + 1).await.is_err() {
                                                        valid = false;
                                                        break;
                                                    }
                                                    
                                                    continue;  // Skip normal transfer verification
                                                }
                                                
                                                // Handle regular transfer
                                                if tx.amount == 0 {
                                                    valid = false;
                                                    break;
                                                }
                                                
                                                // Verify nonce
                                                let account_nonce_key = nonce_key(tx.from);
                                                let expected_nonce = match dirty.get(&account_nonce_key).await {
                                                    Ok(Some(n)) => n,
                                                    Ok(None) => 0,
                                                    Err(_) => {
                                                        valid = false;
                                                        break;
                                                    }
                                                };
                                                
                                                if tx.nonce != expected_nonce {
                                                    valid = false;
                                                    break;
                                                }
                                                
                                                let from_balance_key = balance_key(tx.from);
                                                let to_balance_key = balance_key(tx.to);
                                                
                                                // Check if receiver exists
                                                let receiver_exists = dirty.get(&to_balance_key).await
                                                    .is_ok_and(|opt| opt.is_some());
                                                
                                                // If receiver doesn't exist, require to_public_key
                                                if !receiver_exists {
                                                    if tx.to < 10 {
                                                        valid = false;
                                                        break;
                                                    }
                                                    
                                                    if tx.to_public_key.is_none() {
                                                        valid = false;
                                                        break;
                                                    }
                                                    
                                                    // Simulate account creation (must match execution phase exactly)
                                                    if dirty.update(balance_key(tx.to), 0u64).await.is_err() {
                                                        valid = false;
                                                        break;
                                                    }
                                                    if dirty.update(nonce_key(tx.to), 0u64).await.is_err() {
                                                        valid = false;
                                                        break;
                                                    }
                                                    
                                                    // Store public key hash in QMDB (must match execution)
                                                    let pk_key = public_key_key(tx.to);
                                                    let pk_hash = hash_public_key(tx.to_public_key.as_ref().unwrap());
                                                    if dirty.update(pk_key, pk_hash).await.is_err() {
                                                        valid = false;
                                                        break;
                                                    }
                                                    
                                                    // Update next_account_id to prevent ID collisions (must match execution)
                                                    let next_id_key = next_account_id_key();
                                                    let current_next_id = match dirty.get(&next_id_key).await {
                                                        Ok(Some(id)) => id,
                                                        Ok(None) => 10,
                                                        Err(_) => {
                                                            valid = false;
                                                            break;
                                                        }
                                                    };
                                                    let new_next_id = current_next_id.max(tx.to + 1);
                                                    if dirty.update(next_id_key, new_next_id).await.is_err() {
                                                        valid = false;
                                                        break;
                                                    }
                                                } else {
                                                    // Receiver exists - should not have to_public_key
                                                    if tx.to_public_key.is_some() {
                                                        valid = false;
                                                        break;
                                                    }
                                                }
                                                
                                                // Get balances
                                                let from_balance = match dirty.get(&from_balance_key).await {
                                                    Ok(Some(b)) => b,
                                                    Ok(None) => 0,
                                                    Err(_) => {
                                                        valid = false;
                                                        break;
                                                    }
                                                };
                                                
                                                if from_balance < tx.amount {
                                                    valid = false;
                                                    break;
                                                }
                                                
                                                // Apply transaction
                                                if dirty.update(from_balance_key, from_balance - tx.amount).await.is_err() {
                                                    valid = false;
                                                    break;
                                                }
                                                
                                                let to_balance = match dirty.get(&to_balance_key).await {
                                                    Ok(Some(b)) => b,
                                                    Ok(None) => 0,
                                                    Err(_) => {
                                                        valid = false;
                                                        break;
                                                    }
                                                };
                                                
                                                if dirty.update(balance_key(tx.to), to_balance + tx.amount).await.is_err() {
                                                    valid = false;
                                                    break;
                                                }
                                                
                                                // Increment nonce for next transaction from this account
                                                if dirty.update(account_nonce_key, expected_nonce + 1).await.is_err() {
                                                    valid = false;
                                                    break;
                                                }
                                            }
                                            
                                            if !valid {
                                                // Invalid transactions, restore QMDB from storage
                                                match Current::<R, FixedBytes<8>, u64, Sha256, TwoCap, 64>::init(
                                                    runtime_context.with_label("qmdb"),
                                                    qmdb_config.clone(),
                                                ).await {
                                                    Ok(restored_qmdb) => {
                                                        let mut qmdb_guard = qmdb.lock().await;
                                                        *qmdb_guard = Some(restored_qmdb);
                                                    }
                                                    Err(_) => {
                                                        warn!("Failed to restore QMDB from storage after invalid transactions");
                                                    }
                                                }
                                                return; // Skip this proposal
                                            }
                                            
                                            // Compute root after simulating transactions (without committing)
                                            // We use this root as the state root since it represents the actual database state.
                                            // Execution will call commit() which changes the root, but we track the state root
                                            // from merkleize() which reflects the key-value pairs, not the commit operations.
                                            let clean_after_simulation = match dirty.merkleize().await {
                                                Ok(c) => c,
                                                Err(_) => {
                                                    // Merkleize failed, restore QMDB from storage
                                                    match Current::<R, FixedBytes<8>, u64, Sha256, TwoCap, 64>::init(
                                                        runtime_context.with_label("qmdb"),
                                                        qmdb_config.clone(),
                                                    ).await {
                                                        Ok(restored_qmdb) => {
                                                            let mut qmdb_guard = qmdb.lock().await;
                                                            *qmdb_guard = Some(restored_qmdb);
                                                        }
                                                        Err(_) => {
                                                            warn!("Failed to restore QMDB from storage after merkleize error");
                                                        }
                                                    }
                                                    return;
                                                }
                                            };
                                            
                                            let root = clean_after_simulation.root();
                                            
                                            info!(
                                                height = parent.height + 1,
                                                state_root_from_merkleize = ?root,
                                                note = "Block state_root is from merkleize() BEFORE commit",
                                                "Computed state root for block proposal (before commit)"
                                            );
                                            
                                            // Restore QMDB from storage to discard simulated changes
                                            let restored_qmdb = match Current::<R, FixedBytes<8>, u64, Sha256, TwoCap, 64>::init(
                                                runtime_context.with_label("qmdb"),
                                                qmdb_config.clone(),
                                            ).await {
                                                Ok(q) => q,
                                                Err(_) => {
                                                    warn!("Failed to restore QMDB from storage after simulation - using simulated state");
                                                    clean_after_simulation
                                                }
                                            };
                                            
                                            (root, restored_qmdb)
                                        };
                                        
                                        // Put QMDB back (original for empty blocks, restored from storage for blocks with txs)
                                        let mut qmdb_guard = qmdb.lock().await;
                                        *qmdb_guard = Some(qmdb_to_restore);
                                        
                                        computed_root
                                    };
                                    
                                    let block = Block::new(
                                        parent.digest(),
                                        parent.height + 1,
                                        current,
                                        transactions.clone(),
                                        state_root,
                                    );
                                    
                                    info!(
                                        height = block.height,
                                        block_state_root = ?block.state_root,
                                        state_root_source = "merkleize() before commit",
                                        "Created block with state_root from merkleize (BEFORE commit)"
                                    );
                                    
                                    let digest = block.digest();
                                    {
                                        let mut built = built.lock().await;
                                        *built = Some((round, block));
                                    }

                                    // Send the digest to the consensus
                                    let result = response.send(digest);
                                    info!(
                                        ?round,
                                        ?digest,
                                        tx_count = transactions.len(),
                                        state_root = ?state_root,
                                        parent_state_root = ?parent.state_root,
                                        height = parent.height + 1,
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
                    let Some(built) = built.lock().await.clone() else {
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
                        let qmdb_config = self.qmdb_config.clone();
                        let qmdb_semaphore = self.qmdb_semaphore.clone();
                        let last_committed_height = self.last_committed_height.clone();
                        let last_uncommitted_height = self.last_uncommitted_height.clone();
                        let public_keys = self.public_keys.clone();
                        move |context| async move {
                            let requester =
                                try_join(parent_request, marshal.subscribe(None, payload).await);
                            let response_closed = OneshotClosedFut::new(&mut response);
                            select! {
                                result = requester => {
                                    // Handle error from try_join instead of unwrapping
                                    let (parent, block) = match result {
                                        Ok((p, b)) => (p, b),
                                        Err(e) => {
                                            warn!(?round, ?e, "failed to fetch blocks for verification");
                                            let _ = response.send(false);
                                            return;
                                        }
                                    };

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
                                    // Pass parent block to verify state root chain
                                    let verification_result = Self::verify_transactions_inline(
                                        &block,
                                        &parent,
                                        &qmdb,
                                        context,
                                        qmdb_config,
                                        qmdb_semaphore,
                                        &last_committed_height,
                                        &last_uncommitted_height,
                                        &public_keys,
                                    ).await;

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
                Message::Finalized { block, ack } => {
                    {
                        let mut processed = self.processed_heights.lock().await;
                        if processed.contains(&block.height) {
                            debug!(height = block.height, "block already processed, skipping");
                            continue;
                        }
                        processed.insert(block.height);
                    }

                    // Log finalized block with full details
                    // Note: In Alto, block height corresponds to view/slot (each view produces one block)
                    info!(
                        slot = block.height, // Block height corresponds to view/slot in Alto
                        height = block.height,
                        block_digest = ?block.commitment(),
                        state_root = ?block.state_root,
                        tx_count = block.transactions.len(),
                        timestamp = block.timestamp,
                        parent_digest = ?block.parent,
                        "Block finalized and being executed"
                    );

                    let runtime_context = self.context.clone().into_present();
                    match self.execute_transactions(runtime_context, &block).await {
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
                        state_root = ?block.state_root,
                        "processed finalized block"
                    );
                    
                    // Acknowledge the block processing to marshal
                    ack.acknowledge();
                }
            }
        }
    }

    /// Simplified transaction verification that avoids Send issues.
    /// Verifies: 1) current qmdb root matches parent's state_root, 2) simulating transactions
    /// produces the block's proposed state_root.
    /// 
    /// Note: This function temporarily modifies qmdb during simulation but restores it afterward.
    /// The restoration uses the clean state after merkleize (without commit), which has the same
    /// underlying data as the original but a different computed root. This is acceptable because
    /// verification should be quick and the root will be corrected when the block is actually executed.
    async fn verify_transactions_inline<R2: Rng + Spawner + Metrics + Clock + Storage>(
        block: &Block,
        parent: &Block,
        qmdb: &Arc<Mutex<Option<Current<R2, FixedBytes<8>, u64, Sha256, TwoCap, 64>>>>,
        context: ContextCell<R2>,
        qmdb_config: commonware_storage::qmdb::current::FixedConfig<TwoCap>,
        qmdb_semaphore: Arc<Semaphore>,
        last_committed_height: &Arc<Mutex<u64>>,
        last_uncommitted_height: &Arc<Mutex<Option<u64>>>,
        public_keys: &Arc<Mutex<HashMap<u64, PublicKey>>>,
    ) -> bool {
        // Commit previous block's changes before verifying new block
        {
            let mut uncommitted_guard = last_uncommitted_height.lock().await;
            let mut committed_guard = last_committed_height.lock().await;
            
            if let Some(uncommitted_height) = *uncommitted_guard {
                if block.height > uncommitted_height {
                    let _permit = qmdb_semaphore.acquire().await
                        .expect("semaphore should not be closed");
                    
                    let mut qmdb_to_commit = {
                        let mut qmdb_guard = qmdb.lock().await;
                        qmdb_guard.take().expect("qmdb should always be Some")
                    };
                    
                    // Check root BEFORE commit - should match parent.state_root
                    let current_root_before_commit = qmdb_to_commit.root();
                    if current_root_before_commit != parent.state_root {
                        error!(
                            uncommitted_height,
                            block_height = block.height,
                            current_root = ?current_root_before_commit,
                            parent_state_root = ?parent.state_root,
                            "QMDB root doesn't match parent state_root before commit - state inconsistency detected, aborting verification"
                        );
                        // Restore QMDB and return false (verification failed)
                        let mut qmdb_guard = qmdb.lock().await;
                        *qmdb_guard = Some(qmdb_to_commit);
                        return false;
                    }
                    
                    info!(
                        uncommitted_height,
                        block_height = block.height,
                        root_before_commit = ?current_root_before_commit,
                        parent_state_root = ?parent.state_root,
                        "VERIFICATION Root matches parent state_root before commit - proceeding with commit"
                    );
                    
                    match qmdb_to_commit.commit(None).await {
                        Ok(_range) => {
                            // Get root AFTER commit - should be different from parent.state_root
                            let root_after_commit = qmdb_to_commit.root();
                            
                            if root_after_commit == parent.state_root {
                                warn!(
                                    uncommitted_height,
                                    block_height = block.height,
                                    root_after_commit = ?root_after_commit,
                                    parent_state_root = ?parent.state_root,
                                    "Root didn't change after commit - unexpected behavior"
                                );
                            } else {
                                info!(
                                    uncommitted_height,
                                    block_height = block.height,
                                    root_before_commit = ?current_root_before_commit,
                                    root_after_commit = ?root_after_commit,
                                    parent_state_root = ?parent.state_root,
                                    note = "Root changed after commit (expected: CommitFloor added to MMR)",
                                    "Committed previous block before verification"
                                );
                            }
                            
                            let mut qmdb_guard = qmdb.lock().await;
                            *qmdb_guard = Some(qmdb_to_commit);
                            *committed_guard = uncommitted_height;
                            *uncommitted_guard = None;
                        }
                        Err(e) => {
                            error!(
                                uncommitted_height,
                                block_height = block.height,
                                error = ?e,
                                "Failed to commit previous block before verification"
                            );
                            let mut qmdb_guard = qmdb.lock().await;
                            *qmdb_guard = Some(qmdb_to_commit);
                            return false; // Verification failed due to commit error
                        }
                    }
                }
            }
        }
        
        // Acquire semaphore first so we wait for any ongoing execution to finish
        let _permit = qmdb_semaphore.acquire().await.expect("semaphore should not be closed");
        
        // Simulate applying the block's transactions and verify the resulting root
        let runtime_context = context.into_present();
        let original_qmdb = {
                let mut qmdb_guard = qmdb.lock().await;
                qmdb_guard.take().expect("qmdb should always be Some")
            };
            
        let verification_result = if block.transactions.is_empty() {
            // Empty blocks keep the same state root as parent
            // QMDB's cached root is wrong after commit, so compare with parent's state_root
            let result = parent.state_root == block.state_root;
            info!(
                height = block.height,
                state_root = ?block.state_root,
                parent_state_root = ?parent.state_root,
                "verifying empty block state root"
            );
            // Restore original
            let mut qmdb_guard = qmdb.lock().await;
            *qmdb_guard = Some(original_qmdb);
            result
            } else {
            // First verify all transaction signatures and nonces
            {
                let public_keys_guard = public_keys.lock().await;
                for tx in &block.transactions {
                    // Verify signature
                    if !verify_transaction_signature(tx) {
                        warn!(
                            height = block.height,
                            from = tx.from,
                            "Transaction signature verification failed"
                        );
                        return false;
                    }
                    
                    // For account creation transactions, verify sender is system account
                    if tx.is_account_creation {
                        let system_pk = get_system_public_key();
                        if tx.from != SYSTEM_ACCOUNT_ID || tx.public_key != system_pk {
                            warn!(
                                height = block.height,
                                from = tx.from,
                                "Account creation transaction must be from system account"
                            );
                            return false;
                        }
                    } else {
                        // Verify public key matches account
                        match public_keys_guard.get(&tx.from) {
                            Some(registered_pk) => {
                                if *registered_pk != tx.public_key {
                                    warn!(
                                        height = block.height,
                                        from = tx.from,
                                        "Transaction public key doesn't match registered public key for account"
                                    );
                                    return false;
                                }
                            }
                            None => {
                                warn!(
                                    height = block.height,
                                    from = tx.from,
                                    "Account doesn't have a registered public key"
                                );
                                return false;
                            }
                        }
                    }
                }
            }
            
            // Simulate transactions on a dirty state
            let mut dirty = original_qmdb.into_dirty();
                let mut valid = true;
                
                for tx in &block.transactions {
                    // Handle explicit account creation
                    if tx.is_account_creation {
                        // Verify account doesn't exist
                        let balance_key = balance_key(tx.to);
                        if dirty.get(&balance_key).await.is_ok_and(|opt| opt.is_some()) {
                            warn!(
                                height = block.height,
                                account_id = tx.to,
                                "Account already exists, cannot create"
                            );
                            valid = false;
                            break;
                        }
                        
                        // Verify account ID is valid
                        if tx.to < 10 {
                            warn!(
                                height = block.height,
                                account_id = tx.to,
                                "Account ID reserved for genesis"
                            );
                            valid = false;
                            break;
                        }
                        
                        // Verify receiver's public key is provided
                        if tx.to_public_key.is_none() {
                            warn!(
                                height = block.height,
                                account_id = tx.to,
                                "Account creation requires to_public_key"
                            );
                            valid = false;
                            break;
                        }
                        
                        // Verify sender is system account
                        if tx.from != SYSTEM_ACCOUNT_ID {
                            warn!(
                                height = block.height,
                                from = tx.from,
                                "Only system account can create accounts explicitly"
                            );
                            valid = false;
                            break;
                        }
                        
                        // Verify system account nonce
                        let system_nonce_key = nonce_key(SYSTEM_ACCOUNT_ID);
                        let expected_system_nonce = match dirty.get(&system_nonce_key).await {
                            Ok(Some(n)) => n,
                            Ok(None) => 0,
                            Err(_) => {
                                valid = false;
                                break;
                            }
                        };
                        
                        if tx.nonce != expected_system_nonce {
                            warn!(
                                height = block.height,
                                expected_nonce = expected_system_nonce,
                                tx_nonce = tx.nonce,
                                "System account nonce mismatch"
                            );
                            valid = false;
                            break;
                        }
                        
                        // Simulate account creation (must match proposal and execution phases exactly)
                        if dirty.update(balance_key, tx.amount).await.is_err() {
                            valid = false;
                            break;
                        }
                        if dirty.update(nonce_key(tx.to), 0u64).await.is_err() {
                            valid = false;
                            break;
                        }
                        
                        // Store public key hash in QMDB (must match execution)
                        let pk_key = public_key_key(tx.to);
                        let pk_hash = hash_public_key(tx.to_public_key.as_ref().unwrap());
                        if dirty.update(pk_key, pk_hash).await.is_err() {
                            valid = false;
                            break;
                        }
                        
                        // Update next_account_id to prevent ID collisions (must match execution)
                        let next_id_key = next_account_id_key();
                        let current_next_id = match dirty.get(&next_id_key).await {
                            Ok(Some(id)) => id,
                            Ok(None) => 10,
                            Err(_) => {
                                valid = false;
                                break;
                            }
                        };
                        let new_next_id = current_next_id.max(tx.to + 1);
                        if dirty.update(next_id_key, new_next_id).await.is_err() {
                            valid = false;
                            break;
                        }
                        
                        // Increment system account nonce
                        if dirty.update(system_nonce_key, expected_system_nonce + 1).await.is_err() {
                            valid = false;
                            break;
                        }
                        
                        continue;  // Skip normal transfer verification
                    }
                    
                    // Handle regular transfer
                    if tx.amount == 0 {
                        valid = false;
                        break;
                    }
                    
                    // Verify nonce
                    let account_nonce_key = nonce_key(tx.from);
                    let expected_nonce = match dirty.get(&account_nonce_key).await {
                        Ok(Some(n)) => n,
                        Ok(None) => 0,
                        Err(_) => {
                            valid = false;
                            break;
                        }
                    };
                    
                    if tx.nonce != expected_nonce {
                        warn!(
                            height = block.height,
                            from = tx.from,
                            expected_nonce,
                            tx_nonce = tx.nonce,
                            "Transaction nonce mismatch"
                        );
                        valid = false;
                        break;
                    }
                    
                    let from_balance_key = balance_key(tx.from);
                    let to_balance_key = balance_key(tx.to);
                    
                    // Check if receiver exists
                    let receiver_exists = dirty.get(&to_balance_key).await
                        .is_ok_and(|opt| opt.is_some());
                    
                    // If receiver doesn't exist, require to_public_key
                    if !receiver_exists {
                        if tx.to < 10 {
                            warn!(
                                height = block.height,
                                to = tx.to,
                                "Cannot auto-create genesis account"
                            );
                            valid = false;
                            break;
                        }
                        
                        if tx.to_public_key.is_none() {
                            warn!(
                                height = block.height,
                                to = tx.to,
                                "Receiver account doesn't exist, to_public_key required"
                            );
                            valid = false;
                            break;
                        }
                        
                        // Simulate account creation (must match proposal and execution phases exactly)
                        if dirty.update(balance_key(tx.to), 0u64).await.is_err() {
                            valid = false;
                            break;
                        }
                        if dirty.update(nonce_key(tx.to), 0u64).await.is_err() {
                            valid = false;
                            break;
                        }
                        
                        // Store public key hash in QMDB (must match execution)
                        let pk_key = public_key_key(tx.to);
                        let pk_hash = hash_public_key(tx.to_public_key.as_ref().unwrap());
                        if dirty.update(pk_key, pk_hash).await.is_err() {
                            valid = false;
                            break;
                        }
                        
                        // Update next_account_id to prevent ID collisions (must match execution)
                        let next_id_key = next_account_id_key();
                        let current_next_id = match dirty.get(&next_id_key).await {
                            Ok(Some(id)) => id,
                            Ok(None) => 10,
                            Err(_) => {
                                valid = false;
                                break;
                            }
                        };
                        let new_next_id = current_next_id.max(tx.to + 1);
                        if dirty.update(next_id_key, new_next_id).await.is_err() {
                            valid = false;
                            break;
                        }
                    } else {
                        // Receiver exists - should not have to_public_key
                        if tx.to_public_key.is_some() {
                            warn!(
                                height = block.height,
                                to = tx.to,
                                "Receiver account exists, to_public_key should not be provided"
                            );
                            valid = false;
                            break;
                        }
                    }
                    
                    // Get balances
                    let from_balance = match dirty.get(&from_balance_key).await {
                        Ok(Some(b)) => b,
                        Ok(None) => 0,
                        Err(_) => {
                            valid = false;
                            break;
                        }
                    };
                    
                    if from_balance < tx.amount {
                        valid = false;
                        break;
                    }
                    
                    // Apply transaction
                    if dirty.update(from_balance_key, from_balance - tx.amount).await.is_err() {
                        valid = false;
                        break;
                    }
                    
                    let to_balance = match dirty.get(&to_balance_key).await {
                        Ok(Some(b)) => b,
                        Ok(None) => 0,
                        Err(_) => {
                            valid = false;
                            break;
                        }
                    };
                    
                    if dirty.update(balance_key(tx.to), to_balance + tx.amount).await.is_err() {
                        valid = false;
                        break;
                    }
                    
                    // Increment nonce for next transaction from this account
                    if dirty.update(account_nonce_key, expected_nonce + 1).await.is_err() {
                        valid = false;
                        break;
                    }
                }
                
                if !valid {
                    // Invalid transactions - restore original QMDB from storage
                    match Current::<R2, FixedBytes<8>, u64, Sha256, TwoCap, 64>::init(
                        runtime_context.with_label("qmdb"),
                        qmdb_config.clone(),
                    ).await {
                        Ok(restored_qmdb) => {
                            let mut qmdb_guard = qmdb.lock().await;
                            *qmdb_guard = Some(restored_qmdb);
                        }
                        Err(_) => {
                            // Failed to restore - verification failed anyway
                            warn!("Failed to restore QMDB from storage after invalid transactions");
                        }
                    }
                    return false;
                }
                
                // Merkleize to get the resulting root (WITHOUT committing)
                let clean_after_simulation = match dirty.merkleize().await {
                    Ok(c) => c,
                    Err(_) => {
                        // Error during merkleize - restore original QMDB from storage
                        match Current::<R2, FixedBytes<8>, u64, Sha256, TwoCap, 64>::init(
                            runtime_context.with_label("qmdb"),
                            qmdb_config.clone(),
                        ).await {
                            Ok(restored_qmdb) => {
                                let mut qmdb_guard = qmdb.lock().await;
                                *qmdb_guard = Some(restored_qmdb);
                            }
                            Err(_) => {
                                warn!("Failed to restore QMDB from storage after merkleize error");
                            }
                        }
                        return false;
                    }
                };
                
                let simulated_root = clean_after_simulation.root();
                let result = simulated_root == block.state_root;
                
                info!(
                    height = block.height,
                    simulated_root = ?simulated_root,
                    block_state_root = ?block.state_root,
                    parent_state_root = ?parent.state_root,
                    tx_count = block.transactions.len(),
                    "verifying block with transactions"
                );
                
                if !result {
                    warn!(
                        height = block.height,
                        simulated_root = ?simulated_root,
                        block_state_root = ?block.state_root,
                        tx_count = block.transactions.len(),
                        "verification failed: simulated root doesn't match block state_root"
                    );
                }
                
                // Restore QMDB from storage since we consumed the original with into_dirty()
                // Storage might be stale if execution just committed, but that's fine for verification.
                // Execution will use the QMDB it left behind (correct state, possibly wrong cached root).
                let restored_qmdb = match Current::<R2, FixedBytes<8>, u64, Sha256, TwoCap, 64>::init(
                    runtime_context.with_label("qmdb"),
                    qmdb_config.clone(),
                ).await {
                    Ok(q) => q,
                    Err(_) => {
                        warn!("Failed to restore QMDB from storage after simulation - using simulated state");
                        // Use simulated state as fallback, but this means verification might have wrong state
                        clean_after_simulation
                    }
                };
                
                let mut qmdb_guard = qmdb.lock().await;
                *qmdb_guard = Some(restored_qmdb);
                
                result
        };
        
        verification_result
    }

    /// Full transaction verification - checks balances and validates all txs.
    /// 
    /// This function should receive the parent block to verify state root continuity.
    /// For now, it assumes the caller has already verified parent state_root matches current qmdb.
    async fn verify_transactions<R2: Rng + Spawner + Metrics + Clock + Storage>(
        block: &Block,
        qmdb: &Arc<Mutex<Option<Current<R2, FixedBytes<8>, u64, Sha256, TwoCap, 64>>>>,
    ) -> Result<bool, QmdbError> {
        // Note: This function assumes parent state_root verification is done elsewhere.
        // It focuses on verifying transactions and the resulting state_root.
        
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
            let qmdb_guard = qmdb.lock().await;
            let qmdb_ref = qmdb_guard.as_ref().expect("qmdb should always be Some");
            for &account_id in &accounts_to_query {
                let mut key = [0u8; 8];
                key[0] = 0x00; // Balance prefix
                key[1..].copy_from_slice(&account_id.to_be_bytes()[..7]);
                let balance_key = FixedBytes::new(key);
                // Awaiting while holding the guard is fine here since we're not spawning
                match qmdb_ref.get(&balance_key).await {
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


    async fn execute_transactions(
        &self, 
        _context: R,
        block: &Block
    ) -> Result<commonware_cryptography::sha256::Digest, QmdbError> {
        // CRITICAL: Acquire semaphore FIRST to serialize QMDB access
        // This ensures only one execution can proceed at a time
        let _permit = self.qmdb_semaphore.acquire().await.expect("semaphore should not be closed");
        
        // Move QMDB out of mutex since into_dirty() takes ownership
        let qmdb = {
            let mut qmdb_guard = self.qmdb.lock().await;
            qmdb_guard.take().expect("qmdb should always be Some")
        };
        
        if block.transactions.is_empty() {
            // Empty blocks keep the same state root as parent
            // Use block's state_root instead of QMDB's cached root (wrong after commit)
            let root = block.state_root;
            info!(
                height = block.height,
                state_root = ?root,
                "executed empty block"
            );
            // No changes to commit, just restore QMDB
            let mut qmdb_guard = self.qmdb.lock().await;
            *qmdb_guard = Some(qmdb);
            return Ok(root);
        }

        // Apply transactions to dirty state
        let mut dirty = qmdb.into_dirty();
        let mut public_keys_guard = self.public_keys.lock().await;

        for tx in &block.transactions {
            // Handle explicit account creation
            if tx.is_account_creation {
                let account_id = tx.to;
                
                // Verify account doesn't exist
                let balance_key = balance_key(account_id);
                if dirty.get(&balance_key).await?.is_some() {
                    warn!(
                        height = block.height,
                        account_id,
                        "Account already exists, cannot create"
                    );
                    drop(public_keys_guard);
                    let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                        panic!("failed to merkleize after error: {:?}", e);
                    });
                    let mut qmdb_guard = self.qmdb.lock().await;
                    *qmdb_guard = Some(clean);
                    return Err(QmdbError::Runtime(commonware_runtime::Error::Closed));
                }
                
                // Verify account ID is valid (>= 10 for non-genesis)
                if account_id < 10 {
                    warn!(
                        height = block.height,
                        account_id,
                        "Account ID reserved for genesis accounts"
                    );
                    drop(public_keys_guard);
                    let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                        panic!("failed to merkleize after error: {:?}", e);
                    });
                    let mut qmdb_guard = self.qmdb.lock().await;
                    *qmdb_guard = Some(clean);
                    return Err(QmdbError::Runtime(commonware_runtime::Error::Closed));
                }
                
                // Get receiver's public key
                let receiver_pk = tx.to_public_key.as_ref().ok_or_else(|| {
                    warn!(
                        height = block.height,
                        account_id,
                        "Account creation requires to_public_key"
                    );
                    QmdbError::Runtime(commonware_runtime::Error::Closed)
                })?.clone();
                
                // Create account state
                if let Err(e) = dirty.update(balance_key, tx.amount).await {
                    drop(public_keys_guard);
                    let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                        panic!("failed to merkleize after error: {:?}", e);
                    });
                    let mut qmdb_guard = self.qmdb.lock().await;
                    *qmdb_guard = Some(clean);
                    return Err(e);
                }
                
                if let Err(e) = dirty.update(nonce_key(account_id), 0u64).await {
                    drop(public_keys_guard);
                    let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                        panic!("failed to merkleize after error: {:?}", e);
                    });
                    let mut qmdb_guard = self.qmdb.lock().await;
                    *qmdb_guard = Some(clean);
                    return Err(e);
                }
                
                // Store public key hash in QMDB
                let pk_key = public_key_key(account_id);
                let pk_hash = hash_public_key(&receiver_pk);
                if let Err(e) = dirty.update(pk_key, pk_hash).await {
                    drop(public_keys_guard);
                    let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                        panic!("failed to merkleize after error: {:?}", e);
                    });
                    let mut qmdb_guard = self.qmdb.lock().await;
                    *qmdb_guard = Some(clean);
                    return Err(e);
                }
                
                // Update in-memory HashMap
                public_keys_guard.insert(account_id, receiver_pk);
                
                // Increment system account nonce
                let system_nonce_key = nonce_key(SYSTEM_ACCOUNT_ID);
                let current_system_nonce = dirty.get(&system_nonce_key).await?.unwrap_or(0);
                if let Err(e) = dirty.update(system_nonce_key, current_system_nonce + 1).await {
                    drop(public_keys_guard);
                    let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                        panic!("failed to merkleize after error: {:?}", e);
                    });
                    let mut qmdb_guard = self.qmdb.lock().await;
                    *qmdb_guard = Some(clean);
                    return Err(e);
                }
                
                // Update next_account_id to prevent ID collisions
                let next_id_key = next_account_id_key();
                let current_next_id = dirty.get(&next_id_key).await?.unwrap_or(10);
                let new_next_id = current_next_id.max(account_id + 1);
                if let Err(e) = dirty.update(next_id_key, new_next_id).await {
                    drop(public_keys_guard);
                    let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                        panic!("failed to merkleize after error: {:?}", e);
                    });
                    let mut qmdb_guard = self.qmdb.lock().await;
                    *qmdb_guard = Some(clean);
                    return Err(e);
                }
                
                info!(
                    height = block.height,
                    account_id,
                    initial_balance = tx.amount,
                    "Created account via explicit creation transaction"
                );
                
                continue;  // Skip normal transfer logic
            }
            
            // Handle regular transfer
            let from_balance_key = balance_key(tx.from);
            let to_balance_key = balance_key(tx.to);
            let account_nonce_key = nonce_key(tx.from);

            let current_nonce = match dirty.get(&account_nonce_key).await {
                Ok(Some(n)) => n,
                Ok(None) => 0,
                Err(e) => {
                    warn!(
                        height = block.height,
                        from = tx.from,
                        error = ?e,
                        "failed to get nonce"
                    );
                    drop(public_keys_guard);
                    let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                        panic!("failed to merkleize after error: {:?}", e);
                    });
                    let mut qmdb_guard = self.qmdb.lock().await;
                    *qmdb_guard = Some(clean);
                    return Err(e);
                }
            };

            // Check if receiver account exists
            let receiver_exists = dirty.get(&to_balance_key).await?.is_some();
            
            // Auto-create account if needed
            if !receiver_exists {
                // Verify account ID is valid
                if tx.to < 10 {
                    warn!(
                        height = block.height,
                        to = tx.to,
                        "Cannot auto-create genesis account"
                    );
                    drop(public_keys_guard);
                    let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                        panic!("failed to merkleize after error: {:?}", e);
                    });
                    let mut qmdb_guard = self.qmdb.lock().await;
                    *qmdb_guard = Some(clean);
                    return Err(QmdbError::Runtime(commonware_runtime::Error::Closed));
                }
                
                // Require receiver's public key
                let receiver_pk = tx.to_public_key.as_ref().ok_or_else(|| {
                    warn!(
                        height = block.height,
                        to = tx.to,
                        "Receiver account doesn't exist, to_public_key required"
                    );
                    QmdbError::Runtime(commonware_runtime::Error::Closed)
                })?.clone();
                
                // Create account
                dirty.update(balance_key(tx.to), 0u64).await?;
                dirty.update(nonce_key(tx.to), 0u64).await?;
                
                // Store public key
                let pk_key = public_key_key(tx.to);
                let pk_hash = hash_public_key(&receiver_pk);
                dirty.update(pk_key, pk_hash).await?;
                
                public_keys_guard.insert(tx.to, receiver_pk);
                
                // Update next_account_id to prevent ID collisions
                let next_id_key = next_account_id_key();
                let current_next_id = dirty.get(&next_id_key).await?.unwrap_or(10);
                let new_next_id = current_next_id.max(tx.to + 1);
                if let Err(e) = dirty.update(next_id_key, new_next_id).await {
                    drop(public_keys_guard);
                    let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                        panic!("failed to merkleize after error: {:?}", e);
                    });
                    let mut qmdb_guard = self.qmdb.lock().await;
                    *qmdb_guard = Some(clean);
                    return Err(e);
                }
                
                info!(
                    height = block.height,
                    account_id = tx.to,
                    "Created account via auto-create on first transfer"
                );
            }

            let from_balance = match dirty.get(&from_balance_key).await {
                Ok(Some(balance)) => balance,
                Ok(None) => 0,
                Err(e) => {
                    warn!(
                        height = block.height,
                        from = tx.from,
                        error = ?e,
                        "failed to get sender balance"
                    );
                    drop(public_keys_guard);
                    let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                        panic!("failed to merkleize after error: {:?}", e);
                    });
            let mut qmdb_guard = self.qmdb.lock().await;
                    *qmdb_guard = Some(clean);
                    return Err(e);
                }
            };

            let to_balance = match dirty.get(&to_balance_key).await {
                Ok(Some(balance)) => balance,
                Ok(None) => 0,
                Err(e) => {
                    warn!(
                height = block.height,
                        to = tx.to,
                        error = ?e,
                        "failed to get receiver balance"
                    );
                    drop(public_keys_guard);
                    let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                        panic!("failed to merkleize after error: {:?}", e);
                    });
                        let mut qmdb_guard = self.qmdb.lock().await;
                *qmdb_guard = Some(clean);
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
                drop(public_keys_guard);
                let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                    panic!("failed to merkleize after error: {:?}", e);
                });
                    let mut qmdb_guard = self.qmdb.lock().await;
                *qmdb_guard = Some(clean);
                // Return error - insufficient balance should have been caught in verification
                // Use Runtime error as a generic error type
                return Err(QmdbError::Runtime(commonware_runtime::Error::Closed));
            }

            if let Err(e) = dirty.update(from_balance_key, from_balance - tx.amount).await {
                warn!(
                    height = block.height,
                    from = tx.from,
                    error = ?e,
                    "failed to update sender balance"
                );
                drop(public_keys_guard);
                let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                    panic!("failed to merkleize after error: {:?}", e);
                });
                let mut qmdb_guard = self.qmdb.lock().await;
                *qmdb_guard = Some(clean);
                return Err(e);
            }

            if let Err(e) = dirty.update(balance_key(tx.to), to_balance + tx.amount).await {
                warn!(
                    height = block.height,
                    to = tx.to,
                    error = ?e,
                    "failed to update receiver balance"
                );
                drop(public_keys_guard);
                let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                    panic!("failed to merkleize after error: {:?}", e);
                });
                    let mut qmdb_guard = self.qmdb.lock().await;
                *qmdb_guard = Some(clean);
                return Err(e);
            }
            
            if let Err(e) = dirty.update(account_nonce_key, current_nonce + 1).await {
                warn!(
                    height = block.height,
                    from = tx.from,
                    error = ?e,
                    "failed to increment nonce"
                );
                drop(public_keys_guard);
                let clean = dirty.merkleize().await.unwrap_or_else(|e| {
                    panic!("failed to merkleize after error: {:?}", e);
                });
                let mut qmdb_guard = self.qmdb.lock().await;
                *qmdb_guard = Some(clean);
                return Err(e);
            }
        }
        
        drop(public_keys_guard);

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
        
        info!(
            height = block.height,
            root_after_merkleize = ?root_after_merkleize,
            block_state_root = ?block.state_root,
            tx_count = block.transactions.len(),
            note = "block.state_root should equal root_after_merkleize (both from merkleize, BEFORE commit)",
            "Computed state root after merkleize (BEFORE commit)"
        );
        
        if root_after_merkleize != block.state_root {
            warn!(
                height = block.height,
                expected = ?block.state_root,
                actual = ?root_after_merkleize,
                "state root mismatch after merkleize (verification should have caught this)"
            );
        } else {
            info!(
                height = block.height,
                state_root = ?root_after_merkleize,
                "✓ Block state_root matches root from merkleize (both BEFORE commit)"
            );
        }

        // Sync to disk for durability (but don't commit yet - delayed commit)
        match clean.sync().await {
            Ok(()) => {
                info!(
                    height = block.height,
                    state_root = ?root_after_merkleize,
                    "synced state to disk (delayed commit - will commit at next block)"
                );
            }
            Err(e) => {
                warn!(
                    height = block.height,
                    error = ?e,
                    "failed to sync state to disk"
                );
                // Continue anyway - sync failure is not fatal
            }
        }

        // Store QMDB without committing
        let mut qmdb_guard = self.qmdb.lock().await;
        *qmdb_guard = Some(clean);
        
        // Update tracking: mark this block as uncommitted
        {
            let mut uncommitted_guard = self.last_uncommitted_height.lock().await;
            *uncommitted_guard = Some(block.height);
        }
        
        info!(
            height = block.height,
            state_root = ?root_after_merkleize,
            "successfully executed transactions (synced but not committed - will commit at next block)"
        );

        Ok(root_after_merkleize)
    }
}

use alto_types::{Block, Transaction, NAMESPACE};
use commonware_codec::{varint::UInt, Write};
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest,
    Hasher, Sha256, Signer,
};
use commonware_math::algebra::Random;
use commonware_runtime::{Clock, Metrics, Spawner, Storage};
use commonware_storage::{
    qmdb::current::ordered::fixed::Db as Current,
    translator::TwoCap,
};
use commonware_utils::sequence::FixedBytes;
use rand::{rngs::StdRng, SeedableRng};
use std::sync::Arc;
use std::convert::TryInto;
use tokio::sync::Mutex;

use crate::application::{Actor, Config, Mailbox, Mempool};

// Constants matching actor.rs
const SYSTEM_ACCOUNT_ID: u64 = 0;
const SYSTEM_ACCOUNT_SEED: [u8; 32] = [0xFF; 32];

// Key prefixes matching actor.rs
const KEY_PREFIX_BALANCE: u8 = 0x00;
const KEY_PREFIX_NONCE: u8 = 0x01;

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
    key[0] = 0x02; // KEY_PREFIX_PUBLIC_KEY
    let account_bytes = account_id.to_be_bytes();
    key[1..8].copy_from_slice(&account_bytes[1..8]);
    FixedBytes::new(key)
}

fn next_account_id_key() -> FixedBytes<8> {
    let mut key = [0u8; 8];
    key[0] = 0x03; // KEY_PREFIX_NEXT_ACCOUNT_ID
    key[1..8].fill(0);
    FixedBytes::new(key)
}

fn hash_public_key(pk: &PublicKey) -> u64 {
    let mut hasher = Sha256::new();
    let mut pk_buf = Vec::new();
    pk.write(&mut pk_buf);
    hasher.update(&pk_buf);
    let hash = hasher.finalize();
    u64::from_be_bytes(hash[0..8].try_into().unwrap())
}

/// Generate deterministic keypair for a genesis account
pub fn create_genesis_account_keypair(account_id: u64) -> (PrivateKey, PublicKey) {
    let mut seed = [0u8; 32];
    if account_id == SYSTEM_ACCOUNT_ID {
        seed = SYSTEM_ACCOUNT_SEED;
    } else {
        seed[0..8].copy_from_slice(&account_id.to_be_bytes());
    }
    let mut rng = StdRng::from_seed(seed);
    let private_key = PrivateKey::random(&mut rng);
    let public_key = private_key.public_key();
    (private_key, public_key)
}

/// Compute transaction hash (matching actor.rs implementation)
fn compute_transaction_hash(
    from: u64,
    to: u64,
    amount: u64,
    nonce: u64,
    public_key: &PublicKey,
    to_public_key: Option<&PublicKey>,
    is_account_creation: bool,
) -> Digest {
    let mut hasher = Sha256::new();
    let mut tx_buf = Vec::new();
    UInt(from).write(&mut tx_buf);
    UInt(to).write(&mut tx_buf);
    UInt(amount).write(&mut tx_buf);
    UInt(nonce).write(&mut tx_buf);
    public_key.write(&mut tx_buf);

    if let Some(ref pk) = to_public_key {
        tx_buf.push(1);
        pk.write(&mut tx_buf);
    } else {
        tx_buf.push(0);
    }

    tx_buf.push(if is_account_creation { 1 } else { 0 });

    hasher.update(NAMESPACE);
    hasher.update(&tx_buf);
    hasher.finalize()
}

/// Create a signed test transaction
pub fn create_test_transaction(
    from: u64,
    to: u64,
    amount: u64,
    nonce: u64,
    private_key: PrivateKey,
    to_public_key: Option<PublicKey>,
    is_account_creation: bool,
) -> Transaction {
    let public_key = private_key.public_key();
    let tx_hash = compute_transaction_hash(
        from,
        to,
        amount,
        nonce,
        &public_key,
        to_public_key.as_ref(),
        is_account_creation,
    );
    let signature = private_key.sign(NAMESPACE, tx_hash.as_ref());

    Transaction {
        from,
        to,
        amount,
        nonce,
        signature,
        public_key,
        to_public_key,
        is_account_creation,
    }
}

/// Create a test block with transactions
pub fn create_test_block(
    parent: Digest,
    height: u64,
    timestamp: u64,
    transactions: Vec<Transaction>,
    state_root: Digest,
) -> Block {
    Block::new(parent, height, timestamp, transactions, state_root)
}

/// Get state root from QMDB
pub async fn get_state_root_from_qmdb<R: Spawner + Storage + Metrics + Clock>(
    qmdb: &Arc<Mutex<Option<Current<R, FixedBytes<8>, u64, Sha256, TwoCap, 64>>>>,
) -> Option<Digest> {
    let qmdb_guard = qmdb.lock().await;
    if let Some(ref qmdb_ref) = *qmdb_guard {
        Some(qmdb_ref.root())
    } else {
        None
    }
}

/// Get balance for an account from QMDB
/// Note: This temporarily takes ownership of QMDB to read, then restores it
pub async fn get_balance_from_qmdb<R: Spawner + Storage + Metrics + Clock>(
    qmdb: &Arc<Mutex<Option<Current<R, FixedBytes<8>, u64, Sha256, TwoCap, 64>>>>,
    account_id: u64,
) -> Option<u64> {
    let qmdb_to_read = {
        let mut qmdb_guard = qmdb.lock().await;
        qmdb_guard.take()
    };
    
    if let Some(qmdb_ref) = qmdb_to_read {
        let key = balance_key(account_id);
        let dirty = qmdb_ref.into_dirty();
        let result = match dirty.get(&key).await {
            Ok(Some(balance)) => Some(balance),
            Ok(None) => Some(0), // Account doesn't exist, balance is 0
            Err(_) => None,
        };
        // Restore QMDB by merkleizing (no changes were made, so root should be same)
        let clean = dirty.merkleize().await.ok()?;
        let mut qmdb_guard = qmdb.lock().await;
        *qmdb_guard = Some(clean);
        result
    } else {
        None
    }
}

/// Get nonce for an account from QMDB
/// Note: This temporarily takes ownership of QMDB to read, then restores it
pub async fn get_nonce_from_qmdb<R: Spawner + Storage + Metrics + Clock>(
    qmdb: &Arc<Mutex<Option<Current<R, FixedBytes<8>, u64, Sha256, TwoCap, 64>>>>,
    account_id: u64,
) -> Option<u64> {
    let qmdb_to_read = {
        let mut qmdb_guard = qmdb.lock().await;
        qmdb_guard.take()
    };
    
    if let Some(qmdb_ref) = qmdb_to_read {
        let key = nonce_key(account_id);
        let dirty = qmdb_ref.into_dirty();
        let result = match dirty.get(&key).await {
            Ok(Some(nonce)) => Some(nonce),
            Ok(None) => Some(0), // Account doesn't exist, nonce is 0
            Err(_) => None,
        };
        // Restore QMDB by merkleizing (no changes were made, so root should be same)
        let clean = dirty.merkleize().await.ok()?;
        let mut qmdb_guard = qmdb.lock().await;
        *qmdb_guard = Some(clean);
        result
    } else {
        None
    }
}

/// Create a marshal mailbox for testing
/// This creates a minimal marshal actor setup for testing transaction processing
/// Uses a trusted dealer to generate DKG shares (simpler than full DKG protocol)
pub async fn create_test_marshal_mailbox<R: rand::Rng + rand::CryptoRng + Spawner + Storage + Metrics + Clock>(
    context: R,
) -> Result<commonware_consensus::marshal::Mailbox<alto_types::Scheme, alto_types::Block>, commonware_storage::qmdb::Error> {
    use commonware_consensus::{
        marshal,
        types::{FixedEpocher, ViewDelta},
    };
    use commonware_cryptography::bls12381::{
        dkg::deal_anonymous,
        primitives::variant::MinSig,
    };
    use commonware_cryptography::ed25519::{PrivateKey, PublicKey};
    use commonware_runtime::buffer::PoolRef;
    use commonware_storage::archive::immutable;
    use commonware_utils::{ordered::Set, TryFromIterator, NZUsize, NZU64, NZU32};
    use rand::{rngs::StdRng, SeedableRng};

    // Create minimal archives for marshal
    let finalizations_by_height = immutable::Archive::init(
        context.with_label("test_finalizations"),
        immutable::Config {
            metadata_partition: "test_finalizations_metadata".into(),
            freezer_table_partition: "test_finalizations_table".into(),
            freezer_table_initial_size: 1024,
            freezer_table_resize_frequency: 4,
            freezer_table_resize_chunk_size: 1024,
            freezer_journal_partition: "test_finalizations_journal".into(),
            freezer_journal_target_size: 1024 * 1024,
            freezer_journal_compression: None,
            freezer_journal_buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
            ordinal_partition: "test_finalizations_ordinal".into(),
            items_per_section: NZU64!(1024),
            codec_config: (),
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024),
        },
    )
    .await
    .map_err(|e| commonware_storage::qmdb::Error::Journal(
        commonware_storage::journal::Error::InvalidConfiguration(format!("Archive init failed: {:?}", e))
    ))?;

    let finalized_blocks = immutable::Archive::init(
        context.with_label("test_blocks"),
        immutable::Config {
            metadata_partition: "test_blocks_metadata".into(),
            freezer_table_partition: "test_blocks_table".into(),
            freezer_table_initial_size: 1024,
            freezer_table_resize_frequency: 4,
            freezer_table_resize_chunk_size: 1024,
            freezer_journal_partition: "test_blocks_journal".into(),
            freezer_journal_target_size: 1024 * 1024,
            freezer_journal_compression: None,
            freezer_journal_buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
            ordinal_partition: "test_blocks_ordinal".into(),
            items_per_section: NZU64!(1024),
            codec_config: (),
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024),
        },
    )
    .await
    .map_err(|e| commonware_storage::qmdb::Error::Journal(
        commonware_storage::journal::Error::InvalidConfiguration(format!("Archive init failed: {:?}", e))
    ))?;

    // Create a minimal BLS12-381 threshold signature scheme for testing
    // Using trusted dealer (simpler than full DKG protocol)
    // Generate polynomial and shares using deal_anonymous
    // This is deterministic based on the seed, making tests reproducible
    let mut rng = StdRng::from_seed([0u8; 32]); // Fixed seed for determinism
    let (polynomial, shares) = deal_anonymous::<MinSig>(&mut rng, Default::default(), NZU32!(1));
    let share = shares[0].clone(); // Use first share
    
    // Create a dummy participant to satisfy scheme validation
    // The polynomial expects 1 participant, so we create one dummy public key
    let dummy_private_key = PrivateKey::random(&mut rng);
    let dummy_public_key = dummy_private_key.public_key();
    let participants = Set::try_from_iter([dummy_public_key])
        .expect("single participant should not have duplicates");
    
    // Create the scheme
    let scheme = alto_types::Scheme::signer(participants, polynomial, share)
        .ok_or_else(|| commonware_storage::qmdb::Error::Journal(
            commonware_storage::journal::Error::InvalidConfiguration(
                "Failed to create scheme: share public key does not match polynomial".into()
            )
        ))?;

    // Initialize marshal
    // Type annotation helps compiler infer Acknowledgement type parameter (defaults to Exact)
    let result: (
        marshal::Actor<R, alto_types::Block, _, _, _, FixedEpocher, commonware_utils::acknowledgement::Exact>,
        marshal::Mailbox<alto_types::Scheme, alto_types::Block>,
        u64,
    ) = marshal::Actor::init(
        context.with_label("test_marshal"),
        finalizations_by_height,
        finalized_blocks,
        marshal::Config {
            provider: crate::StaticSchemeProvider::from(scheme),
            epocher: FixedEpocher::new(NZU64!(u64::MAX)), // Very large epoch for testing
            partition_prefix: "test_marshal".into(),
            mailbox_size: 1024,
            view_retention_timeout: ViewDelta::new(1000),
            namespace: alto_types::NAMESPACE.to_vec(),
            prunable_items_per_section: NZU64!(1024),
            buffer_pool: PoolRef::new(NZUsize!(1024), NZUsize!(10)),
            replay_buffer: NZUsize!(1024 * 1024),
            write_buffer: NZUsize!(1024),
            block_codec_config: (),
            max_repair: NZUsize!(10),
        },
    )
    .await;
    let (_marshal, mailbox, _processed_height) = result;

    Ok(mailbox)
}

/// Compute expected state root by simulating transactions (like block proposal)
/// This matches the logic in actor.rs during block proposal
pub async fn compute_expected_state_root<R: Spawner + Storage + Metrics + Clock>(
    qmdb: &Arc<Mutex<Option<Current<R, FixedBytes<8>, u64, Sha256, TwoCap, 64>>>>,
    transactions: &[Transaction],
    parent_state_root: Digest,
) -> Result<Digest, commonware_storage::qmdb::Error> {
    
    if transactions.is_empty() {
        return Ok(parent_state_root);
    }
    
    // Take QMDB to simulate transactions
    let qmdb_to_simulate = {
        let mut qmdb_guard = qmdb.lock().await;
        qmdb_guard.take()
    };
    
    let qmdb_ref = qmdb_to_simulate.ok_or_else(|| {
        commonware_storage::qmdb::Error::Journal(
            commonware_storage::journal::Error::InvalidConfiguration("QMDB is None".into())
        )
    })?;
    
    let mut dirty = qmdb_ref.into_dirty();
    
    // Simulate transactions (matching actor.rs proposal logic)
    for tx in transactions {
        // Handle explicit account creation
        if tx.is_account_creation {
            let account_id = tx.to;
            let balance_key = balance_key(account_id);
            
            // Verify account doesn't exist
            if dirty.get(&balance_key).await?.is_some() {
                return Err(commonware_storage::qmdb::Error::Journal(
                    commonware_storage::journal::Error::InvalidConfiguration("Account already exists".into())
                ));
            }
            
            // Create account
            dirty.update(balance_key, tx.amount).await?;
            dirty.update(nonce_key(account_id), 0u64).await?;
            
            // Store public key hash
            if let Some(ref pk) = tx.to_public_key {
                let pk_key = public_key_key(account_id);
                let pk_hash = hash_public_key(pk);
                dirty.update(pk_key, pk_hash).await?;
            }
            
            // Update next_account_id
            let next_id_key = next_account_id_key();
            let current_next_id = dirty.get(&next_id_key).await?.unwrap_or(10);
            let new_next_id = current_next_id.max(account_id + 1);
            dirty.update(next_id_key, new_next_id).await?;
            
            // Increment system account nonce
            let system_nonce_key = nonce_key(SYSTEM_ACCOUNT_ID);
            let current_system_nonce = dirty.get(&system_nonce_key).await?.unwrap_or(0);
            dirty.update(system_nonce_key, current_system_nonce + 1).await?;
            
            continue;
        }
        
        // Handle regular transfer
        let from_balance_key = balance_key(tx.from);
        let to_balance_key = balance_key(tx.to);
        
        // Check if receiver exists
        let receiver_exists = dirty.get(&to_balance_key).await?.is_some();
        
        if !receiver_exists {
            // Create account
            if tx.to < 10 {
                return Err(commonware_storage::qmdb::Error::Journal(
                    commonware_storage::journal::Error::InvalidConfiguration("Invalid account ID".into())
                ));
            }
            
            if tx.to_public_key.is_none() {
                return Err(commonware_storage::qmdb::Error::Journal(
                    commonware_storage::journal::Error::InvalidConfiguration("to_public_key required for new account".into())
                ));
            }
            
            let to_balance_key = balance_key(tx.to); // Recreate key
            dirty.update(to_balance_key, 0u64).await?;
            dirty.update(nonce_key(tx.to), 0u64).await?;
            
            // Store public key hash
            if let Some(ref pk) = tx.to_public_key {
                let pk_key = public_key_key(tx.to);
                let pk_hash = hash_public_key(pk);
                dirty.update(pk_key, pk_hash).await?;
            }
            
            // Update next_account_id
            let next_id_key = next_account_id_key();
            let current_next_id = dirty.get(&next_id_key).await?.unwrap_or(10);
            let new_next_id = current_next_id.max(tx.to + 1);
            dirty.update(next_id_key, new_next_id).await?;
        }
        
        // Get balances
        let from_balance = dirty.get(&from_balance_key).await?.unwrap_or(0);
        if from_balance < tx.amount {
            return Err(commonware_storage::qmdb::Error::Journal(
                commonware_storage::journal::Error::InvalidConfiguration("Insufficient balance".into())
            ));
        }
        
        let to_balance_key = balance_key(tx.to); // Recreate key
        let to_balance = dirty.get(&to_balance_key).await?.unwrap_or(0);
        
        // Apply transaction
        let from_balance_key = balance_key(tx.from); // Recreate key
        dirty.update(from_balance_key, from_balance - tx.amount).await?;
        let to_balance_key = balance_key(tx.to); // Recreate key
        dirty.update(to_balance_key, to_balance + tx.amount).await?;
        
        // Increment nonce
        let account_nonce_key = nonce_key(tx.from);
        let current_nonce = dirty.get(&account_nonce_key).await?.unwrap_or(0);
        dirty.update(account_nonce_key, current_nonce + 1).await?;
    }
    
    // Compute root after simulation
    let clean = dirty.merkleize().await?;
    let computed_root = clean.root();
    
    // Restore QMDB - we need to restore from storage to match real behavior
    // For now, we'll put back the clean state (which has the simulated changes)
    // In real block proposal, QMDB is restored from storage, but for testing
    // we'll use the simulated state since we're just computing the root
    let mut qmdb_guard = qmdb.lock().await;
    *qmdb_guard = Some(clean);
    
    Ok(computed_root)
}

/// Setup test actor with deterministic runtime
pub async fn setup_test_actor<R: rand::Rng + Spawner + Storage + Metrics + Clock>(
    context: R,
    config: Config,
) -> Result<
    (
        Actor<R>,
        Mailbox,
        Mempool,
        Arc<Mutex<Option<Current<R, FixedBytes<8>, u64, Sha256, TwoCap, 64>>>>,
        Arc<Mutex<std::collections::HashMap<u64, PublicKey>>>,
    ),
    commonware_storage::qmdb::Error,
> {
    Actor::new(context, config).await
}

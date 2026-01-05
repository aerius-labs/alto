use alto_types::{Block, Scheme, Transaction};
use crate::application::Mempool;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use commonware_consensus::marshal;
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_runtime::tokio::Context as TokioContext;
use commonware_storage::{
    mmr::{Location, Position, Proof},
    qmdb::{
        current::{
            ordered::fixed::{Db as Current, KeyValueProof},
            proof::{OperationProof, RangeProof},
        },
        Error as QmdbError,
    },
    translator::TwoCap,
};
use commonware_utils::sequence::FixedBytes;
use commonware_codec::{ReadExt, Write, varint::UInt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

#[derive(Serialize)]
struct SubmitTxResponse {
    success: bool,
    message: String,
}

#[derive(Serialize)]
struct MempoolStatus {
    pending: usize,
    max_size: usize,
}

#[derive(Serialize)]
struct BalanceResponse {
    account: u64,
    balance: u64,
}

#[derive(Serialize)]
struct AllBalancesResponse {
    balances: HashMap<u64, u64>,
    total_accounts: usize,
}

#[derive(Serialize)]
struct BlockResponse {
    parent: String,
    height: u64,
    timestamp: u64,
    transactions: Vec<TransactionResponse>,
    state_root: String,
    digest: String,
}

#[derive(Serialize)]
struct TransactionResponse {
    from: u64,
    to: u64,
    amount: u64,
}

#[derive(Deserialize)]
struct SubmitTxRequest {
    from: u64,
    to: u64,
    amount: u64,
}

type Qmdb = Current<TokioContext, FixedBytes<8>, u64, Sha256, TwoCap, 64>;

#[derive(Clone)]
struct ApiState {
    mempool: Arc<Mempool>,
    qmdb: Arc<Mutex<Option<Qmdb>>>,
    marshal: marshal::Mailbox<Scheme, Block>,
}

pub async fn start_api_server(
    mempool: Mempool,
    qmdb: Arc<Mutex<Option<Qmdb>>>,
    marshal: marshal::Mailbox<Scheme, Block>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    
    let state = ApiState {
        mempool: Arc::new(mempool),
        qmdb,
        marshal,
    };
    
    let app = Router::new()
        .route("/submit", post(submit_transaction))
        .route("/mempool", get(get_mempool_status))
        .route("/balance/:account", get(get_balance))
        .route("/balances", get(get_all_balances))
        .route("/block/:height", get(get_block_by_height))
        .route("/proof/balance/:account", get(get_balance_proof))
        .route("/proof/exclusion/:account", get(get_exclusion_proof))
        .route("/state-root", get(get_state_root))
        .route("/verify/proof", post(verify_balance_proof))
        .route("/health", get(health_check))
        .with_state(state);

    info!(?addr, "Starting API server");
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}

async fn submit_transaction(
    State(state): State<ApiState>,
    Json(payload): Json<SubmitTxRequest>,
) -> Result<Json<SubmitTxResponse>, StatusCode> {
    if payload.amount == 0 {
        return Ok(Json(SubmitTxResponse {
            success: false,
            message: "Amount must be greater than 0".to_string(),
        }));
    }
    
    if payload.from == payload.to {
        return Ok(Json(SubmitTxResponse {
            success: false,
            message: "Sender and receiver cannot be the same".to_string(),
        }));
    }
    
    // Query balance from QMDB
    let sender_balance = {
        let qmdb_guard = state.qmdb.lock().await;
        if let Some(qmdb_ref) = qmdb_guard.as_ref() {
            let key = FixedBytes::new(payload.from.to_be_bytes());
            match qmdb_ref.get(&key).await {
                Ok(Some(balance)) => balance,
                Ok(None) => 0,
                Err(_) => 0,
            }
        } else {
            0
        }
    };
    
    if sender_balance < payload.amount {
        return Ok(Json(SubmitTxResponse {
            success: false,
            message: format!("Insufficient balance. Account {} has {} but needs {}", payload.from, sender_balance, payload.amount),
        }));
    }
    
    let tx = Transaction {
        from: payload.from,
        to: payload.to,
        amount: payload.amount,
    };
    
    let added = state.mempool.add(tx);
    
    if added {
        info!(
            from = payload.from,
            to = payload.to,
            amount = payload.amount,
            "Transaction submitted to mempool"
        );
        Ok(Json(SubmitTxResponse {
            success: true,
            message: "Transaction added to mempool".to_string(),
        }))
    } else {
        Ok(Json(SubmitTxResponse {
            success: false,
            message: "Mempool is full".to_string(),
        }))
    }
}

async fn get_mempool_status(
    State(state): State<ApiState>,
) -> Json<MempoolStatus> {
    Json(MempoolStatus {
        pending: state.mempool.len(),
        max_size: state.mempool.max_size(),
    })
}

async fn get_balance(
    State(state): State<ApiState>,
    Path(account): Path<u64>,
) -> Json<BalanceResponse> {
    let balance = {
        let qmdb_guard = state.qmdb.lock().await;
        if let Some(qmdb_ref) = qmdb_guard.as_ref() {
            let key = FixedBytes::new(account.to_be_bytes());
            match qmdb_ref.get(&key).await {
                Ok(Some(b)) => b,
                Ok(None) => 0,
                Err(_) => 0,
            }
        } else {
            0
        }
    };
    Json(BalanceResponse { account, balance })
}

async fn get_all_balances(
    State(state): State<ApiState>,
) -> Json<AllBalancesResponse> {
    let mut balances = HashMap::new();
    {
        let qmdb_guard = state.qmdb.lock().await;
        if let Some(qmdb_ref) = qmdb_guard.as_ref() {
            // Query balances for accounts 0-99
            for account_id in 0u64..100 {
                let key = FixedBytes::new(account_id.to_be_bytes());
                match qmdb_ref.get(&key).await {
                    Ok(Some(balance)) => {
                        balances.insert(account_id, balance);
                    }
                    Ok(None) => {
                        // Account doesn't exist, balance is 0
                    }
                    Err(_) => {
                        // Error querying, skip this account
                    }
                }
            }
        }
    }
    let total_accounts = balances.len();
    Json(AllBalancesResponse {
        balances,
        total_accounts,
    })
}

async fn get_block_by_height(
    State(state): State<ApiState>,
    Path(height): Path<u64>,
) -> Result<Json<BlockResponse>, StatusCode> {
    use commonware_cryptography::Digestible;
    let mut marshal = state.marshal.clone();
    
    // Get block from marshal by height
    let block = match marshal.get_block(height).await {
        Some(block) => block,
        None => {
            return Err(StatusCode::NOT_FOUND);
        }
    };
    
    // Convert transactions to response format
    let transactions: Vec<TransactionResponse> = block.transactions
        .iter()
        .map(|tx| TransactionResponse {
            from: tx.from,
            to: tx.to,
            amount: tx.amount,
        })
        .collect();
    
    // Convert digests to hex strings
    let parent_hex = hex::encode(block.parent);
    let state_root_hex = hex::encode(block.state_root);
    // Block implements Digestible trait - use fully qualified path
    let digest_hex = hex::encode(<Block as Digestible>::digest(&block));
    
    Ok(Json(BlockResponse {
        parent: parent_hex,
        height: block.height,
        timestamp: block.timestamp,
        transactions,
        state_root: state_root_hex,
        digest: digest_hex,
    }))
}

async fn health_check() -> &'static str {
    "OK"
}

#[derive(Serialize)]
struct BalanceProofResponse {
    account: u64,
    balance: u64,
    proof: String,
    state_root: String,
}

#[derive(Serialize)]
struct ExclusionProofResponse {
    account: u64,
    proof: String,
    state_root: String,
}

#[derive(Serialize)]
struct StateRootResponse {
    state_root: String,
}

#[derive(Deserialize)]
struct VerifyProofRequest {
    account: u64,
    balance: u64,
    proof: String,
    state_root: String,
}

#[derive(Serialize)]
struct VerifyProofResponse {
    valid: bool,
    message: String,
}

async fn get_balance_proof(
    State(state): State<ApiState>,
    Path(account): Path<u64>,
) -> Result<Json<BalanceProofResponse>, StatusCode> {
    let key = FixedBytes::new(account.to_be_bytes());
    
    let (balance, proof_bytes, state_root) = {
        let qmdb_guard = state.qmdb.lock().await;
        let qmdb_ref = match qmdb_guard.as_ref() {
            Some(q) => q,
            None => return Err(StatusCode::SERVICE_UNAVAILABLE),
        };
        
        let balance = match qmdb_ref.get(&key).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                return Err(StatusCode::NOT_FOUND);
            }
            Err(e) => {
                warn!(?account, ?e, "Failed to get balance for proof");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        
        let state_root = qmdb_ref.root();
        
        let mut hasher = Sha256::default();
        let proof = match qmdb_ref.key_value_proof(&mut hasher, key).await {
            Ok(p) => p,
            Err(QmdbError::KeyNotFound) => {
                return Err(StatusCode::NOT_FOUND);
            }
            Err(e) => {
                warn!(?account, ?e, "Failed to generate balance proof");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        
        // Serialize proof to bytes
        let mut proof_bytes = Vec::new();
        use commonware_codec::varint::UInt;
        UInt(*proof.proof.loc).write(&mut proof_bytes);
        proof.proof.chunk.write(&mut proof_bytes);
        proof.proof.range_proof.proof.write(&mut proof_bytes);
        match proof.proof.range_proof.partial_chunk_digest {
            Some(digest) => {
                proof_bytes.push(1);
                digest.write(&mut proof_bytes);
            }
            None => {
                proof_bytes.push(0);
            }
        }
        proof.next_key.write(&mut proof_bytes);
        
        (balance, proof_bytes, state_root)
    };
    
    Ok(Json(BalanceProofResponse {
        account,
        balance,
        proof: hex::encode(proof_bytes),
        state_root: hex::encode(state_root),
    }))
}

async fn get_exclusion_proof(
    State(state): State<ApiState>,
    Path(account): Path<u64>,
) -> Result<Json<ExclusionProofResponse>, StatusCode> {
    let key = FixedBytes::new(account.to_be_bytes());
    
    let (proof_bytes, state_root) = {
        let qmdb_guard = state.qmdb.lock().await;
        let qmdb_ref = match qmdb_guard.as_ref() {
            Some(q) => q,
            None => return Err(StatusCode::SERVICE_UNAVAILABLE),
        };
        
        match qmdb_ref.get(&key).await {
            Ok(Some(_)) => {
                return Err(StatusCode::BAD_REQUEST);
            }
            Ok(None) => {}
            Err(e) => {
                warn!(?account, ?e, "Failed to check account existence");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
        
        let state_root = qmdb_ref.root();
        
        let mut hasher = Sha256::default();
        let proof = match qmdb_ref.exclusion_proof(&mut hasher, &key).await {
            Ok(p) => p,
            Err(QmdbError::KeyExists) => {
                return Err(StatusCode::BAD_REQUEST);
            }
            Err(e) => {
                warn!(?account, ?e, "Failed to generate exclusion proof");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };
        
        let mut proof_bytes = Vec::new();
        use commonware_codec::varint::UInt;
        
        match &proof {
            commonware_storage::qmdb::current::ordered::ExclusionProof::KeyValue(op_proof, update) => {
                proof_bytes.push(0);
                UInt(*op_proof.loc).write(&mut proof_bytes);
                op_proof.chunk.write(&mut proof_bytes);
                op_proof.range_proof.proof.write(&mut proof_bytes);
                match op_proof.range_proof.partial_chunk_digest {
                    Some(digest) => {
                        proof_bytes.push(1);
                        digest.write(&mut proof_bytes);
                    }
                    None => {
                        proof_bytes.push(0);
                    }
                }
                update.write(&mut proof_bytes);
            }
            commonware_storage::qmdb::current::ordered::ExclusionProof::Commit(op_proof, metadata) => {
                proof_bytes.push(1);
                UInt(*op_proof.loc).write(&mut proof_bytes);
                op_proof.chunk.write(&mut proof_bytes);
                op_proof.range_proof.proof.write(&mut proof_bytes);
                match op_proof.range_proof.partial_chunk_digest {
                    Some(digest) => {
                        proof_bytes.push(1);
                        digest.write(&mut proof_bytes);
                    }
                    None => {
                        proof_bytes.push(0);
                    }
                }
                match metadata {
                    Some(v) => {
                        proof_bytes.push(1);
                        UInt(*v).write(&mut proof_bytes);
                    }
                    None => {
                        proof_bytes.push(0);
                    }
                }
            }
        }
        
        (proof_bytes, state_root)
    };
    
    Ok(Json(ExclusionProofResponse {
        account,
        proof: hex::encode(proof_bytes),
        state_root: hex::encode(state_root),
    }))
}

async fn get_state_root(
    State(state): State<ApiState>,
) -> Result<Json<StateRootResponse>, StatusCode> {
    let state_root = {
        let qmdb_guard = state.qmdb.lock().await;
        let qmdb_ref = match qmdb_guard.as_ref() {
            Some(q) => q,
            None => return Err(StatusCode::SERVICE_UNAVAILABLE),
        };
        qmdb_ref.root()
    };
    
    Ok(Json(StateRootResponse {
        state_root: hex::encode(state_root),
    }))
}

async fn verify_balance_proof(
    State(_state): State<ApiState>,
    Json(payload): Json<VerifyProofRequest>,
) -> Result<Json<VerifyProofResponse>, StatusCode> {
    let state_root_bytes = hex::decode(&payload.state_root)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if state_root_bytes.len() != 32 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let state_root_array: [u8; 32] = state_root_bytes.try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let state_root = Digest::from(state_root_array);
    
    let proof_bytes = hex::decode(&payload.proof)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    let mut reader = proof_bytes.as_slice();
    
    let loc_value: u64 = UInt::read(&mut reader)
        .map_err(|_| StatusCode::BAD_REQUEST)?.into();
    let loc = Location::new(loc_value)
        .ok_or(StatusCode::BAD_REQUEST)?;
    
    let chunk = <[u8; 64]>::read(&mut reader)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    
    let proof_size: u64 = UInt::read(&mut reader)
        .map_err(|_| StatusCode::BAD_REQUEST)?.into();
    let proof_size_pos = Position::new(proof_size);
    
    let digest_count: u64 = UInt::read(&mut reader)
        .map_err(|_| StatusCode::BAD_REQUEST)?.into();
    
    let max_digests = 1000usize;
    if digest_count as usize > max_digests {
        return Err(StatusCode::BAD_REQUEST);
    }
    
    let mut digests = Vec::with_capacity(digest_count as usize);
    for _ in 0..digest_count {
        let digest = Digest::read(&mut reader)
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        digests.push(digest);
    }
    
    let mmr_proof = Proof {
        size: proof_size_pos,
        digests,
    };
    
    let has_partial = u8::read(&mut reader)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let partial_chunk_digest = if has_partial == 1 {
        Some(Digest::read(&mut reader)
            .map_err(|_| StatusCode::BAD_REQUEST)?)
    } else {
        None
    };
    
    let range_proof = RangeProof {
        proof: mmr_proof,
        partial_chunk_digest,
    };
    
    let op_proof = OperationProof {
        loc,
        chunk,
        range_proof,
    };
    
    let next_key_bytes = <[u8; 8]>::read(&mut reader)
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let next_key = FixedBytes::new(next_key_bytes);
    
    let key_value_proof = KeyValueProof {
        proof: op_proof,
        next_key,
    };
    
    let key = FixedBytes::new(payload.account.to_be_bytes());
    let mut hasher = Sha256::default();
    let valid = Current::<TokioContext, FixedBytes<8>, u64, Sha256, TwoCap, 64>
        ::verify_key_value_proof(
            &mut hasher,
            key,
            payload.balance,
            &key_value_proof,
            &state_root,
        );
    
    Ok(Json(VerifyProofResponse {
        valid,
        message: if valid {
            format!("Proof is valid: account {} has balance {}", payload.account, payload.balance)
        } else {
            format!("Proof is invalid: account {} balance {} does not match state root", payload.account, payload.balance)
        },
    }))
}

use alto_types::Transaction;
use crate::application::Mempool;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use commonware_cryptography::Sha256;
use commonware_runtime::tokio::Context as TokioContext;
use commonware_storage::{
    qmdb::current::ordered::fixed::Db as Current,
    translator::TwoCap,
};
use commonware_utils::sequence::FixedBytes;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

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
}

pub async fn start_api_server(
    mempool: Mempool,
    qmdb: Arc<Mutex<Option<Qmdb>>>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    
    let state = ApiState {
        mempool: Arc::new(mempool),
        qmdb,
    };
    
    let app = Router::new()
        .route("/submit", post(submit_transaction))
        .route("/mempool", get(get_mempool_status))
        .route("/balance/:account", get(get_balance))
        .route("/balances", get(get_all_balances))
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

async fn health_check() -> &'static str {
    "OK"
}

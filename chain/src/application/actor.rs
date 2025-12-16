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
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner};
use commonware_utils::SystemTimeExt;
use futures::StreamExt;
use futures::{channel::mpsc, future::try_join};
use futures::{future, future::Either};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

/// Genesis message to use during initialization.
const GENESIS: &[u8] = b"commonware is neat";

/// Milliseconds in the future to allow for block timestamps.
const SYNCHRONY_BOUND: u64 = 500;

const GENESIS_BALANCE: u64 = 1000;

/// Application actor.
pub struct Actor<R: Rng + Spawner + Metrics + Clock> {
    context: ContextCell<R>,
    hasher: Sha256,
    mailbox: mpsc::Receiver<Message>,
    balances: Arc<Mutex<HashMap<u64, u64>>>,
    processed_heights: Arc<Mutex<HashSet<u64>>>,
    mempool: Mempool,
}

impl<R: Rng + Spawner + Metrics + Clock> Actor<R> {
    /// Create a new application actor.
    pub fn new(context: R, config: Config) -> (Self, Mailbox, Mempool, Arc<Mutex<HashMap<u64, u64>>>) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        
        let mut balances = HashMap::new();
        for i in 0..10 {
            balances.insert(i, GENESIS_BALANCE);
        }
        
        let mempool = Mempool::new(config.mempool_max_size);
        let mempool_clone = mempool.clone();
        let balances_arc = Arc::new(Mutex::new(balances));
        let balances_clone = balances_arc.clone();
        
        (
            Self {
                context: ContextCell::new(context),
                hasher: Sha256::new(),
                mailbox,
                balances: balances_clone,
                processed_heights: Arc::new(Mutex::new(HashSet::new())),
                mempool: mempool_clone,
            },
            Mailbox::new(sender),
            mempool,
            balances_arc,
        )
    }

    pub fn start(mut self, marshal: marshal::Mailbox<Scheme, Block>) -> Handle<()> {
        spawn_cell!(self.context, self.run(marshal).await)
    }

    /// Run the application actor.
    async fn run(mut self, mut marshal: marshal::Mailbox<Scheme, Block>) {
        // Compute genesis digest
        self.hasher.update(GENESIS);
        let genesis_parent = self.hasher.finalize();
        let genesis = Block::new(genesis_parent, 0, 0, Vec::new());
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
                                    let block = Block::new(
                                        parent.digest(),
                                        parent.height + 1,
                                        current,
                                        transactions.clone(),
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
                    marshal.broadcast(built.1.clone()).await;
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
                        let balances = self.balances.clone();
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

                                    if !Self::verify_transactions(&block, &balances) {
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

                    self.execute_transactions(&block);

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

    fn verify_transactions(block: &Block, balances: &Arc<Mutex<HashMap<u64, u64>>>) -> bool {
        let balances = balances.lock().unwrap();
        let mut temp_balances = balances.clone();
        
        for tx in &block.transactions {
            let sender_balance = temp_balances.get(&tx.from).copied().unwrap_or(0);
            if sender_balance < tx.amount {
                return false;
            }
            
            if tx.amount == 0 {
                return false;
            }
            
            *temp_balances.entry(tx.from).or_insert(0) -= tx.amount;
            *temp_balances.entry(tx.to).or_insert(0) += tx.amount;
        }
        
        true
    }

    fn execute_transactions(&self, block: &Block) {
        let mut balances = self.balances.lock().unwrap();
        
        for tx in &block.transactions {
            let sender_balance = balances.get(&tx.from).copied().unwrap_or(0);
            let receiver_balance = balances.get(&tx.to).copied().unwrap_or(0);
            
            if sender_balance >= tx.amount {
                let new_sender_balance = sender_balance - tx.amount;
                let new_receiver_balance = receiver_balance + tx.amount;
                
                *balances.entry(tx.from).or_insert(0) = new_sender_balance;
                *balances.entry(tx.to).or_insert(0) = new_receiver_balance;
                
                info!(
                    from = tx.from,
                    to = tx.to,
                    amount = tx.amount,
                    from_balance_before = sender_balance,
                    from_balance_after = new_sender_balance,
                    to_balance_before = receiver_balance,
                    to_balance_after = new_receiver_balance,
                    "executed transfer"
                );
            } else {
                warn!(
                    from = tx.from,
                    to = tx.to,
                    amount = tx.amount,
                    balance = sender_balance,
                    "insufficient balance (should not happen after verification)"
                );
            }
        }
        
        info!(
            height = block.height,
            total_accounts = balances.len(),
            "state updated after block finalization"
        );
    }
}

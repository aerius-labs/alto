use alto_types::Transaction;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Mempool {
    transactions: Arc<Mutex<VecDeque<Transaction>>>,
    max_size: usize,
}

impl Mempool {
    pub fn new(max_size: usize) -> Self {
        Self {
            transactions: Arc::new(Mutex::new(VecDeque::new())),
            max_size,
        }
    }

    pub fn add(&self, tx: Transaction) -> bool {
        let mut txs = self.transactions.lock().unwrap();
        if txs.len() >= self.max_size {
            return false;
        }
        txs.push_back(tx);
        true
    }

    pub fn take(&self, max_count: usize) -> Vec<Transaction> {
        let mut txs = self.transactions.lock().unwrap();
        let mut result = Vec::new();
        for _ in 0..max_count {
            if let Some(tx) = txs.pop_front() {
                result.push(tx);
            } else {
                break;
            }
        }
        result
    }

    pub fn len(&self) -> usize {
        self.transactions.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.transactions.lock().unwrap().is_empty()
    }

    pub fn clear(&self) {
        self.transactions.lock().unwrap().clear();
    }

    pub fn max_size(&self) -> usize {
        self.max_size
    }
}

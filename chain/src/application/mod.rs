mod actor;
pub use actor::Actor;
mod ingress;
pub use ingress::Mailbox;
mod mempool;
pub use mempool::Mempool;

#[cfg(test)]
mod tests;

/// Configuration for the application.
pub struct Config {
    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,
    pub mempool_max_size: usize,
}

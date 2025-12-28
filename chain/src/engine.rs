use crate::{application, indexer, indexer::Indexer, StaticSchemeProvider};
use alto_types::{Activity, Block, Scheme, EPOCH, EPOCH_LENGTH, NAMESPACE};
use commonware_broadcast::buffered;
use commonware_consensus::{
    marshal::{self, ingress::handler},
    simplex::{self, elector::Random, Engine as Consensus, types::Finalization},
    types::{Epoch, FixedEpocher, ViewDelta},
    Reporters,
};
use commonware_cryptography::{
    bls12381::primitives::{group, sharing::Sharing, variant::MinSig},
    ed25519::PublicKey,
    sha256::Digest,
};

// Type alias to avoid G2 inference issues
type Polynomial = Sharing<MinSig>;
use commonware_p2p::{Blocker, Receiver, Sender};
use commonware_resolver::Resolver;
use commonware_runtime::{
    buffer::PoolRef, spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::archive::immutable;
use commonware_utils::ordered::Set;
use commonware_utils::{NZUsize, NZU64};
use futures::{channel::mpsc, future::try_join_all};
use governor::clock::Clock as GClock;
use governor::Quota;
use rand::{CryptoRng, Rng};
use std::{num::NonZero, time::Duration};
use tracing::{error, warn};

/// Reporter type for [simplex::Engine].
type Reporter<E, I> =
    Reporters<
        Activity,
        marshal::Mailbox<Scheme, Block>,
        Option<indexer::Pusher<E, I>>,
    >;

/// To better support peers near tip during network instability, we multiply
/// the consensus activity timeout by this factor.
const SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER: u64 = 10;
const PRUNABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(4_096);
const IMMUTABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(262_144);
const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16); // 3MB
const FREEZER_JOURNAL_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const FREEZER_JOURNAL_COMPRESSION: Option<u8> = Some(3);
const REPLAY_BUFFER: NonZero<usize> = NZUsize!(8 * 1024 * 1024); // 8MB
const WRITE_BUFFER: NonZero<usize> = NZUsize!(1024 * 1024); // 1MB
const BUFFER_POOL_PAGE_SIZE: NonZero<usize> = NZUsize!(4_096); // 4KB
const BUFFER_POOL_CAPACITY: NonZero<usize> = NZUsize!(8_192); // 32MB
const MAX_REPAIR: u64 = 20;

/// Configuration for the [Engine].
pub struct Config<B: Blocker<PublicKey = PublicKey>, I: Indexer> {
    pub blocker: B,
    pub partition_prefix: String,
    pub blocks_freezer_table_initial_size: u32,
    pub finalized_freezer_table_initial_size: u32,
    pub me: PublicKey,
    pub polynomial: Polynomial,
    pub share: group::Share,
    pub participants: Set<PublicKey>,
    pub mailbox_size: usize,
    pub deque_size: usize,

    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,
    pub fetch_timeout: Duration,
    pub activity_timeout: u64,
    pub skip_timeout: u64,
    pub max_fetch_count: usize,
    pub max_fetch_size: usize,
    pub fetch_concurrent: usize,
    pub fetch_rate_per_peer: Quota,

    pub indexer: Option<I>,
}

/// The engine that drives the [application].
pub struct Engine<
    E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
    B: Blocker<PublicKey = PublicKey>,
    I: Indexer,
> {
    context: ContextCell<E>,

    application: application::Actor<E>,
    application_mailbox: application::Mailbox,
    buffer: buffered::Engine<E, PublicKey, Block>,
    buffer_mailbox: buffered::Mailbox<PublicKey, Block>,
    marshal: marshal::Actor<
        E,
        Block,
        StaticSchemeProvider,
        immutable::Archive<E, Digest, Finalization<Scheme, Digest>>,
        immutable::Archive<E, Digest, Block>,
        FixedEpocher,
    >,
    marshal_mailbox: marshal::Mailbox<Scheme, Block>,

    consensus: Consensus<
        E,
        Scheme,
        Random,
        B,
        Digest,
        application::Mailbox,
        application::Mailbox,
        Reporter<E, I>,
    >,
}

impl<
        E: Clock + GClock + Rng + CryptoRng + Spawner + Storage + Metrics,
        B: Blocker<PublicKey = PublicKey>,
        I: Indexer,
    > Engine<E, B, I>
{
    /// Create a new [Engine].
    pub async fn new_with_mempool(
        context: E,
        cfg: Config<B, I>,
    ) -> Result<(
        Self,
        application::Mempool,
        std::sync::Arc<tokio::sync::Mutex<std::option::Option<commonware_storage::qmdb::current::ordered::fixed::Db<E, commonware_utils::sequence::FixedBytes<8>, u64, commonware_cryptography::Sha256, commonware_storage::translator::TwoCap, 64>>>>,
    ), commonware_storage::qmdb::Error> {
        // Create the application
        let (application, application_mailbox, mempool, qmdb) = application::Actor::new(
            context.with_label("application"),
            application::Config {
                mailbox_size: cfg.mailbox_size,
                mempool_max_size: 1000,
            },
        ).await?;

        // Create the buffer
        let (buffer, buffer_mailbox) = buffered::Engine::new(
            context.with_label("buffer"),
            buffered::Config {
                public_key: cfg.me.clone(),
                mailbox_size: cfg.mailbox_size,
                deque_size: cfg.deque_size,
                priority: true,
                codec_config: (),
            },
        );

        // Create the buffer pool
        let buffer_pool = PoolRef::new(BUFFER_POOL_PAGE_SIZE, BUFFER_POOL_CAPACITY);

        // Create the signing scheme
        let scheme = Scheme::signer(
            cfg.participants.clone(),
            cfg.polynomial.clone(),
            cfg.share,
        )
        .expect("share must match participant");

        // Initialize finalizations by height
        let finalizations_by_height = immutable::Archive::init(
            context.with_label("finalizations_by_height"),
            immutable::Config {
                metadata_partition: format!(
                    "{}-finalizations-by-height-metadata",
                    cfg.partition_prefix
                ),
                freezer_table_partition: format!(
                    "{}-finalizations-by-height-freezer-table",
                    cfg.partition_prefix
                ),
                freezer_table_initial_size: cfg.finalized_freezer_table_initial_size,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
                freezer_journal_partition: format!(
                    "{}-finalizations-by-height-freezer-journal",
                    cfg.partition_prefix
                ),
                freezer_journal_target_size: FREEZER_JOURNAL_TARGET_SIZE,
                freezer_journal_compression: FREEZER_JOURNAL_COMPRESSION,
                freezer_journal_buffer_pool: buffer_pool.clone(),
                ordinal_partition: format!(
                    "{}-finalizations-by-height-ordinal",
                    cfg.partition_prefix
                ),
                items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                codec_config: (), // Unbounded codec config for certificates
                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,
            },
        )
        .await
        .expect("failed to initialize finalizations by height archive");

        // Initialize finalized blocks
        let finalized_blocks = immutable::Archive::init(
            context.with_label("finalized_blocks"),
            immutable::Config {
                metadata_partition: format!("{}-finalized_blocks-metadata", cfg.partition_prefix),
                freezer_table_partition: format!(
                    "{}-finalized_blocks-freezer-table",
                    cfg.partition_prefix
                ),
                freezer_table_initial_size: cfg.blocks_freezer_table_initial_size,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
                freezer_journal_partition: format!(
                    "{}-finalized_blocks-freezer-journal",
                    cfg.partition_prefix
                ),
                freezer_journal_target_size: FREEZER_JOURNAL_TARGET_SIZE,
                freezer_journal_compression: FREEZER_JOURNAL_COMPRESSION,
                freezer_journal_buffer_pool: buffer_pool.clone(),
                ordinal_partition: format!("{}-finalized_blocks-ordinal", cfg.partition_prefix),
                items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                codec_config: (), // Block codec config
                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");

        // Create marshal
        let (marshal, marshal_mailbox, _processed_height) = marshal::Actor::init(
            context.with_label("marshal"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider: scheme.clone().into(),
                epocher: FixedEpocher::new(NZU64!(EPOCH_LENGTH)),
                partition_prefix: cfg.partition_prefix.clone(),
                mailbox_size: cfg.mailbox_size,
                view_retention_timeout: ViewDelta::new(
                    cfg.activity_timeout
                        .saturating_mul(SYNCER_ACTIVITY_TIMEOUT_MULTIPLIER),
                ),
                namespace: NAMESPACE.to_vec(),
                prunable_items_per_section: PRUNABLE_ITEMS_PER_SECTION,
                buffer_pool: buffer_pool.clone(),
                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,
                block_codec_config: (),
                max_repair: NZUsize!(MAX_REPAIR as usize),
            },
        )
        .await;

        // Create the reporter
        let reporter = (
            marshal_mailbox.clone(),
            cfg.indexer.map(|indexer| {
                indexer::Pusher::new(
                    context.with_label("indexer"),
                    indexer,
                    marshal_mailbox.clone(),
                )
            }),
        )
            .into();

        // Create the consensus engine
        let consensus = Consensus::new(
            context.with_label("consensus"),
            simplex::Config {
                epoch: Epoch::new(EPOCH),
                namespace: NAMESPACE.to_vec(),
                scheme: scheme.clone(),
                elector: Random,
                automaton: application_mailbox.clone(),
                relay: application_mailbox.clone(),
                reporter,
                partition: format!("{}-consensus", cfg.partition_prefix),
                mailbox_size: cfg.mailbox_size,
                leader_timeout: cfg.leader_timeout,
                notarization_timeout: cfg.notarization_timeout,
                nullify_retry: cfg.nullify_retry,
                fetch_timeout: cfg.fetch_timeout,
                activity_timeout: ViewDelta::new(cfg.activity_timeout),
                skip_timeout: ViewDelta::new(cfg.skip_timeout),
                fetch_concurrent: cfg.fetch_concurrent,
                replay_buffer: REPLAY_BUFFER,
                write_buffer: WRITE_BUFFER,
                blocker: cfg.blocker,
                buffer_pool,
            },
        );

        // Return the engine, mempool, and qmdb
        Ok((
            Self {
                context: ContextCell::new(context),

                application,
                application_mailbox,
                buffer,
                buffer_mailbox,
                marshal,
                marshal_mailbox,
                consensus,
            },
            mempool,
            qmdb,
        ))
    }

    /// Create a new [Engine] (for backward compatibility).
    pub async fn new(
        context: E,
        cfg: Config<B, I>,
    ) -> Result<(
        Self,
        application::Mempool,
        std::sync::Arc<tokio::sync::Mutex<std::option::Option<commonware_storage::qmdb::current::ordered::fixed::Db<E, commonware_utils::sequence::FixedBytes<8>, u64, commonware_cryptography::Sha256, commonware_storage::translator::TwoCap, 64>>>>,
    ), commonware_storage::qmdb::Error> {
        Self::new_with_mempool(context, cfg).await
    }

    /// Start the [simplex::Engine].
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        mut self,
        pending: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        recovered: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        resolver: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        broadcast: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        marshal: (
            mpsc::Receiver<handler::Message<Block>>,
            impl Resolver<Key = handler::Request<Block>, PublicKey = PublicKey>,
        ),
    ) -> Handle<()> {
        spawn_cell!(
            self.context,
            self.run(pending, recovered, resolver, broadcast, marshal,)
                .await
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn run(
        self,
        pending: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        recovered: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        resolver: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        broadcast: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        marshal: (
            mpsc::Receiver<handler::Message<Block>>,
            impl Resolver<Key = handler::Request<Block>, PublicKey = PublicKey>,
        ),
    ) {
        // Start the application
        let application_handle = self.application.start(self.marshal_mailbox);

        // Start the buffer
        let buffer_handle = self.buffer.start(broadcast);

        // Start marshal
        let marshal_handle =
            self.marshal
                .start(self.application_mailbox, self.buffer_mailbox, marshal);

        // Start consensus
        //
        // We start the application prior to consensus to ensure we can handle enqueued events from consensus (otherwise
        // restart could block).
        let consensus_handle = self.consensus.start(pending, recovered, resolver);

        // Wait for any actor to finish
        if let Err(e) = try_join_all(vec![
            application_handle,
            buffer_handle,
            marshal_handle,
            consensus_handle,
        ])
        .await
        {
            error!(?e, "engine failed");
        } else {
            warn!("engine stopped");
        }
    }
}

use super::*;
use alto_types::Block;
use commonware_consensus::{marshal::Update, Reporter};
use commonware_cryptography::{sha256::Digest, Digestible};
use commonware_macros::{select, test_traced};
use commonware_runtime::{
    deterministic::Runner,
    Clock, Metrics, Runner as _,
};
use commonware_utils::{acknowledgement::{Acknowledgement, Exact}, SystemTimeExt};
use futures::FutureExt;
use std::time::Duration;

const SYSTEM_ACCOUNT_ID: u64 = 0;

#[test_traced]
fn test_account_creation_transaction() {
    let executor = Runner::seeded(42);
    executor.start(|context| async move {
        let config = crate::application::Config {
            mailbox_size: 1024,
            mempool_max_size: 1000,
        };
        let (actor, mailbox, _mempool, qmdb, _public_keys) =
            setup_test_actor(context.with_label("actor"), config)
                .await
                .expect("Failed to create actor");

        let initial_root = get_state_root_from_qmdb(&qmdb).await.unwrap();
        let genesis_digest = Digest::from([0u8; 32]);
        let genesis = Block::new(
            genesis_digest,
            0,
            context.current().epoch_millis(),
            vec![],
            initial_root,
        );

        // Create account creation transaction
        let (system_key, _) = create_genesis_account_keypair(SYSTEM_ACCOUNT_ID);
        let (_, new_account_pub) = create_genesis_account_keypair(10);
        
        let tx = create_test_transaction(
            SYSTEM_ACCOUNT_ID,
            10, // New account ID
            500, // Initial balance
            0, // System account nonce
            system_key,
            Some(new_account_pub),
            true, // is_account_creation
        );

        let block = create_test_block(
            genesis.digest(),
            1,
            context.current().epoch_millis(),
            vec![tx],
            initial_root, // Placeholder
        );

        // Create marshal mailbox
        let marshal_mailbox = create_test_marshal_mailbox(context.with_label("marshal"))
            .await
            .expect("Failed to create marshal mailbox");
        let actor_handle = actor.start(marshal_mailbox);

        let (ack, _waiter) = Exact::handle();
        let mut mailbox_clone = mailbox.clone();
        mailbox_clone
            .report(Update::Block(block, ack.clone()))
            .await;

        context.sleep(Duration::from_millis(200)).await;

        // Verify state root changed
        let final_root = get_state_root_from_qmdb(&qmdb).await.unwrap();
        assert_ne!(final_root, initial_root, "State root should change after account creation");
        
        // Verify new account was created
        let balance_10 = get_balance_from_qmdb(&qmdb, 10).await.unwrap();
        assert_eq!(balance_10, 500, "New account should have initial balance of 500");
        
        let nonce_10 = get_nonce_from_qmdb(&qmdb, 10).await.unwrap();
        assert_eq!(nonce_10, 0, "New account should have nonce 0");
        
        // Verify system account nonce incremented
        let system_nonce = get_nonce_from_qmdb(&qmdb, SYSTEM_ACCOUNT_ID).await.unwrap();
        assert_eq!(system_nonce, 1, "System account nonce should be incremented");

        // Close mailbox to signal actor to exit
        drop(mailbox_clone);
        drop(mailbox);
        context.sleep(Duration::from_millis(50)).await;
        select! {
            result = actor_handle.fuse() => {
                result.expect("Actor should exit cleanly");
            },
            _ = context.sleep(Duration::from_millis(100)).fuse() => {}
        }

        context.auditor().state()
    });
}

#[test_traced]
fn test_account_creation_invalid_account_id() {
    let executor = Runner::seeded(42);
    executor.start(|context| async move {
        let config = crate::application::Config {
            mailbox_size: 1024,
            mempool_max_size: 1000,
        };
        let (actor, mailbox, _mempool, qmdb, _public_keys) =
            setup_test_actor(context.with_label("actor"), config)
                .await
                .expect("Failed to create actor");

        let initial_root = get_state_root_from_qmdb(&qmdb).await.unwrap();
        let genesis_digest = Digest::from([0u8; 32]);
        let genesis = Block::new(
            genesis_digest,
            0,
            context.current().epoch_millis(),
            vec![],
            initial_root,
        );

        // Try to create account with ID < 10 (reserved for genesis)
        let (system_key, _) = create_genesis_account_keypair(SYSTEM_ACCOUNT_ID);
        let (_, new_account_pub) = create_genesis_account_keypair(5);
        
        let tx = create_test_transaction(
            SYSTEM_ACCOUNT_ID,
            5, // Invalid: < 10
            500,
            0,
            system_key,
            Some(new_account_pub),
            true,
        );

        let block = create_test_block(
            genesis.digest(),
            1,
            context.current().epoch_millis(),
            vec![tx],
            initial_root,
        );

        // Create marshal mailbox
        let marshal_mailbox = create_test_marshal_mailbox(context.with_label("marshal"))
            .await
            .expect("Failed to create marshal mailbox");
        let actor_handle = actor.start(marshal_mailbox);

        let (ack, _waiter) = Exact::handle();
        let mut mailbox_clone = mailbox.clone();
        mailbox_clone
            .report(Update::Block(block, ack.clone()))
            .await;

        context.sleep(Duration::from_millis(200)).await;

        // Verify state root unchanged (transaction should be rejected)
        let final_root = get_state_root_from_qmdb(&qmdb).await.unwrap();
        assert_eq!(final_root, initial_root, "State root should remain unchanged after invalid account creation");

        // Close mailbox to signal actor to exit
        drop(mailbox_clone);
        drop(mailbox);
        context.sleep(Duration::from_millis(50)).await;
        select! {
            result = actor_handle.fuse() => {
                result.expect("Actor should exit cleanly");
            },
            _ = context.sleep(Duration::from_millis(100)).fuse() => {}
        }

        context.auditor().state()
    });
}

#[test_traced]
fn test_account_creation_missing_public_key() {
    let executor = Runner::seeded(42);
    executor.start(|context| async move {
        let config = crate::application::Config {
            mailbox_size: 1024,
            mempool_max_size: 1000,
        };
        let (actor, mailbox, _mempool, qmdb, _public_keys) =
            setup_test_actor(context.with_label("actor"), config)
                .await
                .expect("Failed to create actor");

        let initial_root = get_state_root_from_qmdb(&qmdb).await.unwrap();
        let genesis_digest = Digest::from([0u8; 32]);
        let genesis = Block::new(
            genesis_digest,
            0,
            context.current().epoch_millis(),
            vec![],
            initial_root,
        );

        // Try to create account without public key
        let (system_key, _) = create_genesis_account_keypair(SYSTEM_ACCOUNT_ID);
        
        let tx = create_test_transaction(
            SYSTEM_ACCOUNT_ID,
            10,
            500,
            0,
            system_key,
            None, // Missing public key
            true,
        );

        let block = create_test_block(
            genesis.digest(),
            1,
            context.current().epoch_millis(),
            vec![tx],
            initial_root,
        );

        // Create marshal mailbox
        let marshal_mailbox = create_test_marshal_mailbox(context.with_label("marshal"))
            .await
            .expect("Failed to create marshal mailbox");
        let actor_handle = actor.start(marshal_mailbox);

        let (ack, _waiter) = Exact::handle();
        let mut mailbox_clone = mailbox.clone();
        mailbox_clone
            .report(Update::Block(block, ack.clone()))
            .await;

        context.sleep(Duration::from_millis(200)).await;

        // When execute_transactions returns an error (missing public key), it restores QMDB.
        // Check if account was created (it shouldn't be)
        let balance_10 = get_balance_from_qmdb(&qmdb, 10).await;
        assert!(balance_10.is_none() || balance_10 == Some(0), "Account 10 should not exist (transaction failed due to missing public key)");

        // Close mailbox to signal actor to exit
        drop(mailbox_clone);
        drop(mailbox);
        context.sleep(Duration::from_millis(50)).await;
        select! {
            result = actor_handle.fuse() => {
                result.expect("Actor should exit cleanly");
            },
            _ = context.sleep(Duration::from_millis(100)).fuse() => {}
        }

        context.auditor().state()
    });
}

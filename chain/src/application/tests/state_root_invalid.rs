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

#[test_traced]
fn test_invalid_transaction_insufficient_balance() {
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

        // Create transaction with amount exceeding balance (genesis balance is 1000)
        let (private_key, _) = create_genesis_account_keypair(1);
        let tx = create_test_transaction(1, 2, 2000, 0, private_key, None, false); // Amount > balance

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

        // Verify state root unchanged (transaction should be rejected)
        let final_root = get_state_root_from_qmdb(&qmdb).await.unwrap();
        assert_eq!(final_root, initial_root, "State root should remain unchanged after invalid transaction");
        
        // Verify balances unchanged
        let balance_1 = get_balance_from_qmdb(&qmdb, 1).await.unwrap();
        let balance_2 = get_balance_from_qmdb(&qmdb, 2).await.unwrap();
        assert_eq!(balance_1, 1000, "Account 1 balance should remain 1000 (transaction rejected)");
        assert_eq!(balance_2, 1000, "Account 2 balance should remain 1000 (transaction rejected)");

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
fn test_invalid_transaction_wrong_nonce() {
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

        // Create transaction with wrong nonce (should be 0, but using 1)
        let (private_key, _) = create_genesis_account_keypair(1);
        let tx = create_test_transaction(1, 2, 100, 1, private_key, None, false); // Nonce should be 0

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

        // Note: execute_transactions doesn't check nonce - it assumes transactions have been verified.
        // So a transaction with wrong nonce will still execute. This test verifies that behavior.
        // In production, verification happens before finalization, so wrong nonce transactions
        // would be rejected during verification, not execution.
        
        // Verify transaction was executed (nonce check doesn't happen in execute_transactions)
        let final_root = get_state_root_from_qmdb(&qmdb).await.unwrap();
        // State root should change because transaction was executed
        assert_ne!(final_root, initial_root, "State root should change (transaction executed despite wrong nonce)");
        
        // Verify balances changed (transaction was executed)
        let balance_1 = get_balance_from_qmdb(&qmdb, 1).await.unwrap();
        let balance_2 = get_balance_from_qmdb(&qmdb, 2).await.unwrap();
        assert_eq!(balance_1, 900, "Account 1 balance should be 900 (transaction executed)");
        assert_eq!(balance_2, 1100, "Account 2 balance should be 1100 (transaction executed)");
        
        // Verify nonce was incremented (transaction was executed)
        let nonce_1 = get_nonce_from_qmdb(&qmdb, 1).await.unwrap();
        assert_eq!(nonce_1, 1, "Account 1 nonce should be 1 (transaction executed)");

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
fn test_state_root_verification_mismatch() {
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

        // Create a valid transaction
        let (private_key, _) = create_genesis_account_keypair(1);
        let tx = create_test_transaction(1, 2, 100, 0, private_key, None, false);

        // Create block with WRONG state root (different from what execution will produce)
        let wrong_state_root = Digest::from([0xFF; 32]);
        let block = create_test_block(
            genesis.digest(),
            1,
            context.current().epoch_millis(),
            vec![tx],
            wrong_state_root, // Wrong state root
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

        // The actor will execute the transaction and compute the correct root
        // It will log a warning about the mismatch, but the transaction will still be executed
        // So we verify the state changed (transaction was executed)
        let final_root = get_state_root_from_qmdb(&qmdb).await.unwrap();
        assert_ne!(final_root, initial_root, "State root should change after transaction execution");
        assert_ne!(final_root, wrong_state_root, "Computed root should not match the wrong state root in block");
        
        // Verify state changes were applied (transaction was executed despite wrong state_root in block)
        let balance_1 = get_balance_from_qmdb(&qmdb, 1).await.unwrap();
        let balance_2 = get_balance_from_qmdb(&qmdb, 2).await.unwrap();
        assert_eq!(balance_1, 900, "Account 1 balance should be 900 (transaction was executed)");
        assert_eq!(balance_2, 1100, "Account 2 balance should be 1100 (transaction was executed)");

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

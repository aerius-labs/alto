// Simple script to generate a test transaction
// Compile with: rustc --edition 2021 generate_test_tx.rs --extern commonware_codec --extern commonware_cryptography --extern commonware_utils --extern rand --extern hex
// Or better: cargo run --example generate_test_tx

use alto_types::NAMESPACE;
use commonware_codec::{varint::UInt, Write};
use commonware_cryptography::{
    ed25519::PrivateKey,
    Hasher, Sha256, Signer,
};
use commonware_math::algebra::Random;
use commonware_utils::hex;
use rand::{rngs::StdRng, SeedableRng};

fn main() {
    // Transaction details
    let from = 0u64;
    let to = 11u64;
    let amount = 50u64;
    let nonce = 0u64;
    
    // Generate deterministic keypair matching genesis
    // Account 0 uses SYSTEM_ACCOUNT_SEED, accounts 1-9 use account-index-based seed
    const SYSTEM_ACCOUNT_ID: u64 = 0;
    const SYSTEM_ACCOUNT_SEED: [u8; 32] = [0xFF; 32];
    
    let (private_key, public_key) = if from == SYSTEM_ACCOUNT_ID {
        // System account uses special seed
        let mut rng = StdRng::from_seed(SYSTEM_ACCOUNT_SEED);
        let pk = PrivateKey::random(&mut rng);
        (pk.clone(), pk.public_key())
    } else {
        // Other genesis accounts use account-index-based seed
        let mut seed = [0u8; 32];
        seed[0..8].copy_from_slice(&from.to_be_bytes());
        let mut rng = StdRng::from_seed(seed);
        let pk = PrivateKey::random(&mut rng);
        (pk.clone(), pk.public_key())
    };
    
    // Generate receiver's keypair if sending to non-existent account (to >= 10)
    // For accounts < 10, they already exist in genesis, so to_public_key should be None
    let (to_public_key, to_public_key_hex) = if to >= 10 {
        // Generate a new keypair for the receiver (using deterministic seed based on account ID for reproducibility)
        let mut seed = [0u8; 32];
        seed[0..8].copy_from_slice(&to.to_be_bytes());
        let mut rng = StdRng::from_seed(seed);
        let receiver_pk = PrivateKey::random(&mut rng);
        let receiver_public_key = receiver_pk.public_key();
        let mut receiver_pk_buf = Vec::new();
        receiver_public_key.write(&mut receiver_pk_buf);
        let receiver_pk_hex = hex(&receiver_pk_buf);
        (Some(receiver_public_key), Some(receiver_pk_hex))
    } else {
        // Receiver is a genesis account, no to_public_key needed
        (None, None)
    };
    
    // Compute transaction hash (must match actor.rs::compute_transaction_hash)
    let mut hasher = Sha256::new();
    let mut tx_buf = Vec::new();
    UInt(from).write(&mut tx_buf);
    UInt(to).write(&mut tx_buf);
    UInt(amount).write(&mut tx_buf);
    UInt(nonce).write(&mut tx_buf);
    public_key.write(&mut tx_buf);
    
    // Include to_public_key if present
    if let Some(ref pk) = to_public_key {
        tx_buf.push(1);  // Flag: present
        pk.write(&mut tx_buf);
    } else {
        tx_buf.push(0);  // Flag: absent
    }
    
    // Include is_account_creation flag (false for regular transfers)
    tx_buf.push(0);  // Flag: false
    
    hasher.update(NAMESPACE);
    hasher.update(&tx_buf);
    let tx_hash = hasher.finalize();
    
    // Sign transaction
    let signature = private_key.sign(NAMESPACE, tx_hash.as_ref());
    
    // Encode public key and signature to bytes
    let mut pk_buf = Vec::new();
    public_key.write(&mut pk_buf);
    let mut sig_buf = Vec::new();
    signature.write(&mut sig_buf);
    
    let pk_hex = hex(&pk_buf);
    let sig_hex = hex(&sig_buf);
    
    println!("Generated transaction for account {}:", from);
    println!("Sender Public Key: {}", pk_hex);
    println!("Signature: {}", sig_hex);
    if let Some(ref receiver_pk_hex) = to_public_key_hex {
        println!("Receiver Public Key (for auto-creation): {}", receiver_pk_hex);
    }
    println!();
    println!("Transaction JSON:");
    print!("{{");
    print!("\n  \"from\": {},", from);
    print!("\n  \"to\": {},", to);
    print!("\n  \"amount\": {},", amount);
    print!("\n  \"nonce\": {},", nonce);
    print!("\n  \"signature\": \"{}\",", sig_hex);
    print!("\n  \"public_key\": \"{}\"", pk_hex);
    if let Some(ref receiver_pk_hex) = to_public_key_hex {
        print!(",\n  \"to_public_key\": \"{}\"", receiver_pk_hex);
    }
    println!("\n}}");
    println!();
    println!("Curl command:");
    print!("curl -X POST http://localhost:4001/submit \\");
    print!("\n  -H \"Content-Type: application/json\" \\");
    print!("\n  -d '{{\"from\": {}, \"to\": {}, \"amount\": {}, \"nonce\": {}, \"signature\": \"{}\", \"public_key\": \"{}\"", 
             from, to, amount, nonce, sig_hex, pk_hex);
    if let Some(ref receiver_pk_hex) = to_public_key_hex {
        print!(", \"to_public_key\": \"{}\"", receiver_pk_hex);
    }
    println!("}}'");
}


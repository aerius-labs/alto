// Simple script to generate a test transaction
// Compile with: rustc --edition 2021 generate_test_tx.rs --extern commonware_codec --extern commonware_cryptography --extern commonware_utils --extern rand --extern hex
// Or better: cargo run --example generate_test_tx

use alto_types::NAMESPACE;
use commonware_codec::{varint::UInt, Write};
use commonware_cryptography::{
    ed25519::{PrivateKey, PublicKey},
    Hasher, Sha256, Signer,
};
use commonware_math::algebra::Random;
use commonware_utils::hex;
use rand::{rngs::StdRng, SeedableRng};

fn main() {
    // Generate deterministic keypair for account 0 (same as genesis)
    let mut seed = [0u8; 32];
    seed[0..8].copy_from_slice(&0u64.to_be_bytes());
    let mut rng = StdRng::from_seed(seed);
    let private_key = PrivateKey::random(&mut rng);
    let public_key = private_key.public_key();
    
    // Transaction details
    let from = 0u64;
    let to = 1u64;
    let amount = 50u64;
    let nonce = 0u64;
    
    // Compute transaction hash
    let mut hasher = Sha256::new();
    let mut tx_buf = Vec::new();
    UInt(from).write(&mut tx_buf);
    UInt(to).write(&mut tx_buf);
    UInt(amount).write(&mut tx_buf);
    UInt(nonce).write(&mut tx_buf);
    public_key.write(&mut tx_buf);
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
    
    println!("Generated transaction for account 0:");
    println!("Public Key: {}", pk_hex);
    println!("Signature: {}", sig_hex);
    println!();
    println!("Transaction JSON:");
    println!("{{");
    println!("  \"from\": {},", from);
    println!("  \"to\": {},", to);
    println!("  \"amount\": {},", amount);
    println!("  \"nonce\": {},", nonce);
    println!("  \"signature\": \"{}\",", sig_hex);
    println!("  \"public_key\": \"{}\"", pk_hex);
    println!("}}");
    println!();
    println!("Curl command:");
    println!("curl -X POST http://localhost:4001/submit \\");
    println!("  -H \"Content-Type: application/json\" \\");
    println!("  -d '{{\"from\": {}, \"to\": {}, \"amount\": {}, \"nonce\": {}, \"signature\": \"{}\", \"public_key\": \"{}\"}}'", 
             from, to, amount, nonce, sig_hex, pk_hex);
}


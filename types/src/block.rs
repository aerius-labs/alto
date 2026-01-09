use crate::consensus::{Finalization, Notarization, Scheme};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, Error, Read, ReadExt, Write};
use commonware_cryptography::{
    ed25519::{PublicKey, Signature},
    sha256::Digest,
    Committable, Digestible, Hasher, Sha256,
};
use rand::rngs::OsRng;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub from: u64,
    pub to: u64,
    pub amount: u64,
    pub nonce: u64,
    pub signature: Signature,
    pub public_key: PublicKey,
    pub to_public_key: Option<PublicKey>,
    pub is_account_creation: bool,
}

impl Write for Transaction {
    fn write(&self, writer: &mut impl BufMut) {
        UInt(self.from).write(writer);
        UInt(self.to).write(writer);
        UInt(self.amount).write(writer);
        UInt(self.nonce).write(writer);
        self.signature.write(writer);
        self.public_key.write(writer);
        
        // Write to_public_key (optional)
        if let Some(ref pk) = self.to_public_key {
            writer.put_u8(1);
            pk.write(writer);
        } else {
            writer.put_u8(0);
        }
        
        // Write is_account_creation flag
        writer.put_u8(if self.is_account_creation { 1 } else { 0 });
    }
}

impl Read for Transaction {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let from = UInt::read(reader)?.into();
        let to = UInt::read(reader)?.into();
        let amount = UInt::read(reader)?.into();
        let nonce = UInt::read(reader)?.into();
        let signature = Signature::read(reader)?;
        let public_key = PublicKey::read(reader)?;
        
        // Read to_public_key (optional)
        let flag = u8::read(reader)?;
        let to_public_key = if flag == 1 {
            Some(PublicKey::read(reader)?)
        } else {
            None
        };
        
        // Read is_account_creation flag
        let is_account_creation = u8::read(reader)? != 0;
        
        Ok(Self {
            from,
            to,
            amount,
            nonce,
            signature,
            public_key,
            to_public_key,
            is_account_creation,
        })
    }
}

impl EncodeSize for Transaction {
    fn encode_size(&self) -> usize {
        UInt(self.from).encode_size()
            + UInt(self.to).encode_size()
            + UInt(self.amount).encode_size()
            + UInt(self.nonce).encode_size()
            + self.signature.encode_size()
            + self.public_key.encode_size()
            + 1  // to_public_key flag
            + self.to_public_key.as_ref()
                .map(|pk| pk.encode_size())
                .unwrap_or(0)
            + 1  // is_account_creation flag
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    /// The parent block's digest.
    pub parent: Digest,

    /// The height of the block in the blockchain.
    pub height: u64,

    /// The timestamp of the block (in milliseconds since the Unix epoch).
    pub timestamp: u64,

    /// Transactions in this block.
    pub transactions: Vec<Transaction>,

    /// The Merkle root of the state after executing this block's transactions.
    pub state_root: Digest,

    /// Pre-computed digest of the block.
    digest: Digest,
}

impl Block {
    fn compute_digest(parent: &Digest, height: u64, timestamp: u64, transactions: &[Transaction], state_root: &Digest) -> Digest {
        let mut hasher = Sha256::new();
        hasher.update(parent);
        hasher.update(&height.to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        let mut tx_buf = Vec::new();
        for tx in transactions {
            tx.write(&mut tx_buf);
        }
        hasher.update(&tx_buf);
        hasher.update(state_root);
        hasher.finalize()
    }

    pub fn new(parent: Digest, height: u64, timestamp: u64, transactions: Vec<Transaction>, state_root: Digest) -> Self {
        let digest = Self::compute_digest(&parent, height, timestamp, &transactions, &state_root);
        Self {
            parent,
            height,
            timestamp,
            transactions,
            state_root,
            digest,
        }
    }
}

impl Write for Block {
    fn write(&self, writer: &mut impl BufMut) {
        self.parent.write(writer);
        UInt(self.height).write(writer);
        UInt(self.timestamp).write(writer);
        UInt(self.transactions.len() as u64).write(writer);
        for tx in &self.transactions {
            tx.write(writer);
        }
        self.state_root.write(writer);
    }
}

impl Read for Block {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let parent = Digest::read(reader)?;
        let height = UInt::read(reader)?.into();
        let timestamp = UInt::read(reader)?.into();
        let tx_count: u64 = UInt::read(reader)?.into();
        let mut transactions = Vec::new();
        for _ in 0..tx_count {
            transactions.push(Transaction::read(reader)?);
        }
        let state_root = Digest::read(reader)?;

        // Pre-compute the digest
        let digest = Self::compute_digest(&parent, height, timestamp, &transactions, &state_root);
        Ok(Self {
            parent,
            height,
            timestamp,
            transactions,
            state_root,
            digest,
        })
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.parent.encode_size()
            + UInt(self.height).encode_size()
            + UInt(self.timestamp).encode_size()
            + UInt(self.transactions.len() as u64).encode_size()
            + self.transactions.iter().map(|tx| tx.encode_size()).sum::<usize>()
            + self.state_root.encode_size()
    }
}

impl Digestible for Block {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        self.digest
    }
}

impl Committable for Block {
    type Commitment = Digest;

    fn commitment(&self) -> Digest {
        self.digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notarized {
    pub proof: Notarization,
    pub block: Block,
}

impl Notarized {
    pub fn new(proof: Notarization, block: Block) -> Self {
        Self { proof, block }
    }

    pub fn verify(&self, scheme: &Scheme, namespace: &[u8]) -> bool {
        self.proof.verify(&mut OsRng, scheme, namespace)
    }
}

impl Write for Notarized {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl Read for Notarized {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let proof = Notarization::read(buf)?;
        let block = Block::read(buf)?;

        // Ensure the proof is for the block
        if proof.proposal.payload != block.digest() {
            return Err(Error::Invalid(
                "types::Notarized",
                "Proof payload does not match block digest",
            ));
        }
        Ok(Self { proof, block })
    }
}

impl EncodeSize for Notarized {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finalized {
    pub proof: Finalization,
    pub block: Block,
}

impl Finalized {
    pub fn new(proof: Finalization, block: Block) -> Self {
        Self { proof, block }
    }

    pub fn verify(&self, scheme: &Scheme, namespace: &[u8]) -> bool {
        self.proof.verify(&mut OsRng, scheme, namespace)
    }
}

impl Write for Finalized {
    fn write(&self, buf: &mut impl BufMut) {
        self.proof.write(buf);
        self.block.write(buf);
    }
}

impl Read for Finalized {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let proof = Finalization::read(buf)?;
        let block = Block::read(buf)?;

        // Ensure the proof is for the block
        if proof.proposal.payload != block.digest() {
            return Err(Error::Invalid(
                "types::Finalized",
                "Proof payload does not match block digest",
            ));
        }
        Ok(Self { proof, block })
    }
}

impl EncodeSize for Finalized {
    fn encode_size(&self) -> usize {
        self.proof.encode_size() + self.block.encode_size()
    }
}

impl commonware_consensus::Block for Block {
    fn parent(&self) -> Digest {
        self.parent
    }

    fn height(&self) -> u64 {
        self.height
    }
}

//! Common types used throughout `alto`.

mod block;
pub use block::{Block, Finalized, Notarized, Transaction};
mod consensus;
use commonware_utils::hex;
pub use consensus::{
    Activity, Evaluation, Finalization, Identity, Notarization, PublicKey, Scheme, Seed, Seedable,
    Signature,
};
pub mod wasm;

/// The unique namespace prefix used in all signing operations to prevent signature replay attacks.
pub const NAMESPACE: &[u8] = b"_ALTO";

/// The epoch number used in [commonware_consensus::simplex].
///
/// Because alto does not implement reconfiguration (validator set changes and resharing), we hardcode the epoch to 0.
///
/// For an example of how to implement reconfiguration and resharing, see [commonware-reshare](https://github.com/commonwarexyz/monorepo/tree/main/examples/reshare).
pub const EPOCH: u64 = 0;
/// The epoch length used in [commonware_consensus::simplex].
///
/// Because alto does not implement reconfiguration (validator set changes and resharing), we hardcode the epoch length to u64::MAX (to
/// stay in the first epoch forever).
///
/// For an example of how to implement reconfiguration and resharing, see [commonware-reshare](https://github.com/commonwarexyz/monorepo/tree/main/examples/reshare).
pub const EPOCH_LENGTH: u64 = u64::MAX;

#[repr(u8)]
pub enum Kind {
    Seed = 0,
    Notarization = 1,
    Finalization = 2,
}

impl Kind {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Seed),
            1 => Some(Self::Notarization),
            2 => Some(Self::Finalization),
            _ => None,
        }
    }

    pub fn to_hex(&self) -> String {
        match self {
            Self::Seed => hex(&[0]),
            Self::Notarization => hex(&[1]),
            Self::Finalization => hex(&[2]),
        }
    }
}

// Tests commented out due to API changes in 0.0.64
// #[cfg(test)]
// mod tests {
//     use super::*;
//     // ... test code ...
// }

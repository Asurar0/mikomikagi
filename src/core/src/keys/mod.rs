//! ## Keys
//! 
//! Definition of all generic key structure and their according methods
//! 

// ---------------------------------- Imports --------------------------------------

use borsh::{BorshDeserialize, BorshSerialize};

// Generic DSA key structure
mod signature;
pub use signature::*;

// Generic KEM key structure
mod encapsulation;
pub use encapsulation::*;

// Key encryption at rest
mod encryption;
pub use encryption::*;

// ---------------------------------- Definition --------------------------------------

#[derive(Clone, Copy, BorshSerialize, BorshDeserialize)]
#[repr(transparent)]
/// Public key fingerprint H(H(owner_name), pk)
pub struct Fingerprint([u8;32]);

// ---------------------------------- Implementation --------------------------------------

impl AsRef<[u8]> for Fingerprint {
    
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8;32]> for Fingerprint {
    
    fn from(value: [u8;32]) -> Self {
        Self(value)
    }
}

impl From<Fingerprint> for [u8;32] {
    fn from(value: Fingerprint) -> Self {
        value.0
    }
}

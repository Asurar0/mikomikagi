// ---------------------------------- Imports --------------------------------------

use mikomikagi_core::keys::EncryptionMethod;

use crate::error::Error;

// ---------------------------------- Definitions --------------------------------------

/// This trait is an abstraction to serialize and deserialize cryptographic resources, independently of the originating library/implementation
pub trait Parseable: Clone {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Result<Self,Error>;
}

#[derive(Clone)]
/// Encryption parameters used during private key generation (or re-encryption)
pub struct EncryptionArguments<'key> {
    /// Encryption algorithm to use
    pub algorithm: EncryptionMethod,
    /// Reference to encryption key
    pub key: &'key [u8],
    /// (Optional) Password derivation salt
    pub salt: Option<Vec<u8>>
}

impl<'key> EncryptionArguments<'key> {
    
    /// Create a new encryption parameters for keypair generation or private key reencryption
    pub fn new(algorithm: EncryptionMethod, key: &'key [u8], salt: Option<Vec<u8>>) -> Self {
        Self {
            algorithm, 
            key, 
            salt 
        }
    }
    
    #[inline(always)]
    /// Return the key bytes from the encryption parameters
    pub fn key(&self) -> &[u8] {
        self.key
    }
}

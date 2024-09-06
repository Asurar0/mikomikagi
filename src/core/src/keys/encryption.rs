//! ## Key encryption
//! 
//! This module define the EncryptionParameters structure that contain informations about the encryption of generic private keys
//! 

use borsh::{BorshDeserialize, BorshSerialize};

#[derive(BorshSerialize, BorshDeserialize)]
/// Stores what encryption algorithm is used on a private key, the nonce, and an optional derivation
/// salt if a password has been used.
pub struct EncryptionParameters {
    /// (Optional) Password derivation salt.
    pub salt: Option<Vec<u8>>,
    /// Symmetric encryption algorithm being use to encrypt the private key.
    pub algorithm: EncryptionMethod,
    /// Symmetric encryption nonce.
    pub nonce: Vec<u8>,
}

impl EncryptionParameters {
    pub fn new(salt: Option<Vec<u8>>, algorithm: EncryptionMethod, nonce: Vec<u8>) -> Self {
        Self {
            salt,
            algorithm,
            nonce
        }
    }
    
    #[inline(always)]
    pub fn is_password(&self) -> bool {
        self.salt.is_some()
    }
    
    #[inline(always)]
    pub fn algorithm(&self) -> EncryptionMethod {
        self.algorithm
    }
    
    #[inline(always)]
    pub fn salt(&self) -> Option<&[u8]> {
        self.salt.as_ref().map(|salt| salt.as_ref())
    }
    
    #[inline(always)]
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }
    
    #[inline]
    pub fn check_algorithm(&self) -> bool {
        self.algorithm == AES256GCM 
        || self.algorithm == CHACHA20_POLY1305
    }
}

/// Encryption method for private keys
pub type EncryptionMethod = u32;

pub const AES256GCM: EncryptionMethod = 1;
pub const CHACHA20_POLY1305: EncryptionMethod = 2;

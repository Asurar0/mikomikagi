//! # Mikomikagi library
//! 
//! This crate define an easy to use API for interacting with Mikomikagi
//! 

// ---------------------------------- Imports --------------------------------------

use std::ops::Deref;

use mikomikagi_keyring::{error::KeyringError, KeyringWrite};

// Keypair generation builder
pub mod keygen;

// Signature builder
pub mod signature;

// Encryption builder
pub mod encryption;

// Keyring import builder
pub mod import;

// ---------------------------------- Definition --------------------------------------

#[repr(transparent)]
/// A Generic Mikomikagi keyring.
/// 
/// You'll want to use this structure for everything that requires a keyring.
pub struct Keyring<KR: KeyringWrite>(KR);

impl<KR: KeyringWrite> Keyring<KR> {
    
    /// Open the keyring with the backend options
    /// 
    /// Returns the intended keyring on success, return a `KeyringError` otherwise
    pub fn open(options: KR::OpenOptions) -> Result<Self,KeyringError> {
        KR::open(options).map(Keyring)
    }
    
    /// Initialize the keyring with the backend options
    /// 
    /// Returns `()` if successfully initialized, return a `KeyringError` otherwise
    pub fn init(options: KR::OpenOptions) -> Result<(),KeyringError> {
        KR::init(options)
    }
    
    /// Open the keyring with the backend options in write mode (if supported)
    /// 
    /// Returns the intended keyring on success, return a `KeyringError` otherwise
    pub fn open_write(options: KR::OpenOptions) -> Result<Self,KeyringError> {
        KR::open_write(options).map(Keyring)
    }
    
    /// Close the keyring
    /// 
    /// This method will block until the database is closed.
    /// 
    /// ## Panic
    /// 
    /// This method will panic if it fails to close the database
    pub fn close(self) {
        self.0.close()
    }
}

impl<KR: KeyringWrite> Deref for Keyring<KR> {
    type Target = KR;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

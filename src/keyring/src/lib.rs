//! ## Keyring
//! 
//! The keyring crate defines the database storing all the keys and resources of mikomikagi
//! It achieve the same goal as GPG `~/.gnupg` directory.
//! 
//! ### Backend
//! 
//! Mikomikagi do not use a filsystem based storage for keys but instead use a database.
//! For different usages, different backend can be implemented and gated behind a feature flag.
//! 
//! As of the time of writing this document, mikomikagi only support keyring over LMDB database.
//! 
//! ### Read-only
//! 
//! If supported, mikomikagi will open the database in read-only mode if it do not need write access.
//! 

// ---------------------------------- Imports --------------------------------------

use borsh::{BorshDeserialize, BorshSerialize};
use error::KeyringError as Error;
use mikomikagi_core::{identity::AttachedIdentity, keys::{DecapsulationKey, EncapsulationKey, Fingerprint, SignaturePrivateKey, SignaturePublicKey}};

// Backend implementations
pub mod backend;

// Error definition
pub mod error;

// ----------------------------------- Trait ---------------------------------------

pub type KeyInfoEntry = ([u8; 32],u32,KeyStorageStatistics,AttachedIdentity);

#[derive(Clone, Copy, Debug, BorshSerialize, BorshDeserialize)]
/// Structure used to keep track of which identity detain what type of key.
pub struct KeyStorageStatistics {
    /// Identity have a signature private key
    pub signature_private_key: bool,
    /// Identity have a encryption public subkey
    pub encryption_public_subkey: bool,
    /// Identity have a encryption private subkey
    pub encryption_private_subkey: bool
}


/// Keyring API for Mikomikagi to fetch keypairs and resources
pub trait Keyring: Sized {
    /// Options needed for opening the backend
    type OpenOptions;
    
    /// Open the keyring backend according to the options in read-only mode (if supported)
    fn open(
        options: Self::OpenOptions, 
    ) -> Result<Self, Error>;
    
    /// Close the database (blocking).
    fn close(self);
    
    /// Collect an iterator of all keys stored in database (TODO: Limit)
    fn collect(
        &self
    ) -> Result<Vec<KeyInfoEntry>,Error>;
    
    /// Collect all the keys correspondig to the specific name
    fn get_fingerprint(
        &self,
        name: &str,
    ) -> Result<Vec<Fingerprint>,Error>;
    
    /// Get information block from fingerprint
    fn get_attached_identity(
        &self,
        fingerprint: &Fingerprint
    ) -> Result<AttachedIdentity,Error>;
    
    /// Get key statistics from fingerprint
    fn get_key_statistics(
        &self,
        fingerprint: &Fingerprint
    ) -> Result<KeyStorageStatistics,Error>;
    
    /// Get signature of the attached identity by its corresponding public key (used at export)
    fn get_attached_identity_signature(
        &self,
        fingerprint: &Fingerprint
    ) -> Result<Vec<u8>, Error>;
    
    /// Get public key from fingerprint
    fn get_signature_public_key(
        &self,
        fingerprint: &Fingerprint
    ) -> Result<SignaturePublicKey,Error>;
    
    /// Get public key from fingerprint
    fn get_encryption_public_key(
        &self,
        fingerprint: &Fingerprint
    ) -> Result<Option<EncapsulationKey>,Error>;
    
    /// Get public key from fingerprint
    fn get_encryption_private_key(
        &self,
        fingerprint: &Fingerprint
    ) -> Result<Option<DecapsulationKey>,Error>;
    
    /// Get private key from fingerprint
    fn get_signature_private_key(
        &self,
        fingerprint: &Fingerprint
    ) -> Result<SignaturePrivateKey,Error>;
    
}

/// Keyring API requiring write access, to insert or update keypairs and resources.
pub trait KeyringWrite: Keyring {
    
    /// Initialize the database (if needed). Return `Ok(())` if it has been succesfully initialized. 
    fn init(
        options: Self::OpenOptions
    ) -> Result<(), Error>;
    
    /// Open the keyring backend according to the options in write mode (if supported)
    fn open_write(
        options: Self::OpenOptions, 
    ) -> Result<Self, Error>;
    
    /// Insert a new signature public key and attached informations in keyring
    fn insert_signature_public_key(
        &self, 
        public_key: &SignaturePublicKey,
        signature: &[u8],
        informations: &AttachedIdentity
    ) -> Result<(),Error>;
    
    /// Insert a new signature private key in keyring
    fn insert_signature_private_key(
        &self, 
        private_key: &SignaturePrivateKey,
    ) -> Result<(),Error>;
    
    /// Insert a new signature private key in keyring
    fn insert_encryption_public_key(
        &self, 
        public_key: &EncapsulationKey,
    ) -> Result<(),Error>;
    
    /// Insert a new signature private key in keyring
    fn insert_encryption_private_key(
        &self, 
        private_key: &DecapsulationKey,
    ) -> Result<(),Error>;
    
    /// Remove keys from keyring
    fn remove_keys(
        &self,
        fingerprint: &Fingerprint,
    ) -> Result<AttachedIdentity, Error>;
}

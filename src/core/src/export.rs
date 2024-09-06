//! ## Export
//! 
//! Definition of all export block of Mikomikagi (aka MIKO * BLOCK encoded messages)
//! 

// ---------------------------------- Imports --------------------------------------

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{identity::AttachedIdentity, keys::{DecapsulationKey, EncapsulationKey, SignaturePrivateKey, SignaturePublicKey}};

// -------------------------------- Definitions ------------------------------------

/// PEM Tags for exports
pub mod tag {
    
    pub const PUBLIC_KEY_BLOCK: &str = "MIKO PUBLIC KEY BLOCK";
    pub const PRIVATE_KEY_BLOCK: &str = "MIKO PRIVATE KEY BLOCK";
    pub const ENCRYPTION_PUBLIC_SUBKEY_BLOCK: &str = "MIKO ENCRYPTION PUBLIC SUBKEY BLOCK";
    pub const ENCRYPTION_PRIVATE_SUBKEY_BLOCK: &str = "MIKO ENCRYPTION PRIVATE SUBKEY BLOCK";
    
    // Messages tag
    pub const SIGNED_MESSAGE: &str = "MIKO SIGNED MESSAGE BLOCK";
    pub const ENCRYPTED_MESSAGE: &str = "MIKO ENCRYPTED MESSAGE BLOCK";
}

#[derive(BorshSerialize, BorshDeserialize)]
/// Exportable structure contaning the informations of a PUBLIC KEY BLOCK
pub struct PublicKeyBlock {
    /// Signature public key
    pub public_key: SignaturePublicKey,
    /// Attached identity
    pub attached_identity: AttachedIdentity,
    /// Attached identity's signature (verifiable by `public_key`)
    pub attached_signature: Vec<u8>,
    /// Encapsulation key associated to this signature public key
    pub encapsulation_key: Option<EncapsulationKeyBlock>,
}

#[derive(BorshSerialize, BorshDeserialize)]
/// Exportable structure containing the informations of a ENCRYPTION PUBLIC SUBKEY BLOCK
pub struct EncapsulationKeyBlock {
    /// Encryption public key
    pub encapsulation_key: EncapsulationKey,
    /// `encapsulation_key` bytes hash signature blob
    pub ek_hash_signature: Vec<u8>
}

#[derive(BorshSerialize, BorshDeserialize)]
/// Exportable structure containing the informations of a PRIVATE KEY BLOCK
pub struct PrivateKeyBlock {
    /// Signature private key
    pub private_key: SignaturePrivateKey, 
    /// Signature of private key hash
    pub signature: Vec<u8>,
    /// Encryption private keys
    pub decapsulation_key: Option<DecapsulationKeyBlock>
}

#[derive(BorshSerialize, BorshDeserialize)]
/// Exportable structure containing the informations of a ENCRYPTION PRIVATE SUBKEY BLOCK
pub struct DecapsulationKeyBlock {
    /// Encryption private keys
    pub decapsulation_key: DecapsulationKey,
    /// Signature blob
    pub signature: Vec<u8>
}

#[derive(BorshSerialize, BorshDeserialize)]
/// Exportable structure containing the informations of a SIGNED MESSAGE BLOCK
pub struct SignedMessageBlock {
    /// (Optional) Original (compressed) message
    pub message: Option<Vec<u8>>,
    /// Detached signature,
    pub signature: Vec<u8>
}

#[derive(BorshSerialize, BorshDeserialize)]
/// Exportable structure containing the informations of an ENCRYPTED MESSAGE BLOCK
pub struct EncryptedMessageBlock {
    /// Encapsulated ciphertext
    pub encapsulated: Vec<u8>,
    /// Symmetric encryption algorithm
    pub algorithm: u32,
    /// Symmetric encryption nonce
    pub nonce: Vec<u8>,
    /// Encrypted Message
    pub ciphertext: Vec<u8>
}

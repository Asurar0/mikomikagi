//! ## Signature scheme
//! 
//! A signature scheme implements the `SignatureScheme` trait that define the important method
//! and constants of a diginal signature algorithm.
//! 

// ---------------------------------- Imports --------------------------------------

use mikomikagi_core::keys::{DecapsulationKey, EncapsulationKey, Fingerprint};

use crate::{error::Error, utils::EncryptionArguments, utils::Parseable};

// ---------------------------------- Implementations --------------------------------------

/// Implementation of Kyber key encapsulation mechanism
pub mod kyber;
use kyber::{Kyber768, Kyber1024};

// ---------------------------------- Definitions --------------------------------------

pub static ENCRYPTION_SCHEMES_LIST: [(u32,&str); 2] = [
    (Kyber768::SCHEME_CODE,Kyber768::NAME),
    (Kyber1024::SCHEME_CODE,Kyber1024::NAME)
];

/// A trait defining signature scheme that can be used as a basis for Mikomikagi identities. 
pub trait EncryptionScheme {
    
    /// Human name of this signature scheme
    const NAME: &'static str;
    /// Mikomikagi standard integer code corresponding to this signature scheme
    const SCHEME_CODE: u32;
    
    /// A compatible public key
    type EncapsulationKey: GenericEncapsulationPublicKey;
    /// A compatible private key
    type DecapsulationKey: GenericEncapsulationPrivateKey;
    /// An encapsulated cipher text
    type Ciphertext: Parseable;
    /// A shared secret
    type SharedSecret: Parseable;
    /// Error type thrown if verification fail
    type Error: Into<Error>;
    
    /// Generate a new public/private keypair
    fn keypair() -> (Self::EncapsulationKey,Self::DecapsulationKey);
    
    /// Sign the given message with the supplied private key
    fn encapsulate(pk: &Self::EncapsulationKey) -> (Self::SharedSecret,Self::Ciphertext);
    
    /// Sign the given message with the supplied private key. Only return the detached signature
    fn decapsulate(ciphertext: &Self::Ciphertext, sk: &Self::DecapsulationKey) -> Self::SharedSecret;
}

/// Trait defining the method for converting from scheme specific structure to general purpose private key
pub trait GenericEncapsulationPrivateKey: Sized {
    /// Serialize a scheme specific private key into a generic `SignaturePrivateKey`. It should only be used once
    /// at key generation.
    fn serialize(self, fingerprint: Fingerprint, encryption: Option<EncryptionArguments>) -> Result<DecapsulationKey, Error>;
    
    /// Deserialize a generic signature private key into a scheme specific private key.
    /// 
    /// It is caller responsability to ensure that the scheme is actually respected.
    fn deserialize(sk: &DecapsulationKey, key: Option<&[u8]>) -> Result<Self, Error>;
}

/// Trait defining the method for converting from scheme specific structure to general purpose public key
pub trait GenericEncapsulationPublicKey: Sized {
    
    /// Serialize a scheme specific public key into a generic `SignaturePublicKey`. It should only be used once
    /// at key generation.
    fn serialize(self, fingerprint: Fingerprint) -> Result<EncapsulationKey, Error>;
    
    /// Deserialize a generic signature public key into a scheme specific public key.
    /// 
    /// It is caller responsability to ensure that the scheme is actually respected.
    fn deserialize(pk: &EncapsulationKey) -> Result<Self, Error>;
}

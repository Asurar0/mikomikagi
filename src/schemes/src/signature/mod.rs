//! ## Signature scheme
//! 
//! A signature scheme implements the `SignatureScheme` trait that define the important method
//! and constants of a diginal signature algorithm.
//! 

// ---------------------------------- Imports --------------------------------------

use mikomikagi_core::keys::{Fingerprint, SignaturePrivateKey, SignaturePublicKey};

//use dilithium::{Dilithium5,Dilithium3};
//use falcon::Falcon1024;
use sphincs::SlhDsaSha2128s;

use crate::{error::Error, utils::EncryptionArguments, utils::Parseable};

// ---------------------------------- Implementations --------------------------------------

/// Implementation of SPHINCS+ diginal signature scheme
pub mod sphincs;

/// Implementation of Dilithium diginal signature scheme
pub mod dilithium;

/// Implementation of Falcon diginal signature scheme
pub mod falcon;

// ---------------------------------- Definitions --------------------------------------

pub static SIGNATURE_SCHEMES_LIST: [(u32,&str); 1] = [
    (SlhDsaSha2128s::SCHEME_CODE,SlhDsaSha2128s::NAME),
    // (SphincsSha2128s::SCHEME_CODE,SphincsSha2128s::NAME),
    // (SphincsSha2256s::SCHEME_CODE,SphincsSha2256s::NAME),
    // (Dilithium3::SCHEME_CODE,Dilithium3::NAME),
    // (Dilithium5::SCHEME_CODE,Dilithium5::NAME),
    // (Falcon1024::SCHEME_CODE,Falcon1024::NAME)
];

/// A trait defining signature scheme that can be used as a basis for Mikomikagi identities. 
pub trait SignatureScheme {
    
    /// Human name of this signature scheme
    const NAME: &'static str;
    /// Mikomikagi standard integer code corresponding to this signature scheme
    const SCHEME_CODE: u32;
    
    /// A compatible public key
    type PublicKey: GenericSignaturePublicKey;
    /// A compatible private key
    type PrivateKey: GenericSignaturePrivateKey;
    /// A detached signature
    type Signature: Parseable;
    /// Error type thrown if verification fail
    type Error: Into<Error>;
    
    /// Generate a new public/private keypair
    fn keypair() -> (Self::PublicKey,Self::PrivateKey);

    /// Sign the given message with the supplied private key. Only return the detached signature
    fn sign(message: &[u8], sk: &mut Self::PrivateKey) -> Self::Signature;
    
    /// Verify the supplied signature and message with the given public key.
    fn verify(message: &[u8], signature: &Self::Signature, pk: &Self::PublicKey) -> bool;
}

/// Trait defining the method for converting from scheme specific structure to general purpose private key
pub trait GenericSignaturePrivateKey: Sized {
    /// Serialize a scheme specific private key into a generic `SignaturePrivateKey`. It should only be used once
    /// at key generation.
    fn serialize(self, fingerprint: Fingerprint, encryption: Option<EncryptionArguments>) -> Result<SignaturePrivateKey, Error>;
    
    /// Deserialize a generic signature private key into a scheme specific private key.
    /// 
    /// It is caller responsability to ensure that the scheme is actually respected.
    fn deserialize(sk: &SignaturePrivateKey, key: Option<&[u8]>) -> Result<Self, Error>;
}

/// Trait defining the method for converting from scheme specific structure to general purpose public key
pub trait GenericSignaturePublicKey: Sized {
    
    /// Serialize a scheme specific public key into a generic `SignaturePublicKey`. It should only be used once
    /// at key generation.
    fn serialize(self, owner_name: &str) -> Result<SignaturePublicKey, Error>;
    
    /// Deserialize a generic signature public key into a scheme specific public key.
    /// 
    /// It is caller responsability to ensure that the scheme is actually respected.
    fn deserialize(pk: &SignaturePublicKey) -> Result<Self, Error>;
}

//! ## Error
//! 
//! Definition of errors that could happen in scheme definitions
//! 

#[derive(Debug, thiserror::Error)]
/// Error enum specific to the data models (aka predictable errors)
pub enum Error {
    
    #[error("Decapsulation of shared secret failed. Encryption key is certainly incorrect.")]
    /// Failed to decapsulate ciphertext. Cannot recover shared secret/encryption key material
    DecapsulationFailed,
    
    #[error("Unable to format nonce! Expected = {expected}, Got = {got}")]
    /// Symmetric decryption cannot be accomplished because the nonce length is incompatible with algorithm declared
    FormatNonce { expected: usize, got: usize },
    
    #[error("Decryption of data failed. The password/key is certainly incorrect.")]
    /// Failed to decrypt data with the supplied key!
    DecryptionFailed,
    
    #[error("Verification of the signed message failed. It is either the wrong public key or it has been tampered")]
    /// An attempt into veriyfing a signed message resulted verification falure (Signature is invalid)
    VerificationFailed,
    
    #[error("Unknown encryption algorithm! Integer code: {0}")]
    UnknownAlgorithm(u32),
    
    #[error("A generic key contained a `bytes` field that cannot be serialized by its specified scheme: {0}")]
    /// A generic key contained bytes that cannot be serialized by its specified scheme
    SerializationFailed(#[from] SerializationError)
}

#[derive(Debug, thiserror::Error)]
/// Library specific serialization error
pub enum SerializationError {
    
    #[error("PQCrypto library failed to serialize the incoming the data")]
    PQCrypto(pqcrypto_traits::Error)
}

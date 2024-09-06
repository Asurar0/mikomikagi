//! ## Signature
//! 
//! This module defines builder for signing and verifying messages with public and private keys
//! 

// ---------------------------------- Imports --------------------------------------

use mikomikagi_core::{export::SignedMessageBlock, keys::{SignaturePrivateKey, SignaturePublicKey}};
use mikomikagi_schemes::{signature::{dilithium::{Dilithium3, Dilithium5}, falcon::Falcon1024, sphincs::{SphincsSha2128s, SphincsSha2256s}, GenericSignaturePrivateKey, GenericSignaturePublicKey, SignatureScheme}, utils::Parseable};

// ---------------------------------- Definition --------------------------------------

/// A typed builder for generating signatures from a given private key.
pub struct SignatureBuilder<'sk> {
    /// Signature private key to use
    sk: &'sk SignaturePrivateKey,
    /// (Optional) Encryption key
    key: Option<&'sk [u8]>
}

/// A typed builder for verifying a signature from a given public key
pub struct VerifierBuilder<'pk> {
    /// Signature public key to use
    pk: &'pk SignaturePublicKey
}

// TODO: Private key encryption
impl<'sk> SignatureBuilder<'sk> {
    
    /// Create a new signature builder out of the supplied private key and optional encryption key
    /// 
    /// ## Panic
    /// 
    /// The caller must ensure that a key is provided if the used private key used is encrypted.
    /// If it isn't the case, this method will panic
    pub fn new(sk: &'sk SignaturePrivateKey, key: Option<&'sk [u8]>) -> Self {
        
        assert!(sk.encryption.is_some() == key.is_some(), "Private key is encrypted but no encryption key was provided");
        
        Self {
            sk,
            key
        }
    }
    
    /// Sign the given message with this builder (and underlying private key)
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        
        // Sign message and return signature
        match self.sk.scheme {
            SphincsSha2128s::SCHEME_CODE => Self::sign_scheme::<SphincsSha2128s>(message, self.sk, self.key),
            SphincsSha2256s::SCHEME_CODE => Self::sign_scheme::<SphincsSha2256s>(message, self.sk, self.key),
            Dilithium3::SCHEME_CODE => Self::sign_scheme::<Dilithium3>(message, self.sk, self.key),
            Dilithium5::SCHEME_CODE => Self::sign_scheme::<Dilithium5>(message, self.sk, self.key),
            Falcon1024::SCHEME_CODE => Self::sign_scheme::<Falcon1024>(message, self.sk, self.key),
            _ => panic!("Unknown Signature Scheme!")
        }
    }
    
    /// Sign the given message with this builder (and underlying private key)
    pub fn sign_block(&self, message: &[u8]) -> SignedMessageBlock {
        
        // Hash message
        let hash = blake3::hash(message);
        
        // Sign hash
        let signature = match self.sk.scheme {
            SphincsSha2128s::SCHEME_CODE => Self::sign_scheme::<SphincsSha2128s>(hash.as_bytes(), self.sk, self.key),
            SphincsSha2256s::SCHEME_CODE => Self::sign_scheme::<SphincsSha2256s>(hash.as_bytes(), self.sk, self.key),
            Dilithium3::SCHEME_CODE => Self::sign_scheme::<Dilithium3>(hash.as_bytes(), self.sk, self.key),
            Dilithium5::SCHEME_CODE => Self::sign_scheme::<Dilithium5>(hash.as_bytes(), self.sk, self.key),
            Falcon1024::SCHEME_CODE => Self::sign_scheme::<Falcon1024>(hash.as_bytes(), self.sk, self.key),
            _ => panic!("Unknown Signature Scheme!")
        };
        
        // Store message
        SignedMessageBlock {
            message: Some(message.to_owned()),
            signature,
        }
    }
    
    /// Signature routine
    fn sign_scheme<S: SignatureScheme>(hash: &[u8], sk: &SignaturePrivateKey, key: Option<&[u8]>) -> Vec<u8> {
        
        let signature = S::sign_detach(hash, &<S::PrivateKey>::deserialize(sk, key).unwrap());
        signature.to_bytes()
    }
}

impl<'pk> VerifierBuilder<'pk> {
    
    /// Create a new verifier builder out of the supplied public key
    pub fn new(pk: &'pk SignaturePublicKey) -> Self {
        Self {
            pk
        }
    }
    
    /// Verify the given message and signature with this builder (and underlying public key)
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        
        // Verify message with signature
        match self.pk.scheme() {
            SphincsSha2128s::SCHEME_CODE => Self::verify_scheme::<SphincsSha2128s>(message, signature, self.pk),
            SphincsSha2256s::SCHEME_CODE => Self::verify_scheme::<SphincsSha2256s>(message, signature, self.pk),
            Dilithium3::SCHEME_CODE => Self::verify_scheme::<Dilithium3>(message, signature, self.pk),
            Dilithium5::SCHEME_CODE => Self::verify_scheme::<Dilithium5>(message, signature, self.pk),
            Falcon1024::SCHEME_CODE => Self::verify_scheme::<Falcon1024>(message, signature, self.pk),
            _ => panic!("Unknown Signature Scheme!")
        }
    }
    
    // Verify the given signed message block with this builder (and underlying public key)
    pub fn verify_block(&self, SignedMessageBlock { message, signature }: &SignedMessageBlock) -> bool {
        
        assert!(message.is_some(), "Detached signature block isn't supported yet");
        
        // Hash message
        let hash = blake3::hash(message.as_ref().unwrap());
        
        // Verify hash with signature
        match self.pk.scheme() {
            SphincsSha2128s::SCHEME_CODE => Self::verify_scheme::<SphincsSha2128s>(hash.as_bytes(), signature, self.pk),
            SphincsSha2256s::SCHEME_CODE => Self::verify_scheme::<SphincsSha2256s>(hash.as_bytes(), signature, self.pk),
            Dilithium3::SCHEME_CODE => Self::verify_scheme::<Dilithium3>(hash.as_bytes(), signature, self.pk),
            Dilithium5::SCHEME_CODE => Self::verify_scheme::<Dilithium5>(hash.as_bytes(), signature, self.pk),
            Falcon1024::SCHEME_CODE => Self::verify_scheme::<Falcon1024>(hash.as_bytes(), signature, self.pk),
            _ => panic!("Unknown Signature Scheme!")
        }
    }
    
    /// Signature routine
    fn verify_scheme<S: SignatureScheme>(message: &[u8], signature: &[u8], pk: &SignaturePublicKey) -> bool {
        
        // If failing to serialize signature then return false (wrong scheme and wrong key)
        let s_s = <S::Signature>::from_bytes(signature);
        if s_s.is_err() { return false }
        
        S::verify(message, &s_s.unwrap(), &<S::PublicKey>::deserialize(pk).unwrap())
    }
}

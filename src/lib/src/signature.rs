//! ## Signature
//!
//! This module defines builder for signing and verifying messages with public and private keys
//!

// ---------------------------------- Imports --------------------------------------

use mikomikagi_core::{export::SignedMessageBlock, keys::{SignaturePrivateKey, SignaturePublicKey}};
use mikomikagi_schemes::{signature::{dilithium::{MlDsa44, MlDsa65, MlDsa87}, sphincs::{SlhDsaSha2128s, SlhDsaSha2256s}, GenericSignaturePrivateKey, GenericSignaturePublicKey, SignatureScheme}, utils::Parseable};

// ---------------------------------- Definition --------------------------------------

/// A typed builder for generating signatures from a given private key.
pub struct SignatureBuilder<'sk> {
    /// Signature private key to use
    sk: &'sk mut SignaturePrivateKey,
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
    pub fn new(sk: &'sk mut SignaturePrivateKey, key: Option<&'sk [u8]>) -> Self {

        assert!(sk.encryption.is_some() == key.is_some(), "Private key is encrypted but no encryption key was provided");

        Self {
            sk,
            key
        }
    }

    /// Sign the given message with this builder (and underlying private key)
    pub fn sign(&mut self, message: &[u8]) -> Vec<u8> {

        // Sign message and return signature
        #[forbid(unreachable_patterns)]
        match self.sk.scheme {
            SlhDsaSha2128s::SCHEME_CODE => Self::sign_scheme::<SlhDsaSha2128s>(message, self.sk, self.key),
            SlhDsaSha2256s::SCHEME_CODE => Self::sign_scheme::<SlhDsaSha2256s>(message, self.sk, self.key),
            MlDsa44::SCHEME_CODE => Self::sign_scheme::<MlDsa44>(message, self.sk, self.key),
            MlDsa65::SCHEME_CODE => Self::sign_scheme::<MlDsa65>(message, self.sk, self.key),
            MlDsa87::SCHEME_CODE => Self::sign_scheme::<MlDsa87>(message, self.sk, self.key),
            _ => panic!("Unknown Signature Scheme!")
        }
    }

    /// Sign the given message with this builder (and underlying private key)
    pub fn sign_block(&mut self, message: &[u8]) -> SignedMessageBlock {

        // Hash message
        let hash = blake3::hash(message);

        // Sign hash
        #[forbid(unreachable_patterns)]
        let signature = match self.sk.scheme {
            SlhDsaSha2128s::SCHEME_CODE => Self::sign_scheme::<SlhDsaSha2128s>(hash.as_bytes(), self.sk, self.key),
            SlhDsaSha2256s::SCHEME_CODE => Self::sign_scheme::<SlhDsaSha2256s>(hash.as_bytes(), self.sk, self.key),
            MlDsa44::SCHEME_CODE => Self::sign_scheme::<MlDsa44>(hash.as_bytes(), self.sk, self.key),
            MlDsa65::SCHEME_CODE => Self::sign_scheme::<MlDsa65>(hash.as_bytes(), self.sk, self.key),
            MlDsa87::SCHEME_CODE => Self::sign_scheme::<MlDsa87>(hash.as_bytes(), self.sk, self.key),
            _ => panic!("Unknown Signature Scheme!")
        };

        // Store message
        SignedMessageBlock {
            message: Some(message.to_owned()),
            signature,
        }
    }

    /// Signature routine
    fn sign_scheme<S: SignatureScheme>(hash: &[u8], sk: &mut SignaturePrivateKey, key: Option<&[u8]>) -> Vec<u8> {

        let signature = S::sign(hash, &mut <S::PrivateKey>::deserialize(sk, key).unwrap());
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
        #[forbid(unreachable_patterns)]
        match self.pk.scheme() {
            SlhDsaSha2128s::SCHEME_CODE => Self::verify_scheme::<SlhDsaSha2128s>(message, signature, self.pk),
            SlhDsaSha2256s::SCHEME_CODE => Self::verify_scheme::<SlhDsaSha2256s>(message, signature, self.pk),
            MlDsa44::SCHEME_CODE => Self::verify_scheme::<MlDsa44>(message, signature, self.pk),
            MlDsa65::SCHEME_CODE => Self::verify_scheme::<MlDsa65>(message, signature, self.pk),
            MlDsa87::SCHEME_CODE => Self::verify_scheme::<MlDsa87>(message, signature, self.pk),
            _ => panic!("Unknown Signature Scheme!")
        }
    }

    // Verify the given signed message block with this builder (and underlying public key)
    pub fn verify_block(&self, SignedMessageBlock { message, signature }: &SignedMessageBlock) -> bool {

        assert!(message.is_some(), "Detached signature block isn't supported yet");

        // Hash message
        let hash = blake3::hash(message.as_ref().unwrap());

        // Verify hash with signature
        #[forbid(unreachable_patterns)]
        match self.pk.scheme() {
            SlhDsaSha2128s::SCHEME_CODE => Self::verify_scheme::<SlhDsaSha2128s>(hash.as_bytes(), signature, self.pk),
            SlhDsaSha2256s::SCHEME_CODE => Self::verify_scheme::<SlhDsaSha2256s>(hash.as_bytes(), signature, self.pk),
            MlDsa44::SCHEME_CODE => Self::verify_scheme::<MlDsa44>(hash.as_bytes(), signature, self.pk),
            MlDsa65::SCHEME_CODE => Self::verify_scheme::<MlDsa65>(hash.as_bytes(), signature, self.pk),
            MlDsa87::SCHEME_CODE => Self::verify_scheme::<MlDsa87>(hash.as_bytes(), signature, self.pk),
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

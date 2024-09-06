//! ## Signature keys
//! 
//! This module define all the generic signature key structure, their methods, and trait implementation
//! 

// ---------------------------------- Imports --------------------------------------

use std::borrow::Cow;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{hash::Hashable, keys::{Fingerprint, EncryptionParameters}};

// ---------------------------------- Public Key --------------------------------------

/// Latest version of the signature public key structure
pub const SIGNATURE_PUBLIC_KEY_CURRENT_VERSION: u16 = 1;

#[derive(BorshSerialize, BorshDeserialize)]
/// A generic structure containing a signature public 
/// key and according informations.
pub struct SignaturePublicKey {
    /// Version of this format
    version: u16,
    /// Signature scheme of this key
    scheme: u32,
    /// Key fingerprint
    fingerprint: Fingerprint,
    /// Public Key Blob
    bytes: Vec<u8>,
    /// Encapsulation key hash
    pub ek_hash: Option<[u8;32]>
}

impl SignaturePublicKey {
    
    #[inline(always)]
    /// Create new Signature public key structure
    pub fn new(scheme: u32, fingerprint: Fingerprint, bytes: Vec<u8>, ek_hash: Option<[u8;32]>) -> Self {
        Self {
            version: SIGNATURE_PUBLIC_KEY_CURRENT_VERSION, 
            scheme, 
            fingerprint, 
            bytes,
            ek_hash
        }
    }
    
    #[inline(always)]
    /// Version of this public key
    pub fn version(&self) -> u16 {
        self.version
    }
    
    #[inline(always)]
    /// Digital signature scheme being used (SCHEME_CODE)
    pub fn scheme(&self) -> u32 {
        self.scheme
    }
    
    #[inline(always)]
    /// Fingerprint of this public key (Keyed hash)
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }
    
    #[inline(always)]
    /// Serialized signature public key bytes
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Hashable for SignaturePublicKey {
    
    /// Give the corresponding hash of this generic signature public key structure
    fn hash(&self) -> [u8;32] {
        use blake3::Hasher;
        
        let mut hasher = Hasher::new();
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.scheme.to_le_bytes());
        hasher.update(self.fingerprint.as_ref());
        hasher.update(self.bytes());
        
        if let Some(ek_hash) = self.ek_hash {
            hasher.update(&ek_hash);
        }
        
        *hasher.finalize().as_bytes()
    }
}

// ---------------------------------- Private Key --------------------------------------

/// Latest version of the signature private key structure
pub const SIGNATURE_PRIVATE_KEY_CURRENT_VERSION: u16 = 1;

#[derive(BorshSerialize, BorshDeserialize)]
/// A Signature private key
pub struct SignaturePrivateKey {
    /// Version of this format
    pub version: u16,
    /// Signature scheme of this key
    pub scheme: u32,
    /// Fingerprint of the corresponding public key
    pub pk_fingerprint: Fingerprint,
    /// Encryption method of the private key
    pub encryption: Option<EncryptionParameters>,
    /// Private Key Blob (unencrypted or encrypted)
    pub bytes: Vec<u8>,
}

impl SignaturePrivateKey {
    
    pub fn new(scheme: u32, pk_fingerprint: Fingerprint, encryption: Option<EncryptionParameters>, bytes: Vec<u8>) -> Self {
        Self {
            version: SIGNATURE_PRIVATE_KEY_CURRENT_VERSION, 
            scheme, 
            pk_fingerprint, 
            encryption, 
            bytes
        }
    }

    #[inline(always)]
    /// Retrieve the format version of this SignaturePrivateKey
    pub fn version(&self) -> u16 {
        self.version
    }
    
    #[inline(always)]
    /// Retrieve the scheme code of this SignaturePrivateKey
    pub fn scheme(&self) -> u32 {
        self.scheme
    }
    
    #[inline(always)]
    /// Retrieve the fingerprint of the public key associated with this private key
    pub fn fingerprint(&self) -> Fingerprint {
        self.pk_fingerprint
    }
    
    #[inline(always)]
    /// Retrieve the bytes of the serialized key (or ciphertext if encrypted)
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }
    
    // --------------------------- Encryption ---------------------------
    
    #[inline(always)]
    /// Return true if the private key is encrypted, false otherwise
    pub fn is_encrypted(&self) -> bool {
        self.encryption.is_some()
    }
    
    #[inline]
    /// Return true if the private key contains a derivation salt, false otherwise
    pub fn is_password(&self) -> bool {
        self.encryption.as_ref().is_some_and(|s| s.is_password())
    }
    
    #[inline]
    /// Return the salt bytes if it is stored (check with `is_password()` method)
    pub fn salt(&self) -> Option<&[u8]> {
        self.encryption.as_ref().and_then(|enc| enc.salt())
    }
}

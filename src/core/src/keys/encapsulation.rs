//! ## Encapsulation keys
//! 
//! This module define all the generic encapsulation key structure, their methods, and trait implementation
//! 

// ---------------------------------- Imports --------------------------------------

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{hash::Hashable, keys::{Fingerprint, EncryptionParameters}};

// ---------------------------------- Public Key --------------------------------------

/// Latest version of the encryption public key structure
pub const ENCRYPTION_PUBLIC_KEY_CURRENT_VERSION: u16 = 1;

#[derive(BorshSerialize, BorshDeserialize)]
/// An encryption public key
pub struct EncapsulationKey {
    /// Version of this format
    pub version: u16,
    /// Encryption scheme of this key
    pub scheme: u32,
    /// Key fingerprint
    pub pk_fingerprint: Fingerprint,
    /// Public Key Blob
    pub bytes: Vec<u8>,
}

impl EncapsulationKey {
    
    #[inline(always)]
    /// Create new Signature public key structure
    pub fn new(scheme: u32, pk_fingerprint: Fingerprint, bytes: Vec<u8>) -> Self {
        Self {
            version: ENCRYPTION_PUBLIC_KEY_CURRENT_VERSION, 
            scheme, 
            pk_fingerprint, 
            bytes,
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
        self.pk_fingerprint
    }
    
    #[inline(always)]
    /// Serialized encapsulation key bytes
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Hashable for EncapsulationKey {
    
    /// Give the corresponding hash of this generic signature public key structure
    fn hash(&self) -> [u8;32] {
        use blake3::Hasher;
        
        let mut hasher = Hasher::new();
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&self.scheme.to_le_bytes());
        hasher.update(self.pk_fingerprint.as_ref());
        hasher.update(self.bytes());
        
        *hasher.finalize().as_bytes()
    }
}

// ---------------------------------- Private Key --------------------------------------

/// Latest version of the encryption public key structure
pub const ENCRYPTION_PRIVATE_KEY_CURRENT_VERSION: u32 = 1;

#[derive(BorshSerialize, BorshDeserialize)]
/// An encryption private key
pub struct DecapsulationKey {
    /// Version of this format
    version: u32,
    /// Encryption scheme of this key
    scheme: u32,
    /// Key fingerprint
    fingerprint: Fingerprint,
    /// Encryption method of the private key
    pub encryption: Option<EncryptionParameters>,
    /// Public Key Blob
    bytes: Vec<u8>,
}

impl DecapsulationKey {
    
    pub fn new( scheme: u32, fingerprint: Fingerprint, encryption: Option<EncryptionParameters>, bytes: Vec<u8>) -> Self {
        Self { version: ENCRYPTION_PRIVATE_KEY_CURRENT_VERSION, scheme, fingerprint, encryption, bytes }
    }

    #[inline]
    /// Retrieve the format version of this SignaturePrivateKey
    pub fn version(&self) -> u32 {
        self.version
    }
    
    #[inline]
    /// Retrieve the scheme code of this SignaturePrivateKey
    pub fn scheme(&self) -> u32 {
        self.scheme
    }
    
    #[inline]
    /// Retrieve the fingerprint associated with this private key
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }
    
    #[inline(always)]
    /// Serialized decapsulation key bytes
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    
    // --------------------------- Encryption ---------------------------
    
    #[inline]
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
    
    #[inline]
    /// Retrieve the bytes of the serialized key (or ciphertext if encrypted)
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

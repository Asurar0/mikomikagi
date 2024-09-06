// ---------------------------------- Imports --------------------------------------

use mikomikagi_core::{export::{PrivateKeyBlock, PublicKeyBlock}, keys::Fingerprint};
use mikomikagi_keyring::{error::KeyringError, KeyringWrite};
use mikomikagi_schemes::error::Error;

use crate::{signature::VerifierBuilder, Keyring};

// ---------------------------------- Definition --------------------------------------

/// A typed builder for decapsulating a .
pub struct KeyringImportBuilder<'kr, KR: KeyringWrite> {
    /// Signature private key to use
    keyring: &'kr Keyring<KR>
}

// ---------------------------------- Implementation --------------------------------------

// TODO: Private key encryption
impl<'kr, KR: KeyringWrite> KeyringImportBuilder<'kr, KR> {
    
    /// Create a new signature builder out of the supplied private key and optional encryption key
    /// 
    /// ## Panic
    /// 
    /// The caller must ensure that a key is provided if the used private key used is encrypted.
    /// If it isn't the case, this method will panic
    pub fn new(keyring: &'kr Keyring<KR>) -> Self {
        
        Self {
            keyring
        }
    }
    
    pub fn import_public_key(&self, PublicKeyBlock { public_key, attached_identity, attached_signature, encapsulation_key }: PublicKeyBlock) -> Result<Fingerprint,KeyringError> {
        
        // Hash attached identity
        let attached_identity_blob = borsh::to_vec(&attached_identity)
            .expect("Unable to serialize attached identity (Borsh)");
        let hash = blake3::hash(&attached_identity_blob);
        
        // Verify identity signature
        let builder = VerifierBuilder::new(&public_key);
        let sig_verified = builder.verify(hash.as_bytes(), &attached_signature);
        
        // If there is an encapsulation key, verify its signature
        let ek_verified = if let Some(ek) = &encapsulation_key {
            
            let builder = VerifierBuilder::new(&public_key);
            let ek_blob = borsh::to_vec(&ek.encapsulation_key)
                .expect("Unable to serialize encapsulation key structure (Borsh)");
            let ek_hash = blake3::hash(&ek_blob);
            builder.verify(ek_hash.as_bytes(), &ek.ek_hash_signature)  
        } else {
            true
        };        
        
        // If verified then append to database
        if sig_verified && ek_verified {
            
            if let Some(ek) = &encapsulation_key {
                self.keyring.insert_encryption_public_key(&ek.encapsulation_key)?
            }
            
            self.keyring.insert_signature_public_key(
                &public_key, 
                &attached_signature, 
                &attached_identity
            )?;
            
            Ok(public_key.fingerprint())
        } else {
            Err(KeyringError::Scheme(Error::VerificationFailed))
        }
    }
    
    /// Import the supplied PrivateKeyBlock into the keyring, if the public key and identity already exists
    /// 
    /// Return `Err(KeyringError::NoResource)` if the signature public key or attached identity don't exist.
    pub fn import_private_key(&self, PrivateKeyBlock { private_key, signature, decapsulation_key }: PrivateKeyBlock) -> Result<Fingerprint,KeyringError> {
        
        // Get associated public key
        let public_key = self.keyring.get_signature_public_key(&private_key.fingerprint())?;
        
        // Verify private key signature
        let sk_blob = borsh::to_vec(&private_key).unwrap();
        let hash = blake3::hash(&sk_blob);
        let sk_verified = VerifierBuilder::new(&public_key).verify(hash.as_bytes(), &signature);
        
        // Verify decapsulation key signature
        let dk_verified = if let Some(dk) = &decapsulation_key {
            let dk_blob = borsh::to_vec(&dk.decapsulation_key).unwrap();
            let hash = blake3::hash(&dk_blob);
            VerifierBuilder::new(&public_key).verify(hash.as_bytes(), &dk.signature)
        } else {
            true
        };
        
        // If all verification are valid import
        if dk_verified && sk_verified {
            self.keyring.insert_signature_private_key(&private_key)?;
            
            if let Some(dk) = &decapsulation_key {
                self.keyring.insert_encryption_private_key(&dk.decapsulation_key)?;
            }
            
            Ok(public_key.fingerprint())
        } else {
            
            Err(KeyringError::Scheme(Error::VerificationFailed))
        }
    }
}

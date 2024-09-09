//! ## Encryption
//! 
//! This module defines builder for encrypting and decrypting messages using 
//! encapsulation and decapsulation keys.
//! 

// ---------------------------------- Imports --------------------------------------

use mikomikagi_core::{export::EncryptedMessageBlock, keys::{DecapsulationKey, EncapsulationKey, AES256GCM, CHACHA20_POLY1305}};
use mikomikagi_schemes::{encryption::{kyber::{Kyber1024, Kyber768}, EncryptionScheme, GenericEncapsulationPrivateKey, GenericEncapsulationPublicKey}, error::Error, utils::Parseable};

use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use rand::{rngs::StdRng, SeedableRng};

// ---------------------------------- Definition --------------------------------------

/// A typed builder for decapsulating a shared secret
pub struct DecapsulationBuilder<'dk> {
    /// Signature private key to use
    dk: &'dk DecapsulationKey,
    /// (Optional) Encryption key
    key: Option<&'dk [u8]>
}

/// A typed builder for generating and encapsulating a shared secret
pub struct EncapsulationBuilder<'ek> {
    /// Signature public key to use
    ek: &'ek EncapsulationKey
}

/// A typed builder for decrypting an encrypted message block
pub struct DecryptionBuilder<'dk> {
    /// Inner builder for decapsulating ciphertext
    builder: DecapsulationBuilder<'dk>
}

/// A typed builder for encrypting a message with an encapsulation key
pub struct EncryptionBuilder<'ek> {
    /// Encryption algorithm to use
    algorithm: u32,
    /// Inner builder for encapsulating a shared_secret
    builder: EncapsulationBuilder<'ek>
}

// ---------------------------------- Implementation --------------------------------------

impl<'dk> DecapsulationBuilder<'dk> {
    
    /// Create a new signature builder out of the supplied private key and optional encryption key
    /// 
    /// ## Panic
    /// 
    /// The caller must ensure that a key is provided if the decapsulation key used is encrypted.
    /// If it isn't the case, this method will panic
    pub fn new(dk: &'dk DecapsulationKey) -> Self {
        
        Self {
            dk,
            key: None
        }
    }
    
    /// Set the encryption key for the private key
    pub fn encryption_key(&mut self, key: Option<&'dk [u8]>) -> &mut Self {
        self.key = key;
        self
    }
    
    /// Decapsulate the given ciphertext
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>,Error> {
        
        assert!(self.dk.encryption.is_some() == self.key.is_some(), "Private key is encrypted but no encryption key was provided");
        
        match self.dk.scheme() {
            Kyber768::SCHEME_CODE => Self::decapsulate_scheme::<Kyber768>(ciphertext, self.dk, self.key),
            Kyber1024::SCHEME_CODE => Self::decapsulate_scheme::<Kyber1024>(ciphertext, self.dk, self.key),
            _ => panic!("Unknown Signature Scheme!")
        }
    }
    
    /// Decapsulation routine
    fn decapsulate_scheme<E: EncryptionScheme>(ciphertext: &[u8], dk: &DecapsulationKey, key: Option<&[u8]>) -> Result<Vec<u8>,Error> {
        
        let shared_secret = E::decapsulate(&<E::Ciphertext>::from_bytes(ciphertext)?, &<E::DecapsulationKey>::deserialize(dk, key)?);
        Ok(shared_secret.to_bytes())
    }
}

impl<'ek> EncapsulationBuilder<'ek> {
    
    /// Create a new encapsulation builder with
    pub fn new(ek: &'ek EncapsulationKey) -> Self {
        Self {
            ek
        }
    }
    
    /// Generate a new shared secret in clear and encapsulated form
    pub fn encapsulate(&self) -> Result<(Vec<u8>,Vec<u8>),Error> {
        
        match self.ek.scheme {
            Kyber768::SCHEME_CODE => Self::encapsulate_scheme::<Kyber768>(self.ek),
            Kyber1024::SCHEME_CODE => Self::encapsulate_scheme::<Kyber1024>(self.ek),
            _ => panic!("Unknown Signature Scheme!")
        }
    }
    
    /// Encapsulation routine
    fn encapsulate_scheme<E: EncryptionScheme>(ek: &EncapsulationKey) -> Result<(Vec<u8>,Vec<u8>),Error> {
        
        let (shared_secret,ciphertext) = E::encapsulate(&<E::EncapsulationKey>::deserialize(ek)?);
        Ok((shared_secret.to_bytes(),ciphertext.to_bytes()))
    }
}

impl<'dk> DecryptionBuilder<'dk> {
    
    /// Create a new decryption builder with the given decapsulation key
    pub fn new(dk: &'dk DecapsulationKey) -> Self {
        Self {
            builder: DecapsulationBuilder { 
                dk,
                key: None
            }
        }
    }
    
    /// Set the encryption key for the decapsulation key
    pub fn encryption_key(&mut self, key: Option<&'dk [u8]>) -> &mut Self {
        self.builder.encryption_key(key);
        self
    }
    
    /// Decrypt the encrypted message with this builder
    /// 
    /// ## Panic
    /// 
    /// The caller must ensure that a key is provided if the decapsulation key used is encrypted.
    /// If it isn't the case, this method will panic
    pub fn decrypt(&self, message: &EncryptedMessageBlock) -> Result<Vec<u8>,Error> {
        
        // Encapsulate a shared secret
        let shared_secret = self.builder.decapsulate(&message.encapsulated)?;
        
        // Shared secret hash is our AES256 key
        let key = blake3::hash(&shared_secret);
        
        // Decrypt
        let plaintext = Self::decryption_routine(message.algorithm, &message.ciphertext, &message.nonce, key.as_bytes())?;
        
        Ok(plaintext)
    }
    
    /// Decryption routine
    fn decryption_routine(algorithm: u32, ciphertext: &[u8], nonce: &[u8], key: &[u8]) -> Result<Vec<u8>,Error> {
        // Format nonce
        let nonce: [u8; 12] = nonce.try_into().map_err(|_|Error::FormatNonce { expected: 12, got: nonce.len() })?;
        
        // Decrypt
        match algorithm {
            AES256GCM => {
                let cipher = Aes256Gcm::new_from_slice(key).unwrap();
                let plaintext = cipher.decrypt(&nonce.into(), ciphertext.as_ref())
                    .map_err(|_|Error::DecryptionFailed)?;
                
                Ok(plaintext)
            }
            CHACHA20_POLY1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
                let plaintext = cipher.decrypt(&nonce.into(), ciphertext.as_ref())
                    .map_err(|_|Error::DecryptionFailed)?;
                
                Ok(plaintext)
            }
            c => Err(Error::UnknownAlgorithm(c))
        }
    }
}
impl<'ek> EncryptionBuilder<'ek> {
    
    pub fn new(ek: &'ek EncapsulationKey) -> Self {
        Self {
            algorithm: CHACHA20_POLY1305, // Default is ChaCha20Poly1305.
            builder: EncapsulationBuilder { 
                ek 
            }
        }
    }
    
    /// Change the encryption algorithm being used for encrypting this message. (Default: ChaCha20Poly1305)
    pub fn algorithm(&mut self, algorithm: u32) -> &mut Self {
        
        assert!(
            algorithm ==  AES256GCM
            || algorithm == CHACHA20_POLY1305,
            "Invalid encryption algorithm used! Integer code: {algorithm}");
        
        self.algorithm = algorithm;
        self
    }
    
    pub fn encrypt(&self, message: &[u8]) -> Result<EncryptedMessageBlock,Error> {
        
        // Encapsulate a shared secret
        let (shared_secret,encapsulated) = self.builder.encapsulate()?;
        
        // Shared secret hash is our AES256 key
        let key = blake3::hash(&shared_secret);
        
        assert!(key.as_bytes().len() == 32, "Encryption keys are 256 bit");
        
        // Encrypt message
        let (ciphertext, nonce) = Self::encryption_routine(self.algorithm, message, key.as_bytes());
        
        Ok(
            EncryptedMessageBlock { 
                encapsulated,
                algorithm: self.algorithm,
                nonce, 
                ciphertext 
            }
        )
    }
    
    fn encryption_routine(algorithm: u32, message: &[u8], key: &[u8]) -> (Vec<u8>,Vec<u8>) {
        match algorithm {
            AES256GCM => {
                let nonce = Aes256Gcm::generate_nonce(&mut StdRng::from_entropy());
                let cipher = Aes256Gcm::new_from_slice(key).unwrap();
                let ciphertext = cipher.encrypt(&nonce, message).unwrap();
                
                (ciphertext,nonce.to_vec())
            }
            CHACHA20_POLY1305 => {
                let nonce = ChaCha20Poly1305::generate_nonce(&mut StdRng::from_entropy());
                let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
                let ciphertext = cipher.encrypt(&nonce, message).unwrap();
                
                (ciphertext,nonce.to_vec())
            }
            _ => panic!("Unknown encryption algorithm. Another assertion has been made prior to this point.")
        }
    }
}

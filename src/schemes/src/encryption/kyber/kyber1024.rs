//! ### Kyber768 variant
//! 
//! Current implementation is PQClean library
//! 

// ---------------------------------- Imports --------------------------------------

use std::ops::Deref;

use aes_gcm::Aes256Gcm;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::{Aead, AeadCore} };
use mikomikagi_core::keys::{AES256GCM, CHACHA20_POLY1305, EncryptionParameters, DecapsulationKey, EncapsulationKey, Fingerprint};
use pqcrypto_kyber::kyber1024 as kyberctx;
use pqcrypto_traits::kem::*;
use rand::{rngs::StdRng, SeedableRng};

use crate::{error::{Error, SerializationError}, utils::EncryptionArguments, utils::Parseable};

use super::super::{EncryptionScheme, GenericEncapsulationPublicKey, GenericEncapsulationPrivateKey};

// ---------------------------------- Defintions --------------------------------------

pub struct Kyber1024;

#[derive(Clone)]
#[repr(transparent)]
/// Implementation wrapper over kyberctx::PublicKey
pub struct EncapsulationKeyWrapper(kyberctx::PublicKey);

#[derive(Clone)]
#[repr(transparent)]
/// Implementation wrapper over kyberctx::PublicKey
pub struct DecapsulationKeyWrapper(kyberctx::SecretKey);

// ---------------------------------- Implementation --------------------------------------

impl GenericEncapsulationPublicKey for EncapsulationKeyWrapper {    
    fn serialize(self, pk_fingerprint: Fingerprint) -> Result<EncapsulationKey, Error> {
        let bytes = <kyberctx::PublicKey as pqcrypto_traits::kem::PublicKey>::as_bytes(&self.0).to_vec();
        
        Ok(EncapsulationKey::new(Kyber1024::SCHEME_CODE, pk_fingerprint, bytes))
    }

    fn deserialize(pk: &EncapsulationKey) -> Result<Self, Error> {
        <kyberctx::PublicKey as pqcrypto_traits::kem::PublicKey>::from_bytes(&pk.bytes)
            .map(EncapsulationKeyWrapper)
            .map_err(|e|Error::SerializationFailed(SerializationError::PQCrypto(e)))
    }
}

impl GenericEncapsulationPrivateKey for DecapsulationKeyWrapper {
    fn serialize(
        self,
        fingerprint: Fingerprint, 
        encryption: Option<EncryptionArguments>
    ) -> Result<DecapsulationKey,Error> {
        
        let (bytes,encryption): (Vec<u8>,Option<EncryptionParameters>) = 
            if let Some(EncryptionArguments {algorithm,key,salt}) = encryption {
            // Create chacha12 rng for nonce.
            let mut rng = StdRng::from_entropy();
            
            let (enc_sk, nonce): (Vec<u8>,Vec<u8>) = match algorithm {
                AES256GCM => {
                    
                    assert!(key.len() == 32, "Invariant failed. AES256GCM encryption keys must be 32 bytes. key.len() = {}", key.len());
                    
                    let bytes = <kyberctx::SecretKey as pqcrypto_traits::kem::SecretKey>::as_bytes(&self.0);
                    
                    let nonce = Aes256Gcm::generate_nonce(&mut rng);
                    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
                    let ciphertext = cipher.encrypt(&nonce, bytes).unwrap();
                    
                    (ciphertext,nonce.to_vec())
                }
                CHACHA20_POLY1305 => {
                    
                    assert!(key.len() == 32, "Invariant failed. CHACHA20_POLY1305 encryption keys must be 32 bytes. key.len() = {}", key.len());
                    
                    let bytes = <kyberctx::SecretKey as pqcrypto_traits::kem::SecretKey>::as_bytes(&self.0);
                    
                    let nonce = ChaCha20Poly1305::generate_nonce(&mut rng);
                    let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
                    let ciphertext = cipher.encrypt(&nonce, bytes).unwrap();
                    
                    (ciphertext,nonce.to_vec())
                }
                _ => panic!("Unknown encryption algorithm!")
            };
            
            (enc_sk, Some(EncryptionParameters { salt, algorithm, nonce }))
        } else {
            (<kyberctx::SecretKey as pqcrypto_traits::kem::SecretKey>::as_bytes(&self.0).to_vec(),None)
        };
        
        Ok(DecapsulationKey::new(Kyber1024::SCHEME_CODE, fingerprint, encryption, bytes))
    }

    fn deserialize(dk: &DecapsulationKey, key: Option<&[u8]>) -> Result<Self, Error> {
        
        assert!(dk.is_encrypted() == key.is_some(), "Attempted to deserialize an encrypted key without the decryption key");
        
        match &dk.encryption {
            None => {
                let private_key = <kyberctx::SecretKey as pqcrypto_traits::kem::SecretKey>::from_bytes(dk.bytes())
                    .map_err(|e|Error::SerializationFailed(SerializationError::PQCrypto(e)))?;
                
                Ok(Self(private_key))
            },
            Some(EncryptionParameters { salt: _, algorithm, nonce }) => {
                
                let key = key.unwrap();
                match *algorithm {
                    AES256GCM => {
                        
                        assert!(key.len() == 32, "Invariant failed. AES256GCM encryption keys must be 32 bytes. key.len() = {}", key.len());
                        
                        let nonce: [u8;12] = nonce.clone().try_into().unwrap();
                        let cipher = Aes256Gcm::new_from_slice(key).unwrap();
                        let plaintext = cipher.decrypt(&nonce.into(), dk.bytes()).map_err(|_|Error::DecryptionFailed)?;
                        
                        let private_key = <kyberctx::SecretKey as pqcrypto_traits::kem::SecretKey>::from_bytes(&plaintext)
                            .map_err(|e|Error::SerializationFailed(SerializationError::PQCrypto(e)))?;
                        
                        Ok(Self(private_key))
                    },
                    CHACHA20_POLY1305 => {
                        
                        assert!(key.len() == 32, "Invariant failed. CHACHA20_POLY1305 encryption keys must be 32 bytes. key.len() = {}", key.len());
                        
                        let nonce: [u8;12] = nonce.clone().try_into().unwrap();
                        let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
                        let plaintext = cipher.decrypt(&nonce.into(), dk.bytes()).map_err(|_|Error::DecryptionFailed)?;
                        
                        let private_key = <kyberctx::SecretKey as pqcrypto_traits::kem::SecretKey>::from_bytes(&plaintext)
                            .map_err(|e|Error::SerializationFailed(SerializationError::PQCrypto(e)))?;
                        
                        Ok(Self(private_key))
                    }
                    _ => panic!("Unknown encryption algorithm")
                }
            }
        }
    }
}

impl EncryptionScheme for Kyber1024 {
    
    const NAME: &'static str = "Kyber-1024";
    
    const SCHEME_CODE: u32 = 1;

    type EncapsulationKey = EncapsulationKeyWrapper;

    type DecapsulationKey = DecapsulationKeyWrapper;

    type Ciphertext = kyberctx::Ciphertext;

    type SharedSecret = kyberctx::SharedSecret;
    
    type Error = Error;

    fn keypair() -> (Self::EncapsulationKey,Self::DecapsulationKey) {
        let (pk,sk) = kyberctx::keypair();
        
        (EncapsulationKeyWrapper(pk),DecapsulationKeyWrapper(sk))
    }

    fn encapsulate(pk: &Self::EncapsulationKey) -> (Self::SharedSecret,Self::Ciphertext) {
        kyberctx::encapsulate(pk)
    }

    fn decapsulate(ciphertext: &Self::Ciphertext, sk: &Self::DecapsulationKey) -> Self::SharedSecret {
        kyberctx::decapsulate(ciphertext, sk)
    }
}

impl Deref for EncapsulationKeyWrapper {
    type Target = kyberctx::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for DecapsulationKeyWrapper {
    type Target = kyberctx::SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Parseable for kyberctx::SharedSecret {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self,Error> {
        <Self as SharedSecret>::from_bytes(bytes)
            .map_err(|e|Error::SerializationFailed(SerializationError::PQCrypto(e)))
    }
}

impl Parseable for kyberctx::Ciphertext {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self,Error> {
        <Self as Ciphertext>::from_bytes(bytes)
            .map_err(|e|Error::SerializationFailed(SerializationError::PQCrypto(e)))
    }
}

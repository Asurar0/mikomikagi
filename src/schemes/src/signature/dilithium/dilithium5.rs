//! ### Dilithium-5 variant
//! 
//! Current implementation is PQClean library
//! 

// ---------------------------------- Imports --------------------------------------

use std::ops::Deref;

use aes_gcm::Aes256Gcm;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::{Aead, AeadCore} };
use mikomikagi_core::keys::{AES256GCM, CHACHA20_POLY1305, EncryptionParameters, Fingerprint, SignaturePrivateKey, SignaturePublicKey};
use pqcrypto_dilithium::dilithium5 as dilithiumctx;
use pqcrypto_traits::sign::*;
use rand::{rngs::StdRng, SeedableRng};

use crate::{error::{Error, SerializationError}, utils::EncryptionArguments, utils::Parseable};

use super::super::{SignatureScheme, GenericSignaturePublicKey, GenericSignaturePrivateKey};

// ---------------------------------- Defintions --------------------------------------

pub struct Dilithium5;

#[derive(Clone)]
#[repr(transparent)]
/// Implementation wrapper over dilithiumctx::PublicKey
pub struct PublicKey(dilithiumctx::PublicKey);

#[derive(Clone)]
#[repr(transparent)]
/// Implementation wrapper over dilithiumctx::PublicKey
pub struct PrivateKey(dilithiumctx::SecretKey);

// ---------------------------------- Implementation --------------------------------------

impl GenericSignaturePublicKey for PublicKey {    
    fn serialize(self, owner_name: &str) -> Result<SignaturePublicKey, Error> {
        let bytes = <dilithiumctx::PublicKey as pqcrypto_traits::sign::PublicKey>::as_bytes(&self.0).to_vec();
        
        let fingerprint = *blake3::keyed_hash(
            blake3::hash(owner_name.as_bytes())
                .as_bytes(), 
            &bytes)
        .as_bytes();
        
        Ok(SignaturePublicKey::new(Dilithium5::SCHEME_CODE, fingerprint.into(), bytes, None))
    }

    fn deserialize(pk: &SignaturePublicKey) -> Result<Self, Error> {
        <dilithiumctx::PublicKey as pqcrypto_traits::sign::PublicKey>::from_bytes(pk.bytes())
            .map(PublicKey)
            .map_err(|e|Error::SerializationFailed(SerializationError::PQCrypto(e)))
    }
}

impl GenericSignaturePrivateKey for PrivateKey {
    fn serialize(
        self,
        fingerprint: Fingerprint, 
        encryption: Option<EncryptionArguments>
    ) -> Result<SignaturePrivateKey,Error> {
        
        let (bytes,encryption): (Vec<u8>,Option<EncryptionParameters>) = 
            if let Some(EncryptionArguments {algorithm,key,salt}) = encryption {
            // Create chacha12 rng for nonce.
            let mut rng = StdRng::from_entropy();
            
            let (enc_sk, nonce): (Vec<u8>,Vec<u8>) = match algorithm {
                AES256GCM => {
                    
                    assert!(key.len() == 32, "Invariant failed. AES256GCM encryption keys must be 32 bytes. key.len() = {}", key.len());
                    
                    let bytes = <dilithiumctx::SecretKey as pqcrypto_traits::sign::SecretKey>::as_bytes(&self.0);
                    
                    let nonce = Aes256Gcm::generate_nonce(&mut rng);
                    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
                    let ciphertext = cipher.encrypt(&nonce, bytes).unwrap();
                    
                    (ciphertext,nonce.to_vec())
                }
                CHACHA20_POLY1305 => {
                    
                    assert!(key.len() == 32, "Invariant failed. CHACHA20_POLY1305 encryption keys must be 32 bytes. key.len() = {}", key.len());
                    
                    let bytes = <dilithiumctx::SecretKey as pqcrypto_traits::sign::SecretKey>::as_bytes(&self.0);
                    
                    let nonce = ChaCha20Poly1305::generate_nonce(&mut rng);
                    let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
                    let ciphertext = cipher.encrypt(&nonce, bytes).unwrap();
                    
                    (ciphertext,nonce.to_vec())
                }
                _ => panic!("Unknown encryption algorithm!")
            };
            
            (enc_sk, Some(EncryptionParameters { salt, algorithm, nonce }))
        } else {
            (<dilithiumctx::SecretKey as pqcrypto_traits::sign::SecretKey>::as_bytes(&self.0).to_vec(),None)
        };
        
        Ok(SignaturePrivateKey::new(Dilithium5::SCHEME_CODE, fingerprint, encryption, bytes, ))
    }

    fn deserialize(sk: &SignaturePrivateKey, key: Option<&[u8]>) -> Result<Self, Error> {
        
        assert!(sk.encryption.is_some() == key.is_some(), "Attempted to deserialize an encrypted key without the decryption key");
        
        match &sk.encryption {
            None => {
                let private_key = <dilithiumctx::SecretKey as pqcrypto_traits::sign::SecretKey>::from_bytes(&sk.bytes)
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
                        let plaintext = cipher.decrypt(&nonce.into(), sk.bytes.as_ref()).map_err(|_|Error::DecryptionFailed)?;
                        
                        let private_key = <dilithiumctx::SecretKey as pqcrypto_traits::sign::SecretKey>::from_bytes(&plaintext)
                            .map_err(|e|Error::SerializationFailed(SerializationError::PQCrypto(e)))?;
                        
                        Ok(Self(private_key))
                    },
                    CHACHA20_POLY1305 => {
                        
                        assert!(key.len() == 32, "Invariant failed. CHACHA20_POLY1305 encryption keys must be 32 bytes. key.len() = {}", key.len());
                        
                        let nonce: [u8;12] = nonce.clone().try_into().unwrap();
                        let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
                        let plaintext = cipher.decrypt(&nonce.into(), sk.bytes.as_ref()).map_err(|_|Error::DecryptionFailed)?;
                        
                        let private_key = <dilithiumctx::SecretKey as pqcrypto_traits::sign::SecretKey>::from_bytes(&plaintext)
                            .map_err(|e|Error::SerializationFailed(SerializationError::PQCrypto(e)))?;
                        
                        Ok(Self(private_key))
                    }
                    _ => panic!("Unknown encryption algorithm")
                }
            }
        }
    }
}

impl SignatureScheme for Dilithium5 {
    
    const NAME: &'static str = "DILITHIUM-5";
    
    const SCHEME_CODE: u32 = 3;
    
    type PublicKey = PublicKey;

    type PrivateKey = PrivateKey;

    type SignedMessage = dilithiumctx::SignedMessage;

    type Signature = dilithiumctx::DetachedSignature;

    type Error = Error;

    fn keypair() -> (Self::PublicKey,Self::PrivateKey) {
        let (pk,sk) = dilithiumctx::keypair();
        
        (PublicKey(pk),PrivateKey(sk))
    }

    fn sign(message: &[u8], sk: &Self::PrivateKey) -> Self::SignedMessage {
        dilithiumctx::sign(message, sk)
    }

    fn sign_detach(message: &[u8], sk: &Self::PrivateKey) -> Self::Signature {
        dilithiumctx::detached_sign(message, sk)
    }

    fn open(signed_message: &Self::SignedMessage, pk: &Self::PublicKey) -> Result<Vec<u8>,Self::Error> {
        dilithiumctx::open(signed_message, pk).map_err(|_| Self::Error::VerificationFailed)
    }

    fn verify(message: &[u8], signature: &Self::Signature, pk: &Self::PublicKey) -> bool {
        dilithiumctx::verify_detached_signature(signature, message, pk).is_ok()
    }
}

impl Deref for PublicKey {
    type Target = dilithiumctx::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for PrivateKey {
    type Target = dilithiumctx::SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Parseable for dilithiumctx::SignedMessage {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self,Error> {
        <Self as SignedMessage>::from_bytes(bytes)
            .map_err(|e|Error::SerializationFailed(SerializationError::PQCrypto(e)))
    }
}

impl Parseable for dilithiumctx::DetachedSignature {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self,Error> {
        <Self as DetachedSignature>::from_bytes(bytes)
            .map_err(|e|Error::SerializationFailed(SerializationError::PQCrypto(e)))
    }
}

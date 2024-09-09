//! ### SPHINCS+-SHA2-128s variant
//! 
//! Current implementation is PQClean library

// ---------------------------------- Imports --------------------------------------

use std::ops::{Deref, DerefMut};

use aes_gcm::Aes256Gcm;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::{Aead, AeadCore} };
use mikomikagi_core::keys::{AES256GCM, CHACHA20_POLY1305, EncryptionParameters, Fingerprint, SignaturePrivateKey, SignaturePublicKey};
use slh_dsa::{signature::{Keypair, SignerMut, Verifier}, Sha2_128s, Signature, SigningKey, VerifyingKey};
use rand::{rngs::StdRng, SeedableRng};

use crate::{error::{Error, SerializationError}, utils::EncryptionArguments, utils::Parseable};

use super::super::{SignatureScheme, GenericSignaturePublicKey, GenericSignaturePrivateKey};

// ---------------------------------- Defintions --------------------------------------

pub struct SlhDsaSha2128s;

#[derive(Clone)]
#[repr(transparent)]
/// Implementation wrapper over VerifyingKey<Sha2_128s>
pub struct PublicKey(VerifyingKey<Sha2_128s>);

#[derive(Clone)]
#[repr(transparent)]
/// Implementation wrapper over SigningKey<Sha2_128s>
pub struct PrivateKey(SigningKey<Sha2_128s>);

// ---------------------------------- Implementation --------------------------------------

impl GenericSignaturePublicKey for PublicKey {    
    fn serialize(self, owner_name: &str) -> Result<SignaturePublicKey, Error> {
        let bytes = self.0.to_vec();
        
        let fingerprint = *blake3::keyed_hash(
            blake3::hash(owner_name.as_bytes())
                .as_bytes(), 
            &bytes)
        .as_bytes();
        
        Ok(SignaturePublicKey::new(SlhDsaSha2128s::SCHEME_CODE, fingerprint.into(), bytes, None))
    }

    fn deserialize(pk: &SignaturePublicKey) -> Result<Self, Error> {
        VerifyingKey::<Sha2_128s>::try_from(pk.bytes())
            .map(PublicKey)
            .map_err(|_|Error::SerializationFailed(SerializationError::RustCrypto))
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
                    
                    let bytes = self.to_bytes();
                    
                    let nonce = Aes256Gcm::generate_nonce(&mut rng);
                    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
                    let ciphertext = cipher.encrypt(&nonce, bytes.as_ref()).unwrap();
                    
                    (ciphertext,nonce.to_vec())
                }
                CHACHA20_POLY1305 => {
                    
                    assert!(key.len() == 32, "Invariant failed. CHACHA20_POLY1305 encryption keys must be 32 bytes. key.len() = {}", key.len());
                    
                    let bytes = self.to_bytes();
                    
                    let nonce = ChaCha20Poly1305::generate_nonce(&mut rng);
                    let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
                    let ciphertext = cipher.encrypt(&nonce, bytes.as_ref()).unwrap();
                    
                    (ciphertext,nonce.to_vec())
                }
                _ => panic!("Unknown encryption algorithm!")
            };
            
            (enc_sk, Some(EncryptionParameters { salt, algorithm, nonce }))
        } else {
            (self.to_vec(),None)
        };
        
        Ok(SignaturePrivateKey::new(SlhDsaSha2128s::SCHEME_CODE, fingerprint, encryption, bytes))
    }

    fn deserialize(sk: &SignaturePrivateKey, key: Option<&[u8]>) -> Result<Self, Error> {
        
        assert!(sk.encryption.is_some() == key.is_some(), "Attempted to deserialize an encrypted key without the decryption key");
        
        match &sk.encryption {
            None => {
                let private_key = SigningKey::<Sha2_128s>::try_from(sk.bytes.as_ref())
                    .map_err(|e|Error::SerializationFailed(SerializationError::RustCrypto))?;
                
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
                        
                        let private_key = SigningKey::<Sha2_128s>::try_from(plaintext.as_ref())
                            .map_err(|e|Error::SerializationFailed(SerializationError::RustCrypto))?;
                        
                        Ok(Self(private_key))
                    },
                    CHACHA20_POLY1305 => {
                        
                        assert!(key.len() == 32, "Invariant failed. CHACHA20_POLY1305 encryption keys must be 32 bytes. key.len() = {}", key.len());
                        
                        let nonce: [u8;12] = nonce.clone().try_into().unwrap();
                        let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
                        let plaintext = cipher.decrypt(&nonce.into(), sk.bytes.as_ref()).map_err(|_|Error::DecryptionFailed)?;
                        
                        let private_key = SigningKey::<Sha2_128s>::try_from(plaintext.as_ref())
                            .map_err(|e|Error::SerializationFailed(SerializationError::RustCrypto))?;
                        
                        Ok(Self(private_key))
                    }
                    _ => panic!("Unknown encryption algorithm")
                }
            }
        }
    }
}

impl SignatureScheme for SlhDsaSha2128s {
    
    const NAME: &'static str = "SLH-DSA-SHA2-128s";
    
    const SCHEME_CODE: u32 = 0;
    
    type PublicKey = PublicKey;

    type PrivateKey = PrivateKey;

    type Signature = Signature<Sha2_128s>;

    type Error = Error;

    fn keypair() -> (Self::PublicKey,Self::PrivateKey) {
        let mut rng = StdRng::from_entropy();
        let sk = slh_dsa::SigningKey::<Sha2_128s>::new(&mut rng);
        let pk = sk.verifying_key();
        
        (PublicKey(pk),PrivateKey(sk))
    }

    fn sign(message: &[u8], sk: &mut Self::PrivateKey) -> Self::Signature {
        sk.sign(message)
    }

    fn verify(message: &[u8], signature: &Self::Signature, pk: &Self::PublicKey) -> bool {
        VerifyingKey::<Sha2_128s>::verify(pk, message, signature).is_ok()
    }
}

impl Deref for PublicKey {
    type Target = VerifyingKey<Sha2_128s>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for PrivateKey {
    type Target = SigningKey<Sha2_128s>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PrivateKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Parseable for Signature<Sha2_128s> {
    fn to_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self,Error> {
        Self::try_from(bytes)
            .map_err(|_|Error::SerializationFailed(SerializationError::RustCrypto))
    }
}

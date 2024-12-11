//! ### Kyber768 variant
//!
//! Current implementation is PQClean library
//!

// ---------------------------------- Imports --------------------------------------

use std::ops::Deref;

use aes_gcm::Aes256Gcm;
use chacha20poly1305::{
    aead::{Aead, AeadCore},
    ChaCha20Poly1305, KeyInit,
};
use mikomikagi_core::keys::{
    DecapsulationKey, EncapsulationKey, EncryptionParameters, Fingerprint, AES256GCM,
    CHACHA20_POLY1305,
};
use pqcrypto_mlkem::mlkem768 as mlkemctx;
use pqcrypto_traits::kem::*;
use rand::{rngs::StdRng, SeedableRng};

use crate::{
    error::{Error, SerializationError},
    utils::EncryptionArguments,
    utils::Parseable,
};

use super::super::{
    EncryptionScheme, GenericEncapsulationPrivateKey, GenericEncapsulationPublicKey,
};

// ---------------------------------- Defintions --------------------------------------

pub struct MlKem768;

#[derive(Clone)]
#[repr(transparent)]
/// Implementation wrapper over mlkemctx::PublicKey
pub struct EncapsulationKeyWrapper(mlkemctx::PublicKey);

#[derive(Clone)]
#[repr(transparent)]
/// Implementation wrapper over mlkemctx::PublicKey
pub struct DecapsulationKeyWrapper(mlkemctx::SecretKey);

// ---------------------------------- Implementation --------------------------------------

impl GenericEncapsulationPublicKey for EncapsulationKeyWrapper {
    fn serialize(self, pk_fingerprint: Fingerprint) -> Result<EncapsulationKey, Error> {
        let bytes =
            <mlkemctx::PublicKey as pqcrypto_traits::kem::PublicKey>::as_bytes(&self.0).to_vec();

        Ok(EncapsulationKey::new(
            MlKem768::SCHEME_CODE,
            pk_fingerprint,
            bytes,
        ))
    }

    fn deserialize(pk: &EncapsulationKey) -> Result<Self, Error> {
        <mlkemctx::PublicKey as pqcrypto_traits::kem::PublicKey>::from_bytes(&pk.bytes)
            .map(EncapsulationKeyWrapper)
            .map_err(|e| Error::SerializationFailed(SerializationError::PQCrypto(e)))
    }
}

impl GenericEncapsulationPrivateKey for DecapsulationKeyWrapper {
    fn serialize(
        self,
        fingerprint: Fingerprint,
        encryption: Option<EncryptionArguments>,
    ) -> Result<DecapsulationKey, Error> {
        let (bytes, encryption): (Vec<u8>, Option<EncryptionParameters>) = if let Some(
            EncryptionArguments {
                algorithm,
                key,
                salt,
            },
        ) = encryption
        {
            // Create chacha12 rng for nonce.
            let mut rng = StdRng::from_entropy();

            let (enc_sk, nonce): (Vec<u8>, Vec<u8>) = match algorithm {
                AES256GCM => {
                    assert!(key.len() == 32, "Invariant failed. AES256GCM encryption keys must be 32 bytes. key.len() = {}", key.len());

                    let bytes =
                        <mlkemctx::SecretKey as pqcrypto_traits::kem::SecretKey>::as_bytes(&self.0);

                    let nonce = Aes256Gcm::generate_nonce(&mut rng);
                    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
                    let ciphertext = cipher.encrypt(&nonce, bytes).unwrap();

                    (ciphertext, nonce.to_vec())
                }
                CHACHA20_POLY1305 => {
                    assert!(key.len() == 32, "Invariant failed. CHACHA20_POLY1305 encryption keys must be 32 bytes. key.len() = {}", key.len());

                    let bytes =
                        <mlkemctx::SecretKey as pqcrypto_traits::kem::SecretKey>::as_bytes(&self.0);

                    let nonce = ChaCha20Poly1305::generate_nonce(&mut rng);
                    let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
                    let ciphertext = cipher.encrypt(&nonce, bytes).unwrap();

                    (ciphertext, nonce.to_vec())
                }
                _ => panic!("Unknown encryption algorithm!"),
            };

            (
                enc_sk,
                Some(EncryptionParameters {
                    salt,
                    algorithm,
                    nonce,
                }),
            )
        } else {
            (
                <mlkemctx::SecretKey as pqcrypto_traits::kem::SecretKey>::as_bytes(&self.0)
                    .to_vec(),
                None,
            )
        };

        Ok(DecapsulationKey::new(
            MlKem768::SCHEME_CODE,
            fingerprint,
            encryption,
            bytes,
        ))
    }

    fn deserialize(dk: &DecapsulationKey, key: Option<&[u8]>) -> Result<Self, Error> {
        assert!(
            dk.is_encrypted() == key.is_some(),
            "Attempted to deserialize an encrypted key without the decryption key"
        );

        match &dk.encryption {
            None => {
                let private_key =
                    <mlkemctx::SecretKey as pqcrypto_traits::kem::SecretKey>::from_bytes(
                        dk.bytes(),
                    )
                    .map_err(|e| Error::SerializationFailed(SerializationError::PQCrypto(e)))?;

                Ok(Self(private_key))
            }
            Some(EncryptionParameters {
                salt: _,
                algorithm,
                nonce,
            }) => {
                let key = key.unwrap();
                match *algorithm {
                    AES256GCM => {
                        assert!(key.len() == 32, "Invariant failed. AES256GCM encryption keys must be 32 bytes. key.len() = {}", key.len());

                        let nonce: [u8; 12] = nonce.clone().try_into().unwrap();
                        let cipher = Aes256Gcm::new_from_slice(key).unwrap();
                        let plaintext = cipher
                            .decrypt(&nonce.into(), dk.bytes())
                            .map_err(|_| Error::DecryptionFailed)?;

                        let private_key =
                            <mlkemctx::SecretKey as pqcrypto_traits::kem::SecretKey>::from_bytes(
                                &plaintext,
                            )
                            .map_err(|e| {
                                Error::SerializationFailed(SerializationError::PQCrypto(e))
                            })?;

                        Ok(Self(private_key))
                    }
                    CHACHA20_POLY1305 => {
                        assert!(key.len() == 32, "Invariant failed. CHACHA20_POLY1305 encryption keys must be 32 bytes. key.len() = {}", key.len());

                        let nonce: [u8; 12] = nonce.clone().try_into().unwrap();
                        let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
                        let plaintext = cipher
                            .decrypt(&nonce.into(), dk.bytes())
                            .map_err(|_| Error::DecryptionFailed)?;

                        let private_key =
                            <mlkemctx::SecretKey as pqcrypto_traits::kem::SecretKey>::from_bytes(
                                &plaintext,
                            )
                            .map_err(|e| {
                                Error::SerializationFailed(SerializationError::PQCrypto(e))
                            })?;

                        Ok(Self(private_key))
                    }
                    _ => panic!("Unknown encryption algorithm"),
                }
            }
        }
    }
}

impl EncryptionScheme for MlKem768 {
    const NAME: &'static str = "ML-KEM-768";

    const SCHEME_CODE: u32 = 0;

    type EncapsulationKey = EncapsulationKeyWrapper;

    type DecapsulationKey = DecapsulationKeyWrapper;

    type Ciphertext = mlkemctx::Ciphertext;

    type SharedSecret = mlkemctx::SharedSecret;

    type Error = Error;

    fn keypair() -> (Self::EncapsulationKey, Self::DecapsulationKey) {
        let (pk, sk) = mlkemctx::keypair();

        (EncapsulationKeyWrapper(pk), DecapsulationKeyWrapper(sk))
    }

    fn encapsulate(pk: &Self::EncapsulationKey) -> (Self::SharedSecret, Self::Ciphertext) {
        mlkemctx::encapsulate(pk)
    }

    fn decapsulate(
        ciphertext: &Self::Ciphertext,
        sk: &Self::DecapsulationKey,
    ) -> Self::SharedSecret {
        mlkemctx::decapsulate(ciphertext, sk)
    }
}

impl Deref for EncapsulationKeyWrapper {
    type Target = mlkemctx::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for DecapsulationKeyWrapper {
    type Target = mlkemctx::SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Parseable for mlkemctx::SharedSecret {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        <Self as SharedSecret>::from_bytes(bytes)
            .map_err(|e| Error::SerializationFailed(SerializationError::PQCrypto(e)))
    }
}

impl Parseable for mlkemctx::Ciphertext {
    fn to_bytes(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        <Self as Ciphertext>::from_bytes(bytes)
            .map_err(|e| Error::SerializationFailed(SerializationError::PQCrypto(e)))
    }
}

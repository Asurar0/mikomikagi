//! ## Keypair generation
//! 
//! This module defines two type of builders for creating a new keypair.
//! 
//! - `StandaloneKeypairBuilder`, a typed builder that given the required parameters will output
//!    the tuple (`AttachedIdentity`,Signature bytes,`SignaturePublicKey`,`SignaturePrivateKey`). Use it if you
//!    require direct access to the generated keys (e.g. in standalone mode)
//! 
//! - `KeypairBuilder`, a wrapper around `StandaloneKeypairBuilder` that will instead, directly insert
//!    the keypair into the keyring it was generated from. The `finish` method will output the tuple
//!    (`Fingerprint`,`AttachedIdentity`)
//! 
//! ### Routine
//! 
//! The actual routine generating the new keypair is `StandaloneKeypairBuilder::genkey::<S> where S: SignatureScheme`
//! 

// ---------------------------------- Imports --------------------------------------

use std::{ops::{Deref, DerefMut}, time::{Duration, SystemTime, UNIX_EPOCH}};

use mikomikagi_keyring::{error::KeyringError, KeyringWrite};
use mikomikagi_core::{identity::AttachedIdentity, keys::{DecapsulationKey, EncapsulationKey, Fingerprint, SignaturePrivateKey, SignaturePublicKey}};
use mikomikagi_schemes::{encryption::{kyber::{Kyber1024, Kyber768}, EncryptionScheme, GenericEncapsulationPublicKey, GenericEncapsulationPrivateKey}, error::Error, signature::{dilithium::{Dilithium3, Dilithium5}, falcon::Falcon1024, sphincs::{SphincsSha2128s, SphincsSha2256s}, GenericSignaturePrivateKey, GenericSignaturePublicKey, SignatureScheme}, utils::EncryptionArguments};

use crate::{signature::SignatureBuilder, Keyring};

// ---------------------------------- Definition --------------------------------------

#[derive(Clone, Default)]
/// A typed builder for building keypairs (signature only at the moment)
pub struct StandaloneKeypairBuilder<'a> {
    /// Scheme of the signature keys
    signature_scheme: Option<u32>,
    /// Scheme of the encryption keys
    encryption_scheme: Option<u32>,
    /// Name of the owner
    name: Option<&'a str>,
    /// Comment of the owner
    comment: Option<&'a str>,
    /// Validity period
    validity_period: Option<u64>,
    /// Private key encryption
    encryption: Option<EncryptionArguments<'a>>,
    /// Trusted fields
    trusted_fields: Vec<(String,String)>,
}

pub struct KeygenResult {
    attached_identity: AttachedIdentity,
    signature: Vec<u8>,
    signature_public_key: SignaturePublicKey,
    signature_private_key: SignaturePrivateKey,
    encryption_public_key: Option<EncapsulationKey>,
    encryption_private_key: Option<DecapsulationKey>
}

impl<'a> StandaloneKeypairBuilder<'a> {
    
    #[inline(always)]
    /// Generate a new standalone builder
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set owner's name
    pub fn name(&mut self, name: &'a str) -> &mut Self {
        self.name = Some(name);
        self
    }
    
    /// Set identity comment
    pub fn comment(&mut self, comment: Option<&'a str>) -> &mut Self {
        self.comment = comment;
        self
    }
    
    /// Set the validity period of the keypair. Caution: This isn't the date at which the key
    /// will expire
    pub fn validity_period(&mut self, validity_period: Duration) -> &mut Self {
        self.validity_period = Some(validity_period.as_millis() as u64);
        self
    }
    
    /// Adds an additional field to the attached identity
    pub fn trusted_field(&mut self, field: (String,String)) -> &mut Self {
        self.trusted_fields.push(field);
        self
    }
    
    /// Set the signature scheme to use
    pub fn scheme(&mut self, scheme_code: u32) -> &mut Self {
        self.signature_scheme = Some(scheme_code);
        self
    }
    
    pub fn encryption_scheme(&mut self, scheme_code: u32) -> &mut Self {
        self.encryption_scheme = Some(scheme_code);
        self
    }
    
    /// Set up private key encryption. Requires a reference to the key bytes and an integer
    /// describing the encryption algorithm (see `mikomikagi_models::keys::encryption` module)
    pub fn encryption(&mut self, algorithm: u32, key: &'a [u8], salt: Option<Vec<u8>>) -> &mut Self {
        self.encryption = Some(EncryptionArguments::new(algorithm, key, salt));
        self
    }
    
    /// Finish builder and generate the keypair
    /// 
    /// ### Panic
    /// 
    /// This method panic if the following properties are omited:
    /// - `owner_name`
    /// - `signature_scheme`
    /// 
    /// Or if the EncryptionMethod is incorrect
    pub fn build(&self) -> Result<KeygenResult,Error> {
        
        // Generate attached identity
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        
        let attached_identity = AttachedIdentity {
            owner_name: self.name.expect("No name precised in keypair builder! You should precise a name").to_string(),
            creation_date: now,
            expiration_date: self.validity_period.map(|v| now+v).unwrap_or(0),
            owner_comment: self.comment.map(Into::into),
            trusted_fields: self.trusted_fields.clone(),
        };
        
        // Generate signature keypairs
        let (pk,sk) = (match self.signature_scheme.expect("No signature scheme set in builder") {
            SphincsSha2128s::SCHEME_CODE => Self::signature_genkey::<SphincsSha2128s>,
            SphincsSha2256s::SCHEME_CODE => Self::signature_genkey::<SphincsSha2256s>,
            Dilithium3::SCHEME_CODE => Self::signature_genkey::<Dilithium3>,
            Dilithium5::SCHEME_CODE => Self::signature_genkey::<Dilithium5>,
            Falcon1024::SCHEME_CODE => Self::signature_genkey::<Falcon1024>,
            _ => panic!("Unknown signature scheme!")
        })(&attached_identity, self.encryption.clone())?;
        
        // Generate encryption keypair if requested
        let (ek,dk) = match self.encryption_scheme {
            None => (None,None),
            Some(s) => {
                let (ek,dk) = (match s {
                    Kyber768::SCHEME_CODE => Self::encryption_genkey::<Kyber768>,
                    Kyber1024::SCHEME_CODE => Self::encryption_genkey::<Kyber1024>,
                    _ => panic!("Unknown encryption scheme!")
                })(pk.fingerprint(), self.encryption.clone())?;
                
                (Some(ek),Some(dk))
            }
        };
        
        let serialized_attached_identity = borsh::to_vec(&attached_identity).unwrap();
        let hash = blake3::hash(&serialized_attached_identity);
        
        // Sign attached identity with private key
        let signature = SignatureBuilder::new(&sk, self.encryption.as_ref().map(|s|s.key())).sign(hash.as_bytes());
        
        Ok(
            KeygenResult {
                attached_identity,
                signature,
                signature_public_key: pk,
                signature_private_key: sk,
                encryption_public_key: ek,
                encryption_private_key: dk,
            }
        )
    }
    
    /// Keypair generation and serialization routine
    fn signature_genkey<S: SignatureScheme>(attached_identity: &AttachedIdentity, encryption: Option<EncryptionArguments>) -> Result<(SignaturePublicKey,SignaturePrivateKey),Error> {
        
        let (pk,sk) = S::keypair();
        
        let f_pk = pk.serialize(&attached_identity.owner_name)?;
        let f_sk = sk.serialize(f_pk.fingerprint(), encryption)?;
        
        Ok((f_pk,f_sk))
    }
    
    /// Keypair generation and serialization routine
    fn encryption_genkey<E: EncryptionScheme>(fingerprint: Fingerprint, encryption: Option<EncryptionArguments>) -> Result<(EncapsulationKey,DecapsulationKey),Error> {
        
        let (ek,dk) = E::keypair();
        
        let f_ek = ek.serialize(fingerprint)?;
        let f_dk = dk.serialize(fingerprint, encryption)?;
        
        Ok((f_ek,f_dk))
    }
}

/// A keyring wrapper of StandaloneKeypairBuilder. When building, the keys and identity will automatically be imported
/// into the keyring. The `finish` function will return the fingerprint and identity.
/// 
/// If you want direct access to the keypair generated, see `StandaloneKeypairBuilder`
pub struct KeypairBuilder<'a, 'kr, KR: KeyringWrite> {
    /// Reference to the keyring that will obtain these keys
    keyring: &'kr Keyring<KR>,
    /// Signature scheme to use
    builder: StandaloneKeypairBuilder<'a>
}

impl<'a,'kr,KR: KeyringWrite> Keyring<KR> {
    
    /// Generate a new signature keypair builder
    pub fn keypair_builder(&'kr self) -> KeypairBuilder<'a,'kr,KR> {
        KeypairBuilder { 
            keyring: self,
            builder: StandaloneKeypairBuilder {
                signature_scheme: None,
                encryption_scheme: None,
                name: None, 
                comment: None, 
                validity_period: None,
                encryption: None,
                trusted_fields: Vec::new()
            }
        }
    }
}

impl<'a,'kr,KR: KeyringWrite> Deref for KeypairBuilder<'a,'kr,KR> {
    type Target = StandaloneKeypairBuilder<'a>;

    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}

impl<'a,'kr,KR: KeyringWrite> DerefMut for KeypairBuilder<'a,'kr,KR> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.builder
    }
}

impl<'a,'kr,KR: KeyringWrite> KeypairBuilder<'a,'kr,KR> {
    
    /// Finish builder and generate the keypair
    /// 
    /// ### Panic
    /// 
    /// This method panic if the following properties are omited:
    /// - `owner_name`
    /// - `signature_scheme`
    pub fn finish(self) -> Result<(Fingerprint,AttachedIdentity),KeyringError> {
        
        // Generate the keypair
        let res = self.build()?;
        
        // Insert in keyring
        self.keyring.insert_signature_public_key(&res.signature_public_key, &res.signature, &res.attached_identity)?;
        self.keyring.insert_signature_private_key(&res.signature_private_key)?;
        
        // Insert in keyring
        if let Some(ek) = res.encryption_public_key {
            self.keyring.insert_encryption_public_key(&ek)?;
        }
        if let Some(dk) = res.encryption_private_key {
            self.keyring.insert_encryption_private_key(&dk)?;
        }
        
        Ok((res.signature_public_key.fingerprint(), res.attached_identity))
    }
}

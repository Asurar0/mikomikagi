//! ## Keyring > Export subcommand
//! 
//! Implementation of `keyring export` subcommand, which will export a PUBLIC or PRIVATE key block file
//! from a keypair in the keyring. 
//! 
//! ### Arguments
//! 
//! * `-o` | `--output`     : If set, the export key block will be written to the specified path instead of being displayed.
//! * `-f` | `--fingerprint`: Specify the fingerprint of the keypair to export.
//! * `--owner`             : Specify the owner name of the keypair to export.
//! 

// ---------------------------------- Imports --------------------------------------

use std::{fs, io::Write};

use mikomikagi_keyring::KeyringWrite;
use mikomikagi_lib::{signature::SignatureBuilder, Keyring};
use mikomikagi_core::{export::{tag::{PRIVATE_KEY_BLOCK, PUBLIC_KEY_BLOCK}, DecapsulationKeyBlock, EncapsulationKeyBlock, PublicKeyBlock, PrivateKeyBlock}, keys::{EncapsulationKey, DecapsulationKey, SignaturePrivateKey}};
use pem::Pem;

use crate::{cli::Args, utils::{fetch_signature_private_key, search::select_fingerprint}};

// ---------------------------------- Definitions ----------------------------------

/// Main export routine
pub fn export<KR: KeyringWrite>(keyring: &Keyring<KR>, secret_key: bool, fingerprint: &Option<[u8;32]>, owner: &Option<String>) {
    
    // Export appropriate data in PEM encoded format
    let pem = match secret_key {
        false => export_public_key(keyring, fingerprint, owner),
        true => export_private_key(keyring, fingerprint, owner)
    };
    
    // Output in either file or stdout
    if let Some(path) = &Args::global().output {
        // If --output set then output the message to this file
        // TODO: ask confirmation for overwrite
        let mut file = fs::OpenOptions::new().create(true).write(true).truncate(true).open(path).unwrap();
        file.write_all(pem.as_bytes()).unwrap();
        
        println!("Successfully generated exported at {}", path.canonicalize().unwrap().display());
    } else {
        println!("{pem}");
    }
}

/// Export a public key block into a PEM encoded format
pub fn export_public_key<KR: KeyringWrite>(keyring: &Keyring<KR>, fingerprint: &Option<[u8;32]>, owner: &Option<String>) -> String {
    
    // Get fingerprint (if needed)
    let fingerprint = select_fingerprint(keyring, fingerprint, owner).unwrap();
    
    // Get Public key, attached identity and according signature
    let public_key = keyring.get_signature_public_key(&fingerprint).unwrap();
    let encapsulation_key = keyring.get_encryption_public_key(&fingerprint).unwrap();
    let attached_identity = keyring.get_attached_identity(&fingerprint).unwrap();
    let attached_signature = keyring.get_attached_identity_signature(&fingerprint).unwrap();
    
    let encapsulation_key = encapsulation_key.map(|ek| export_encryption_public_key(keyring, ek));
    
    // Generate exported public key block and encode it
    let exported_block = PublicKeyBlock {
        public_key,
        attached_identity,
        attached_signature,
        encapsulation_key,
    };
    
    pem::encode(&Pem::new(PUBLIC_KEY_BLOCK, borsh::to_vec(&exported_block).unwrap()))
}

pub fn export_private_key<KR: KeyringWrite>(keyring: &Keyring<KR>, fingerprint: &Option<[u8;32]>, owner: &Option<String>) -> String {
    
    // Get fingerprint (if needed)
    let fingerprint = select_fingerprint(keyring, fingerprint, owner).unwrap();
    
    // Get private key and decapsulation key
    let (private_key,key) = fetch_signature_private_key(keyring, fingerprint).unwrap();
    let decapsulation_key = keyring.get_encryption_private_key(&fingerprint).unwrap();
    
    // Generate signature for private key and decapsulation key
    let (signature,decapsulation_key) = generate_private_key_signature((&private_key,key), decapsulation_key);
    
    // Generate exported public key block and encode it
    let exported_block = PrivateKeyBlock {
        private_key,
        signature,
        decapsulation_key,
    };
    
    pem::encode(&Pem::new(PRIVATE_KEY_BLOCK, borsh::to_vec(&exported_block).unwrap()))
}

/// Export a private key block into a PEM encoded format
pub fn export_encryption_public_key<KR: KeyringWrite>(keyring: &Keyring<KR>, encapsulation_key: EncapsulationKey) -> EncapsulationKeyBlock {
    
    // Fetch signature private key
    let (sk,key) = fetch_signature_private_key(keyring, encapsulation_key.fingerprint()).unwrap();
    
    // Sign encapsulation key
    let ek_blob = borsh::to_vec(&encapsulation_key).unwrap();
    let hash = blake3::hash(&ek_blob);
    let ek_hash_signature = SignatureBuilder::new(&sk, key.as_ref().map(|s| s.as_ref())).sign(hash.as_bytes());
    
    EncapsulationKeyBlock { encapsulation_key, ek_hash_signature }
}

pub fn generate_private_key_signature((sk,key): (&SignaturePrivateKey,Option<[u8;32]>), decapsulation_key: Option<DecapsulationKey>) -> (Vec<u8>,Option<DecapsulationKeyBlock>)
{    
    let sk_blob = borsh::to_vec(sk).unwrap();
    let hash = blake3::hash(&sk_blob);
    let sk_sig = SignatureBuilder::new(&sk, key.as_ref().map(|s| s.as_ref())).sign(hash.as_bytes());
    
    let dk_block = if let Some(decapsulation_key) = decapsulation_key {
        let dk_blob = borsh::to_vec(&decapsulation_key).unwrap();
        let hash = blake3::hash(&dk_blob);
        let signature = SignatureBuilder::new(&sk, key.as_ref().map(|s| s.as_ref())).sign(hash.as_bytes());
        
        Some(DecapsulationKeyBlock { decapsulation_key, signature })
    } else {
        None
    };
    
    (sk_sig,dk_block)
}

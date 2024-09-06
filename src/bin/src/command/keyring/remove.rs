//! ## Keyring > Remove subcommand
//! 
//! Implementation of `keyring remove` subcommand, delete all keys associated with a fingerprint 
//! or owner from the default keyring (or specified one with `--keyring-path`)
//! 
//! ### Arguments
//! 
//! * `-f` | `--fingerprint`: Specify the fingerprint of the keypair to details.
//! * `--owner`             : Specify the owner name of the keypair to details.
//! 

// ---------------------------------- Imports --------------------------------------

use mikomikagi_keyring::KeyringWrite;
use mikomikagi_lib::Keyring;

use crate::utils::search::select_fingerprint;

// ---------------------------------- Definitions ----------------------------------

/// Remove all keys related to an owner name or specific fingerprint
pub fn remove<KR: KeyringWrite>(keyring: &Keyring<KR>, fingerprint: &Option<[u8;32]>, owner: &Option<String>) {
    
    let fingerprint = select_fingerprint(keyring, fingerprint, owner).unwrap();
    
    // Delete each keys
    let identity = keyring.remove_keys(&fingerprint).unwrap();
    
    // Print message
    print!("Deleted keys {} of {}", hex::encode(fingerprint), identity.owner_name);
    if let Some(comment) = identity.owner_comment {
        println!(" ({})", comment);
    }
}

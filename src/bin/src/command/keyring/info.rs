//! ## Keyring > Info subcommand
//! 
//! Implementation of `keyring info` subcommand, which display a complete summary of a specific
//! key stored in the default keyring (or specified one with `--keyring-path`)
//! 
//! ### Arguments
//! 
//! * `-f` | `--fingerprint`: Specify the fingerprint of the keypair to details.
//! * `--owner`             : Specify the owner name of the keypair to details.
//! 

// ---------------------------------- Imports --------------------------------------

use mikomikagi_keyring::KeyringWrite;
use mikomikagi_lib::Keyring;
use mikomikagi_tui::list::KeySummary;

use crate::utils::search::select_fingerprint;

// ---------------------------------- Definitions ----------------------------------

pub fn info<KR: KeyringWrite>(keyring: &Keyring<KR>, fingerprint: &Option<[u8;32]>, owner: &Option<String>) {
    
    // Get fingerprint
    let fingerprint = select_fingerprint(keyring, fingerprint, owner).unwrap();
    
    // Get all data
    let public_key = keyring.get_signature_public_key(&fingerprint).unwrap();
    let statistics = keyring.get_key_statistics(&fingerprint).unwrap();
    let attached_identity = keyring.get_attached_identity(&fingerprint).unwrap();
    let encryption_scheme = keyring.get_encryption_public_key(&fingerprint).unwrap().map(|p| p.scheme);
    
    KeySummary::print_long_from(fingerprint, public_key.scheme(), encryption_scheme, statistics, attached_identity);
}

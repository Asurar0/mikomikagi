//! ## Keyring > Import subcommand
//! 
//! Implementation of `keyring import` subcommand, which import a given PUBLIC or PRIVATE key block file
//! into keyring. This subcommand will not import a private key if the public key isn't stored in keyring. 
//! 
//! ### Arguments
//! 
//! * `-i` | `--input`      : The path to the key block file
//! 

// ---------------------------------- Imports --------------------------------------

use std::{fs::{self}, path::Path};

use mikomikagi_core::export::tag;
use mikomikagi_keyring::KeyringWrite;
use mikomikagi_lib::{import::KeyringImportBuilder, Keyring};


// ---------------------------------- Handler --------------------------------------

/// Import keys from a file or stdin
pub fn import<KR: KeyringWrite>(keyring: &Keyring<KR>, input: &Path) {
    let importer = KeyringImportBuilder::new(keyring);
    
    // Read file
    let buffer = fs::read(input).expect("Unable to read file.");
    
    // Parse PEM and Match tag
    let parsed = pem::parse(buffer).expect("Expected PEM format. This file is not a correct one");
    
    match parsed.tag() {
        // Parse and import public key block
        tag::PUBLIC_KEY_BLOCK => importer.import_public_key(borsh::from_slice(parsed.contents()).unwrap()),
        tag::PRIVATE_KEY_BLOCK => importer.import_private_key(borsh::from_slice(parsed.contents()).unwrap()),
        _ => todo!()
    }.unwrap();
}

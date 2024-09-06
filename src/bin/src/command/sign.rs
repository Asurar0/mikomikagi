//! ## Sign subcommand
//! 
//! Implementation of `sign` subcommand, which take as an input a path to a file containing a message.
//! Will attempt to sign it with the specified key into an SIGNED MESSAGE BLOCK.
//! 
//! ### Arguments
//! 
//! * `-i` | `--input`      : The path to the message file
//! * `--stdin`             : If set, will read the message from stdin instead
//! * `-o` | `--output`     : If set, the signed message or detached signature will be written to the specified path instead of being displayed.
//! * `-f` | `--fingerprint`: Specify the fingerprint of the keypair to use.
//! * `--owner`             : Specify the owner name of the keypair to use.
//! 

// ---------------------------------- Imports --------------------------------------

use std::{fs, io::Write, path::PathBuf};

use mikomikagi_keyring::{error::KeyringError, KeyringWrite};
use mikomikagi_lib::{signature::SignatureBuilder, Keyring};
use mikomikagi_core::{export::{tag::SIGNED_MESSAGE, SignedMessageBlock}, keys::Fingerprint};
use mikomikagi_tui::list::KeySummary;
use pem::Pem;

use crate::{cli::Args, utils::{fetch_signature_private_key, search::select_fingerprint}};

// ---------------------------------- Handler --------------------------------------

/// Sign subcommand entry point;
pub fn entry<
    KR: KeyringWrite
>(
    keyring: &Keyring<KR>,
    fingerprint: Option<[u8;32]>, 
    owner: &Option<String>, 
    path: &PathBuf
) {    
    // Get fingerprint
    let fingerprint = select_fingerprint(keyring, &fingerprint, owner).unwrap();
    
    // Check expiration
    let attached_identity = keyring.get_attached_identity(&fingerprint).unwrap();
    if attached_identity.is_expired() {        
        // If not --force then abort
        if !Args::global().force {
            KeySummary::has_expired_signature(fingerprint);
            std::process::exit(0);
        }
    }
    
    // Get message
    let message = fs::read(path).unwrap();
    
    let signed_message = sign(keyring, fingerprint, message).unwrap();
    export(&signed_message).unwrap();
}

/// Signing routine
fn sign<
    KR: KeyringWrite
>(
    keyring: &Keyring<KR>, 
    fingerprint: Fingerprint, 
    message: Vec<u8>
) -> Result<String,KeyringError> {
    
    // Get private key
    let (private_key,key) = fetch_signature_private_key(keyring, fingerprint).unwrap();
    
    // Make a signature builder and sign the message
    let builder = SignatureBuilder::new(&private_key, key.as_ref().map(|s| s.as_ref()));
    let signed_message = builder.sign_block(&message);
    
    // PEM encode it
    let pem = pem::encode(&Pem::new(SIGNED_MESSAGE, borsh::to_vec(&signed_message).unwrap()));
    Ok(pem)
}

/// Output result in file or stdout
fn export(
    signed_message: &str
) -> Result<(),KeyringError> {
    
    if let Some(output) = &Args::global().output {
        // If --output set then output the message to this file
        let mut file = fs::OpenOptions::new().create(true).write(true).truncate(true).open(output).unwrap();
        file.write_all(signed_message.as_bytes()).unwrap();
        
        println!("Successfully generated signed message at {}", output.canonicalize().unwrap().display());
    } else {
        // Else output to stdout
        println!("{signed_message}");
    }
    
    Ok(())
}

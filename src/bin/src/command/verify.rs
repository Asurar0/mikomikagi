//! ## Decryption subcommand
//! 
//! Implementation of `verify` subcommand, which take as an input a path to a file containing a PEM-encoded SIGNED MESSAGE BLOCK
//! Will attempt to verify it with the specified public key.
//! 
//! ### Arguments
//! 
//! * `-i` | `--input`      : The path to the signed message file
//! * `--stdin`             : If set, will read the signed message from stdin instead
//! * `-o` | `--output`     : If set, the verified message (if present) will be written to the specified path instead of being displayed.
//! * `-f` | `--fingerprint`: Specify the fingerprint of the keypair to use.
//! * `--owner`             : Specify the owner name of the keypair to use.
//! 

// ---------------------------------- Imports --------------------------------------

use std::{fs, path::PathBuf};

use mikomikagi_keyring::{error::KeyringError, KeyringWrite};
use mikomikagi_lib::{signature::VerifierBuilder, Keyring};
use mikomikagi_core::{export::{tag::SIGNED_MESSAGE, SignedMessageBlock}, keys::Fingerprint};
use mikomikagi_tui::{list::KeySummary, signature::Result as VerifierResult};

use crate::utils::search::select_fingerprint;

// ---------------------------------- Handler --------------------------------------

/// Verify subcommand entry point
pub fn entry<KR: KeyringWrite>(keyring: &Keyring<KR>, fingerprint: &Option<[u8;32]>, owner: &Option<String>, path: &PathBuf, stdout: bool) {
    
    // Get fingerprint
    let fingerprint = select_fingerprint(keyring, fingerprint, owner).unwrap();
    
    // Read file
    let message = fs::read(path).unwrap();
    
    // Parse message block
    let signed_message_block = parse(&message).unwrap();
    
    if signed_message_block.message.is_none() {
        println!("Detached signature block isn't supported yet!");
        std::process::exit(0)
    }
    
    // Verify it
    let verified = verify(keyring, fingerprint, &signed_message_block).unwrap();
    
    // Output result
    if verified {
        VerifierResult::verification_successful(fingerprint);
        
        // If -s --stdout is set, print signed message to terminal.
        if stdout {
            let message = signed_message_block.message.as_ref().unwrap();
            let string = String::from_utf8_lossy(message);
            println!("\n{string}");
        }
    } else {
        VerifierResult::verification_failed(fingerprint)
    }
}

/// Attempt to parse the given raw data into an SignedMessageBlock
pub fn parse(
    message: &[u8]
) -> Result<SignedMessageBlock,KeyringError> {
    
    // Parse message
    let pem = pem::parse(message).expect("This file isn't PEM encoded. Aborting.");
    if pem.tag() != SIGNED_MESSAGE {
        panic!("This is not a signed message");
    }
    
    // Deserialize export block
    Ok(borsh::from_slice(pem.contents()).unwrap())
}

/// Verify routine
pub fn verify<
    KR: KeyringWrite
>(
    keyring: &Keyring<KR>,
    fingerprint: Fingerprint,
    signed_message_block: &SignedMessageBlock
) -> Result<bool, KeyringError> {
    
    // Get public key
    let public_key = keyring.get_signature_public_key(&fingerprint)?;
    let attached_identity = keyring.get_attached_identity(&fingerprint)?;
    
    // Check if key has expired
    if attached_identity.is_expired() {
        KeySummary::has_expired_verification(fingerprint);
    }
    
    // Build verifier and verify message with signature
    let verifier = VerifierBuilder::new(&public_key).verify_block(signed_message_block);
    
    Ok(verifier)
}

//! ## Encryption subcommand
//! 
//! Implementation of `encrypt` subcommand, which take as an input a path to a file containing a message.
//! Will attempt to encrypt it with the specified key into an ENCRYPTE MESSAGE BLOCK.
//! 
//! ### Arguments
//! 
//! * `-i` | `--input`      : The path to the message file to encrypt
//! * `--stdin`             : If set, will read the message from stdin instead
//! * `-o` | `--output`     : If set, the encrypted message will be written to the specified path instead of being displayed.
//! * `-f` | `--fingerprint`: Specify the fingerprint of the keypair to use.
//! * `--owner`             : Specify the owner name of the keypair to use.
//! 

// ---------------------------------- Imports --------------------------------------

use std::{fs, io::{stdin, Read, Write}, path::PathBuf};

use mikomikagi_keyring::{error::KeyringError, KeyringWrite};
use mikomikagi_lib::{encryption::EncryptionBuilder, Keyring};
use mikomikagi_core::{export::tag::ENCRYPTED_MESSAGE, keys::Fingerprint};
use mikomikagi_tui::list::KeySummary;
use pem::Pem;

use crate::{cli::Args, utils::search::select_fingerprint};

// ---------------------------------- Handler --------------------------------------

/// Encrypt subcommand entry point
pub fn entry<
    KR: KeyringWrite
>(
    keyring: &Keyring<KR>,
    fingerprint: Option<[u8;32]>, 
    owner: &Option<String>, 
    path: &Option<PathBuf>
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
    let message = if let Some(path) = path {
        fs::read(path).expect("Unable to read requested message")
    } else if !Args::global().stdin {
        println!("No message has been specified for encryption.");
        std::process::exit(0);
    } else {
        let mut string = String::with_capacity(4*1024);
        stdin().read_to_string(&mut string).expect("Unable to read stdin");
        string.into()
    };
    
    let encrypted_message = encrypt(keyring, fingerprint, message).unwrap();
    export(&encrypted_message).unwrap();
}

/// Fetch encapsulation key linked to the fingerprint and encrypt the message.
/// Returns a PEM-encoded ENCRYPTED MESSAGE BLOCK
fn encrypt<
    KR: KeyringWrite
>(
    keyring: &Keyring<KR>, 
    fingerprint: Fingerprint, 
    message: Vec<u8>
) -> Result<String,KeyringError> {
    
    // Get private key
    let public_key = keyring.get_encryption_public_key(&fingerprint).unwrap().expect("No encapsulation key found.");
    
    // Make a signature builder and sign the message
    let builder = EncryptionBuilder::new(&public_key);
    let encrypted_message = builder.encrypt(&message).unwrap();
    
    // PEM encode it
    let pem = pem::encode(&Pem::new(ENCRYPTED_MESSAGE, borsh::to_vec(&encrypted_message).unwrap()));
    Ok(pem)
}

/// Output ENCRYPTED MESSAGE BLOCK to either file or stdout
fn export(
    encrypted_message: &str
) -> Result<(),KeyringError> {
    
    if let Some(output) = &Args::global().output {
        // If --output set then output the message to this file
        let mut file = fs::OpenOptions::new().create(true).write(true).truncate(true).open(output).unwrap();
        file.write_all(encrypted_message.as_bytes()).unwrap();
        
        println!("Successfully encrypted message at {}", output.canonicalize().unwrap().display());
    } else {
        // Else output to stdout
        println!("{encrypted_message}");
    }
    
    Ok(())
}

//! ## Decryption subcommand
//! 
//! Implementation of `decrypt` subcommand, which take as an input a path to a file containing a PEM-encoded ENCRYPTED MESSAGE BLOCK
//! Will attempt to decrypt it with the specified key.
//! 
//! ### Arguments
//! 
//! * `-i` | `--input`      : The path to the encrypted message file
//! * `--stdin`             : If set, will read the encrypted message from stdin instead
//! * `-o` | `--output`     : If set, the decrypted message will be written to the specified path instead of being displayed.
//! * `-f` | `--fingerprint`: Specify the fingerprint of the keypair to use.
//! * `--owner`             : Specify the owner name of the keypair to use.
//! 

// ---------------------------------- Imports --------------------------------------

use std::{fs, io::{stdin, Read, Write}, path::PathBuf};

use mikomikagi_keyring::{error::KeyringError, KeyringWrite};
use mikomikagi_lib::{encryption::DecryptionBuilder, Keyring};
use mikomikagi_schemes::error::Error;
use mikomikagi_core::{export::{tag::ENCRYPTED_MESSAGE, EncryptedMessageBlock}, keys::Fingerprint};

use crate::{cli::Args, utils::{fetch_encryption_private_key, search::select_fingerprint}};

// ---------------------------------- Implementation --------------------------------------

/// Decrypt subcommand entry point
pub fn entry<KR: KeyringWrite>(keyring: &Keyring<KR>, fingerprint: &Option<[u8;32]>, owner: &Option<String>, path: &Option<PathBuf>) {
    
    // Get fingerprint
    let fingerprint = select_fingerprint(keyring, fingerprint, owner)
        .expect("Unable to select a corresponding fingerprint:");
    
    // Read file or data
    let pem = if let Some(path) = path {
        fs::read(path).expect("Unable to read requested message")
    } else if !Args::global().stdin {
        println!("No message has been specified for decryption.");
        std::process::exit(0);
    } else {
        let mut string = String::with_capacity(4*1024);
        stdin().read_to_string(&mut string).expect("Unable to read stdin");
        string.into()
    };
    
    // Parse encrypted message block
    let encrypted_message_block = parse(&pem);
    
    // Decrypt it
    let plaintext = decrypt(keyring, fingerprint, &encrypted_message_block).unwrap();
    
    // Output result
    if let Some(output) = &Args::global().output {
        // If --output set then output the message to this file
        let mut file = fs::OpenOptions::new().create(true).write(true).truncate(true).open(output).expect("Unable to open destination file.");
        file.write_all(&plaintext).unwrap();
        
        println!("Successfully decrypted message at {}", output.canonicalize().unwrap().display());
    } else {
        // Else output to stdout
        let str = String::from_utf8_lossy(&plaintext);
        println!("\n{str}");
    }
}

/// Attempt to parse the given raw data into an EncryptedMessageBlock
pub fn parse(
    message: &[u8]
) -> EncryptedMessageBlock {
    
    // Parse message
    let pem = pem::parse(message).expect("This file isn't PEM encoded. Aborting.");
    if pem.tag() != ENCRYPTED_MESSAGE {
        println!("This is not an encrypted message! Tag: {} has been found.", pem.tag());
        std::process::exit(0);
    }
    
    // Deserialize export block
    borsh::from_slice(pem.contents())
        .expect("Unable to deserialize PEM content into an ENCRYPTED MESSAGE BLOCK. Aborting.")
}

/// Decrypt the supplied encrypted message
pub fn decrypt<
    KR: KeyringWrite
>(
    keyring: &Keyring<KR>,
    fingerprint: Fingerprint,
    encrypted_message_block: &EncryptedMessageBlock
) -> Result<Vec<u8>, KeyringError> {
    
    // Get private key
    let (private_key,key) = fetch_encryption_private_key(keyring, fingerprint).inspect_err(|err| {
        if let KeyringError::NoResource = err {
            println!("The given keys do not have encryption capabilities (lack of decapsulation key)");
            std::process::exit(0);
        }
    })?;
    
    // Make the decryption builder
    let mut builder = DecryptionBuilder::new(&private_key);
    builder.encryption_key(key.as_ref().map(|s| s.as_ref()));
    
    // Attempt to decrypt it
    let plaintext = builder.decrypt(encrypted_message_block).inspect_err(|err| {
        if let Error::DecryptionFailed = err {
            println!("Unable to decrypt message. The message might be corrupted or the wrong key has been chosen.");
            std::process::exit(0);
        }
    }).map_err(KeyringError::Scheme)?;
    Ok(plaintext)
}

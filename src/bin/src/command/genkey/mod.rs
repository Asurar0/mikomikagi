//! ### Keypair generation
//! 
//! This module define the routine responsible for generating a new keypair and underlying chain of trust.
//! All required informations are collected before generating the keypair into the `KeyGenArgs` structure.
//! 
//! #### Setup mode
//!  
//! Unlike GPG, Mikomikagi do not supports a direct generation mode yet, which parse all the requested informations from 
//! the process arguments. The interactive setup is defined in the `setup` module
//! 

// ---------------------------------- Imports --------------------------------------

use std::time::Duration;

use mikomikagi_keyring::KeyringWrite;
use mikomikagi_lib::Keyring;
use mikomikagi_core::keys::AES256GCM;

use crate::{cli::{Args, Subcommand}, utils::argon2::argon2_derive_password_nonce};

// Interactive setup definition
mod setup;

// ---------------------------------- Definitions ----------------------------------

#[derive(Debug)]
/// Structure containing all the required informations when generating the keypair
struct KeyGenArgs {
    /// The Signature scheme being used
    scheme: u32,
    /// The owner name
    name: String,
    /// Comment
    comment: Option<String>,
    /// Validity period (in millis)
    validity_period: Option<u64>,
    /// Added fields
    fields: Vec<(String,String)>,
    /// Encryption password
    password: Option<String>,
    /// Create encryption keypair
    encryption: Option<u32>,
}

/// Keypair generation entry routine
pub fn entry<KR: KeyringWrite>(keyring: &Keyring<KR>) {
    
    if let Subcommand::GenKey { interactive } = Args::global().subcommand {
        if !interactive {
            // Direct mode
            todo!("Key generation only support interactive mode at the moment");
        } else {
            // Interactive setup
            let args = setup::interactive_setup();
            create_key(keyring, args)
        }
    }
}

/// Actual key generation routine
/// 
/// - First create builder with keyring
/// - set name, scheme and comment
/// - set expiration date
/// - set additional fields
/// - set encryption if required
fn create_key<KR: KeyringWrite>(keyring: &Keyring<KR>, args: KeyGenArgs) {
    
    // Create builder
    let mut builder = keyring.keypair_builder();
    builder
        .name(&args.name)
        .scheme(args.scheme)
        .comment(args.comment.as_deref());
    
    // If expiration date set then add validity period
    if let Some(validity_period) = args.validity_period {
        builder.validity_period(Duration::from_millis(validity_period));
    }
    
    // Add additional trusted fields
    args.fields.into_iter().for_each(|s| {
        builder.trusted_field(s);
    });
    
    // Generate encryption keypair if requested
    if let Some(scheme_code) = &args.encryption {
        builder.encryption_scheme(*scheme_code);
    }
    
    // Branch for lifetimes
    if let Some(password) = &args.password {
        
        // Add encryption to the private key (argon2 derivation)
        let (key,salt) = argon2_derive_password_nonce(password);
        builder.encryption(AES256GCM, &key, Some(salt));
        
        // Finish builder
        match builder.finish() {
            Ok((fingerprint,attached_identity)) => {
                println!("Sucessfully generated new keypair {} owned by {}", hex::encode(fingerprint), attached_identity.owner_name)
            },
            Err(err) => {
                println!("Failed to generate new keypair: {err}");
            },
        }
    } else {
        
        // Finish builder
        match builder.finish() {
            Ok((fingerprint,attached_identity)) => {
                println!("Sucessfully generated new keypair {} owned by {}", hex::encode(fingerprint), attached_identity.owner_name)
            },
            Err(err) => {
                println!("Failed to generate new keypair: {err}");
            },
        }
    }
}

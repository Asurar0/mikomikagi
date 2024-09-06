//! ### Interactive setup
//! 
//! Very ugly code. Planning on migrating most of the ask logic to mikomikagi-tui
//! 

// ---------------------------------- Imports --------------------------------------

use mikomikagi_tui::{prompt::Prompt, template::DIVIDER};
use mikomikagi_schemes::{encryption::ENCRYPTION_SCHEMES_LIST, signature::SIGNATURE_SCHEMES_LIST};

use super::KeyGenArgs;

// ---------------------------------- Definitions ----------------------------------

/// Interactive setup routine. Collect all needed informations and return a `KeyGenArgs` structure for
/// the key generation routine.
pub fn interactive_setup() -> KeyGenArgs {
    // Select available scheme
    println!("Please select a scheme for the new keys:\n");
    for (i, scheme) in SIGNATURE_SCHEMES_LIST.into_iter() {
        println!("({}) - {scheme}", i+1);
    }
    let number = Prompt::ask_parse::<usize>(None, Some(DIVIDER)) - 1;
    
    println!("Selected: {}", SIGNATURE_SCHEMES_LIST[number].1);
    
    // Select name
    let name = Prompt::ask(Some("What's your name: "), None);
    
    // Add comment
    let confirmation = Prompt::ask_confirmation(Some("Do you want to add a comment?"));
    let comment = if confirmation { Some(Prompt::ask(Some("Add a comment: "), None)) } else { None };
    
    // Password?
    let confirmation = Prompt::ask_confirmation(Some("Do you want to encrypt your private key with a password?"));
    let password = if confirmation { Some(Prompt::read_password()) } else { None };
    
    // Expiration date
    let confirmation = Prompt::ask_confirmation(Some("Do you want to set an expiration date to this keypair?"));
    let validity_period = if confirmation { Some(Prompt::ask_parse::<u64>(Some("How many months (30 days) will this key be valid? "), None) * 30 * 24 * 60 * 60 * 1000) } else { None };
    
    // Additional fields?
    let mut fields = Vec::new();
    loop {
        let confirmation = Prompt::ask_confirmation(Some("Do you want to insert an additional field under your public key?"));
        if confirmation { 
            fields.push((Prompt::ask(Some("Name of the field: "), None),Prompt::ask(Some("Content of this field: "), None)));
        } else {
            break
        }
    }
    
    // Generate encryption keypair
    let confirmation = Prompt::ask_confirmation(Some("Do you want to generate an encryption keypair?"));
    let encryption = if confirmation {
        
        println!("Please select a scheme for the new keys:\n");
        for (i, scheme) in ENCRYPTION_SCHEMES_LIST.into_iter() {
            println!("({}) - {scheme}", i+1);
        }
        let number = Prompt::ask_parse::<usize>(None, Some(DIVIDER)) - 1;
        
        println!("Selected: {}", ENCRYPTION_SCHEMES_LIST[number].1);
        Some(number as u32)
    } else { None };
    
    KeyGenArgs { scheme: SIGNATURE_SCHEMES_LIST[number].0, name, validity_period, password, comment, fields, encryption }
}

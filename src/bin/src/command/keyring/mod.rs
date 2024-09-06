//! ## Keyring subcommand
//! 
//! This subcommand handle the management of the keyring storing all the imported or generated keys
//! 

// ---------------------------------- Imports --------------------------------------

use mikomikagi_keyring::KeyringWrite;
use mikomikagi_lib::Keyring;

use crate::cli::{Args, KeyringSubcommand, Subcommand};

pub mod list;
pub mod info;
pub mod import;
pub mod export;
pub mod remove;

// ---------------------------------- Definitions ----------------------------------

pub fn entry<KR: KeyringWrite>(keyring: &Keyring<KR>) {
    
    if let Subcommand::Keyring { subcommand } = &Args::global().subcommand {
        
        match subcommand {
            KeyringSubcommand::List => list::list(keyring),
            KeyringSubcommand::Info { fingerprint, owner } => info::info(keyring, fingerprint, owner),
            KeyringSubcommand::Remove { fingerprint, owner } => remove::remove(keyring, fingerprint, owner),
            KeyringSubcommand::Import { input } => import::import(keyring, input),
            KeyringSubcommand::Export { fingerprint, owner, secret_key } => export::export(keyring, *secret_key, fingerprint, owner),
        }
    }
}

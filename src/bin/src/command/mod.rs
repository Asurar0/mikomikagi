//! ### Subcommands
//! 
//! This module is the entry point of the binary. It imports routine for all defined subcommands.
//! At startup, `main` fn will call `handle_subcommand` which will collect the requested subcommand from arguments
//! and call its `entry()` routine accordingly.
//! 

// ---------------------------------- Imports --------------------------------------

use mikomikagi_keyring::KeyringWrite;
use mikomikagi_lib::Keyring;

use crate::cli::{Args, Subcommand};

// Main subcommands
pub mod verify;
pub mod sign;
pub mod genkey;
pub mod keyring;
pub mod encrypt;
pub mod decrypt;

// ---------------------------------- Handler --------------------------------------

/// Call the requested subcommand entry point 
pub fn handle_subcommand<KR: KeyringWrite>(keyring: &Keyring<KR>) {
    let args = Args::global();
    
    match &args.subcommand {
        Subcommand::Verify { fingerprint, owner, path, stdout } => verify::entry(keyring, fingerprint, owner, path, *stdout),
        Subcommand::Sign { fingerprint, owner, path } => sign::entry(keyring, *fingerprint, owner, path),
        Subcommand::Encrypt { fingerprint, owner, path } => encrypt::entry(keyring, *fingerprint, owner, path),
        Subcommand::Decrypt { fingerprint, owner, path } => decrypt::entry(keyring, fingerprint, owner, path),
        Subcommand::GenKey { interactive: _ } => genkey::entry(keyring),
        Subcommand::Keyring { subcommand: _ } => keyring::entry(keyring),
    }
}

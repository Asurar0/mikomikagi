//! ## Keyring > List subcommand
//! 
//! Implementation of `keyring list` subcommand, which list a short summary of all the 
//! keys stored in the default keyring (or specified one with `--keyring-path`)
//! 

// ---------------------------------- Imports --------------------------------------

use mikomikagi_keyring::KeyringWrite;
use mikomikagi_lib::Keyring;
use mikomikagi_tui::list::KeySummary;

// ---------------------------------- Definitions ----------------------------------

pub fn list<KR: KeyringWrite>(keyring: &Keyring<KR>) {
    // Collect all keys
    let list = keyring.collect().unwrap();
    
    // If keyring is empty print appropriate message. Otherwise continue
    match list.is_empty() {
        true => KeySummary::empty_short(),
        false => {
            KeySummary::before_short();
            
            for (fingerprint,scheme,stats,attached_identity) in list.into_iter() {
                
                KeySummary::print_short_from(fingerprint, scheme, stats, attached_identity)
            }
        }
    }
}

use mikomikagi_keyring::{error::KeyringError, KeyringWrite};
use mikomikagi_lib::Keyring;
use mikomikagi_core::keys::Fingerprint;

/// Utility function that search a corresponding fingerprint in the database given either a fingerprint or owner name
pub fn select_fingerprint<KR: KeyringWrite>(keyring: &Keyring<KR>, fingerprint: &Option<[u8;32]>, owner: &Option<String>) -> Result<Fingerprint,KeyringError> {
    
    // Get fingerprint
    match fingerprint {
        // Fingerprint is directly given. Use it.
        Some(fingerprint) => Ok((*fingerprint).into()),
        None => {
            match owner {
                // No Fingerprint and no owner, abort.
                None => panic!("No owner or fingerprint specified!"),
                // Owner is given. Take the first
                Some(owner) => {
                    Ok(*keyring.get_fingerprint(owner)?.first().ok_or(KeyringError::NoResource)?)
                }
            }
        }
    }
}

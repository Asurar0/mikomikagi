use argon2::argon2_derive_password;
use mikomikagi_keyring::{error::KeyringError, KeyringWrite};
use mikomikagi_lib::Keyring;
use mikomikagi_core::keys::{DecapsulationKey, Fingerprint, SignaturePrivateKey};
use mikomikagi_tui::prompt::Prompt;

/// Argon2 Key derivation
pub mod argon2;

/// Fingerprint selection by owner
pub mod search;

/// Fetch private key from keyring and ask for encryption password if needed
pub fn fetch_signature_private_key<
    KR: KeyringWrite
>(
    keyring: &Keyring<KR>,
    fingerprint: Fingerprint
) -> Result<(SignaturePrivateKey,Option<[u8;32]>),KeyringError> {
    
    // Get private key
    let private_key = keyring.get_signature_private_key(&fingerprint)?;
    
    // If need get the decryption key
    let key: Option<[u8;32]> = match private_key.is_password() {
        true => {
            let salt: [u8;16] = private_key.salt().unwrap().try_into().unwrap();
            let password = Prompt::read_password();
            let key = argon2_derive_password(password.as_str(), &salt);
            
            Some(key)
        },
        false => {
            if private_key.is_encrypted() {
                panic!("The CLI do not support raw key encryption")
            } else {
                None
            }
        }
    };
    
    Ok((private_key,key))
}

/// Fetch private key from keyring and ask for encryption password if needed
pub fn fetch_encryption_private_key<
    KR: KeyringWrite
>(
    keyring: &Keyring<KR>,
    fingerprint: Fingerprint
) -> Result<(DecapsulationKey,Option<[u8;32]>),KeyringError> {
    
    // Get private key
    let private_key = keyring.get_encryption_private_key(&fingerprint)?.ok_or(KeyringError::NoResource)?;
    
    // If need get the decryption key
    let key: Option<[u8;32]> = match private_key.is_password() {
        true => {
            let salt: [u8;16] = private_key.salt().unwrap().try_into().unwrap();
            let password = Prompt::read_password();
            let key = argon2_derive_password(password.as_str(), &salt);
            
            Some(key)
        },
        false => {
            if private_key.is_encrypted() {
                panic!("The CLI do not support raw key encryption")
            } else {
                None
            }
        }
    };
    
    Ok((private_key,key))
}

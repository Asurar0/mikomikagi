use argon2::{password_hash::{SaltString, PasswordHasher}, Argon2};
use rand::{rngs::StdRng, SeedableRng};

/// Derive the password with the given nonce and return the 256 bit key
pub fn argon2_derive_password(password: &str, salt: &[u8;16]) -> [u8;32] {
    
    let argon2 = Argon2::default();
    let salt_string = SaltString::encode_b64(salt.as_ref()).unwrap();
    
    let derived = argon2.hash_password(password.as_bytes(), &salt_string).unwrap();
    let key: [u8;32] = derived.hash.unwrap().as_bytes().try_into().unwrap();
    
    key
}

/// Derive the password and return a 256 bit key + generated Salt
pub fn argon2_derive_password_nonce(password: &str) -> ([u8;32],Vec<u8>) {
    
    let mut rng = StdRng::from_entropy();
    
    let argon2 = Argon2::default();
    let mut salt = [0u8;16];
    let salt_string = SaltString::generate(&mut rng);
    salt_string.decode_b64(&mut salt).unwrap();
    
    let derived = argon2.hash_password(password.as_bytes(), &salt_string).unwrap();
    let key: [u8;32] = derived.hash.unwrap().as_bytes().try_into().unwrap();
    
    (key,salt.to_vec())
}

//! ## Error definition
//! 
//! Define all the possible errors threw from keyring
//! Backend error are included into the enum

use std::array::TryFromSliceError;

use mikomikagi_schemes::error::Error;

#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    
    #[error("LMDB Failed: {0}")]
    LMDB(#[from] heed::Error),
    
    #[error("The requested table ({0}) do not exist. Migration most likely failed or the database is corrupted.")]
    NoTable(&'static str),
    
    #[error("The requested resource do not exist")]
    NoResource,
    
    #[error("Unable to parse data out of the keyring. This is an internal operation and is likely sign of a corruption or illicit modification.\nError: {0}")]
    FailedParsing(#[from] ParsingError),
    
    #[error("Internal error: {0}")]
    Scheme(#[from] Error),
    
    #[error("Error the database file permissions are too permissive.")]
    FilePermission
}

#[derive(Debug, thiserror::Error)]
pub enum ParsingError {
    #[error("Borsh serialization/deserialization failed: {0}")]
    Borsh(borsh::io::Error),
    #[error("Failed to convert a variable size blob into a fixed byte array. This is an invariant and shouldn't happen: {0}")]
    TryInto(TryFromSliceError)
}

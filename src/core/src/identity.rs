// ---------------------------------- Imports --------------------------------------

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use borsh::{BorshDeserialize, BorshSerialize};

// ---------------------------------- Definition --------------------------------------

#[derive(BorshSerialize, BorshDeserialize)]
/// Definition of all the identity-related fields attached to a public key.
pub struct AttachedIdentity {
    /// The owner name
    pub owner_name: String,
    /// Key creation date
    pub creation_date: u64,
    /// Expiration date
    pub expiration_date: u64,
    /// Owner's comment
    pub owner_comment: Option<String>,
    /// Additional trusted fields,
    pub trusted_fields: Vec<(String,String)>,
}

impl AttachedIdentity {
    
    /// Return true if the identity (and underlying keys) has expired. False otherwise.
    pub fn is_expired(&self) -> bool {
        
        if self.expiration_date == 0 { return false }
        
        let expiration_date = UNIX_EPOCH.checked_add(Duration::from_millis(self.expiration_date)).unwrap();
        
        expiration_date < SystemTime::now()
    }
}

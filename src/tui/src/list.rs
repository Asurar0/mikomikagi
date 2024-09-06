use std::{io::{stdout, Write}, time::{Duration, UNIX_EPOCH}};

use crossterm::{style::{Color, Print, ResetColor, SetForegroundColor}, ExecutableCommand, QueueableCommand};
use mikomikagi_core::{identity::AttachedIdentity, keys::Fingerprint};
use mikomikagi_keyring::KeyStorageStatistics;
use mikomikagi_schemes::{encryption::ENCRYPTION_SCHEMES_LIST, signature::SIGNATURE_SCHEMES_LIST};

pub fn stats_character(sk: bool, ek: bool, dk: bool) -> (&'static str,&'static str) {
    
    if !sk && !ek && !dk {
        ("🮣","<pk>")
    }
    else if !sk && ek && !dk {
        ("🮨","<pk|ek>")
    }
    else if sk && !ek && !dk {
        ("🮦","<pk|sk>")
    }
    else if sk && ek && !dk {
        ("🮫","<pk|sk|ek>")
    }
    else {
        ("🮮","<pk|sk|ek|dk>")
    }
}

/// Listing keys
pub struct KeySummary;

impl KeySummary {
    
    pub fn has_expired_signature(fingerprint: Fingerprint) {
        stdout()
            .queue(SetForegroundColor(Color::Rgb { r: 187, g: 61, b: 64 })).unwrap()
            .queue(Print("\nWarning! Key ")).unwrap()
            .queue(SetForegroundColor(Color::Rgb { r: 122, g: 124, b: 125 })).unwrap()
            .queue(Print(hex::encode(fingerprint))).unwrap()
            .queue(SetForegroundColor(Color::Rgb { r: 187, g: 61, b: 64 })).unwrap()
            .queue(Print(" has expired!!\n")).unwrap()
            .queue(ResetColor).unwrap()
            .queue(Print("Aborting! Mikomikagi will not let you use an expired key for signing. use -f or --force argument if you really want to.")).unwrap()
            .queue(Print("\n")).unwrap();
        
        stdout().flush().unwrap()
    }
    
    pub fn has_expired_encryption(fingerprint: Fingerprint) {
        stdout()
            .queue(SetForegroundColor(Color::Rgb { r: 187, g: 61, b: 64 })).unwrap()
            .queue(Print("\nWarning! Key ")).unwrap()
            .queue(SetForegroundColor(Color::Rgb { r: 122, g: 124, b: 125 })).unwrap()
            .queue(Print(hex::encode(fingerprint))).unwrap()
            .queue(SetForegroundColor(Color::Rgb { r: 187, g: 61, b: 64 })).unwrap()
            .queue(Print(" has expired!!\n")).unwrap()
            .queue(ResetColor).unwrap()
            .queue(Print("Aborting! Mikomikagi will not let you use an expired key for encryption. use --force argument if you really want to.")).unwrap()
            .queue(Print("\n")).unwrap();
        
        stdout().flush().unwrap()
    }
    
    pub fn has_expired_verification(fingerprint: Fingerprint) {
        stdout()
            .queue(SetForegroundColor(Color::Rgb { r: 187, g: 61, b: 64 })).unwrap()
            .queue(Print("\nWarning! Key ")).unwrap()
            .queue(SetForegroundColor(Color::Rgb { r: 122, g: 124, b: 125 })).unwrap()
            .queue(Print(hex::encode(fingerprint))).unwrap()
            .queue(SetForegroundColor(Color::Rgb { r: 187, g: 61, b: 64 })).unwrap()
            .queue(Print(" has expired!!\n")).unwrap()
            .queue(ResetColor).unwrap()
            .queue(Print("Upon expiration, the owner cannot guarantee the integrity of this public key, and the authenticity of signatures cannot be assured.")).unwrap()
            .queue(Print("\n")).unwrap();
        
        stdout().flush().unwrap()
    }
    
    /// This method output the message printed before the short keys summaries
    pub fn before_short() {
        
        stdout()
            .queue(Print("\nThe connected keyring contains the following keys:\n")).unwrap()
            .queue(SetForegroundColor(Color::Rgb { r: 122, g: 124, b: 125 })).unwrap()
            .queue(Print(format!("{:─^50}\n",""))).unwrap()
            .queue(ResetColor).unwrap();
    }
    
    /// This method output the message printed in case the keyring is empty
    pub fn empty_short() {
        
        stdout()
            .queue(Print("\nNo keys are currently stored. \nTo view a list of keys, please import existing keys or generate a new one.\n")).unwrap();
        
        stdout().flush().unwrap()
    }
    
    /// Given the collected informations about a key, this method will print
    /// a pretty and short information summary about the key
    pub fn print_short_from(
        fingerprint: [u8;32], 
        scheme: u32, 
        stats: KeyStorageStatistics, 
        attached_identity: AttachedIdentity
    ) {
        
        let (diamond,stat) = stats_character(stats.signature_private_key, stats.encryption_public_subkey, stats.encryption_private_subkey);
        
        if attached_identity.is_expired() {
            stdout()
                .queue(SetForegroundColor(Color::Rgb { r: 187, g: 61, b: 64 })).unwrap();
        } else {
            stdout()
                .queue(SetForegroundColor(Color::Rgb { r: 36, g: 149, b: 255 })).unwrap(); 
        }
        stdout()
            .queue(Print("\n●")).unwrap()
            .queue(ResetColor).unwrap()
            .queue(Print(format!(" {:17}  Owner: {:20}  ", SIGNATURE_SCHEMES_LIST[scheme as usize].1, attached_identity.owner_name))).unwrap()
            .queue(SetForegroundColor(Color::Rgb { r: 36, g: 149, b: 255 })).unwrap()
            .queue(Print(format!("{diamond}  "))).unwrap()
            .queue(ResetColor).unwrap()
            .queue(Print(format!("{stat:>12}\n"))).unwrap();
        
        stdout()
            .queue(SetForegroundColor(Color::Rgb { r: 122, g: 124, b: 125 })).unwrap()
            .queue(Print(format!("  {}\n", hex::encode(fingerprint)))).unwrap()
            .queue(ResetColor).unwrap();
        
        if attached_identity.expiration_date != 0 {
            
            let expiration_date = time::OffsetDateTime::from(UNIX_EPOCH.checked_add(Duration::from_millis(attached_identity.expiration_date)).unwrap());
            let expiration_date = expiration_date.format(&time::format_description::well_known::Rfc2822).unwrap();
            
            if attached_identity.owner_comment.is_none() {    
                stdout()
                    .queue(SetForegroundColor(Color::Rgb { r: 122, g: 124, b: 125 })).unwrap()
                    .queue(Print("  └─── ")).unwrap();
            } else {
                stdout()
                    .queue(SetForegroundColor(Color::Rgb { r: 122, g: 124, b: 125 })).unwrap()
                    .queue(Print("  ├─── ")).unwrap();
            }
            
            if attached_identity.is_expired() {
                stdout()
                    .queue(Print("Expires: ")).unwrap()
                    .queue(ResetColor).unwrap()
                    .queue(Print(expiration_date)).unwrap()
                    .queue(SetForegroundColor(Color::Rgb { r: 187, g: 61, b: 64 })).unwrap()
                    .queue(Print(" [Expired]")).unwrap()
                    .queue(ResetColor).unwrap()
                    .queue(Print("\n")).unwrap();
            }
            else {
                stdout()
                    .queue(Print("Expires: ")).unwrap()
                    .queue(ResetColor).unwrap()
                    .queue(Print(expiration_date)).unwrap()
                    .queue(Print("\n")).unwrap()
                    .queue(ResetColor).unwrap();  
            }
        }
        
        if let Some(comment) = attached_identity.owner_comment {
            stdout()
                .queue(SetForegroundColor(Color::Rgb { r: 122, g: 124, b: 125 })).unwrap()
                .queue(Print("  └─── ")).unwrap()
                .queue(Print("Comment: ")).unwrap()
                .queue(ResetColor).unwrap()
                .queue(Print(format!("\"{}\"\n", comment))).unwrap();
        }
        
        if !attached_identity.trusted_fields.is_empty() {
            stdout()
                .queue(SetForegroundColor(Color::Rgb { r: 206, g: 206, b: 160 })).unwrap()
                .queue(Print(format!("  [+{} additional fields]\n", attached_identity.trusted_fields.len()))).unwrap()
                .queue(ResetColor).unwrap();
        }
        
        stdout().flush().unwrap()
    }
    
    /// Given the collected informations about a key, this method will print
    /// a pretty and short information summary about the key
    pub fn print_long_from(
        fingerprint: Fingerprint, 
        scheme: u32,
        encryption_scheme: Option<u32>,
        stats: KeyStorageStatistics, 
        attached_identity: AttachedIdentity
    ) {
        
        let (diamond,stat) = stats_character(stats.signature_private_key, stats.encryption_public_subkey, stats.encryption_private_subkey);
        
        if attached_identity.is_expired() {
            stdout()
                .queue(SetForegroundColor(Color::Rgb { r: 187, g: 61, b: 64 })).unwrap();
        } else {
            stdout()
                .queue(SetForegroundColor(Color::Rgb { r: 36, g: 149, b: 255 })).unwrap(); 
        }
        stdout()
            .queue(Print("\n●")).unwrap()
            .queue(ResetColor).unwrap()
            .queue(Print(format!(" {:17}  Owner: {:20}  ", SIGNATURE_SCHEMES_LIST[scheme as usize].1, attached_identity.owner_name))).unwrap()
            .queue(SetForegroundColor(Color::Rgb { r: 36, g: 149, b: 255 })).unwrap()
            .queue(Print(format!("{diamond}  "))).unwrap()
            .queue(ResetColor).unwrap()
            .queue(Print(format!("{stat:>12}\n"))).unwrap();
        
        stdout()
            .queue(SetForegroundColor(Color::Rgb { r: 122, g: 124, b: 125 })).unwrap()
            .queue(Print(format!("  {}\n", hex::encode(fingerprint)))).unwrap()
            .queue(ResetColor).unwrap();
        
        let creation_date = time::OffsetDateTime::from(UNIX_EPOCH.checked_add(Duration::from_millis(attached_identity.creation_date)).unwrap());
        let creation_date = creation_date.format(&time::format_description::well_known::Rfc2822).unwrap();
        
        if attached_identity.expiration_date != 0 
        || attached_identity.owner_comment.is_some() 
        || !attached_identity.trusted_fields.is_empty() 
        || encryption_scheme.is_some() 
        {
            stdout()
                .queue(SetForegroundColor(Color::Rgb { r: 122, g: 124, b: 125 })).unwrap()
                .queue(Print("  ├─── Created: ")).unwrap();
        } else {
            stdout()
                .queue(SetForegroundColor(Color::Rgb { r: 122, g: 124, b: 125 })).unwrap()
                .queue(Print("  └─── Created: ")).unwrap();
        }
        stdout()
            .queue(ResetColor).unwrap()
            .queue(Print(creation_date)).unwrap()
            .queue(Print("\n")).unwrap()
            .queue(ResetColor).unwrap();
        
        if attached_identity.expiration_date != 0 {
            
            let expiration_date = time::OffsetDateTime::from(UNIX_EPOCH.checked_add(Duration::from_millis(attached_identity.expiration_date)).unwrap());
            let expiration_date = expiration_date.format(&time::format_description::well_known::Rfc2822).unwrap();
            
            if attached_identity.owner_comment.is_none() {    
                stdout()
                    .queue(SetForegroundColor(Color::Rgb { r: 122, g: 124, b: 125 })).unwrap()
                    .queue(Print("  └─── ")).unwrap();
            } else {
                stdout()
                    .queue(SetForegroundColor(Color::Rgb { r: 122, g: 124, b: 125 })).unwrap()
                    .queue(Print("  ├─── ")).unwrap();
            }
            
            if attached_identity.is_expired() {
                stdout()
                    .queue(Print("Expires: ")).unwrap()
                    .queue(ResetColor).unwrap()
                    .queue(Print(expiration_date)).unwrap()
                    .queue(SetForegroundColor(Color::Rgb { r: 187, g: 61, b: 64 })).unwrap()
                    .queue(Print(" [Expired]")).unwrap()
                    .queue(ResetColor).unwrap()
                    .queue(Print("\n")).unwrap();
            }
            else {
                stdout()
                    .queue(Print("Expires: ")).unwrap()
                    .queue(ResetColor).unwrap()
                    .queue(Print(expiration_date)).unwrap()
                    .queue(Print("\n")).unwrap()
                    .queue(ResetColor).unwrap();  
            }
        }
        
        if let Some(comment) = attached_identity.owner_comment {
            if attached_identity.trusted_fields.is_empty() {
                stdout()
                    .queue(SetForegroundColor(Color::Rgb { r: 122, g: 124, b: 125 })).unwrap()
                    .queue(Print("  └─── ")).unwrap();
            } else {
                stdout()
                    .queue(SetForegroundColor(Color::Rgb { r: 122, g: 124, b: 125 })).unwrap()
                    .queue(Print("  ├─── ")).unwrap();
            }
            stdout()
                .queue(Print("Comment: ")).unwrap()
                .queue(ResetColor).unwrap()
                .queue(Print(format!("\"{}\"\n", comment))).unwrap();
        }
        
        let len = attached_identity.trusted_fields.len().saturating_sub(1);
        for (i,field) in attached_identity.trusted_fields.iter().enumerate() {
            
            if i < len || encryption_scheme.is_some() {
                stdout()
                    .queue(SetForegroundColor(Color::Rgb { r: 206, g: 206, b: 160 })).unwrap()
                    .queue(Print(format!("  ├─── {}: {}\n", field.0, field.1))).unwrap()
                    .queue(ResetColor).unwrap();
            } else {
                stdout()
                    .queue(SetForegroundColor(Color::Rgb { r: 206, g: 206, b: 160 })).unwrap()
                    .queue(Print(format!("  └─── {}: {}\n", field.0, field.1))).unwrap()
                    .queue(ResetColor).unwrap();
            } 
        }
        if let Some(encryption_scheme) = encryption_scheme {
            stdout()
                .queue(SetForegroundColor(Color::Rgb { r: 36, g: 149, b: 255 })).unwrap()
                .queue(Print(format!("  └─── [{} encryption subkey]\n", ENCRYPTION_SCHEMES_LIST[encryption_scheme as usize].1))).unwrap()
                .queue(ResetColor).unwrap();
        }
        
        stdout().flush().unwrap()
    }
}

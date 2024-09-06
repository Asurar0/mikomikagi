use std::io::{stdout, Write};

use crossterm::{style::{Color, Print, ResetColor, SetForegroundColor}, QueueableCommand};
use mikomikagi_core::keys::Fingerprint;

pub struct Result;

impl Result {
    
    pub fn verification_failed(fingerprint: Fingerprint) {
        stdout()
            .queue(SetForegroundColor(Color::Rgb { r: 187, g: 61, b: 64 })).unwrap()
            .queue(Print("\nVerification failed!\n")).unwrap()
            .queue(ResetColor).unwrap()
            .queue(Print("This message is either tampered or has not been signed with the public key ")).unwrap()
            .queue(SetForegroundColor(Color::Rgb { r: 122, g: 124, b: 125 })).unwrap()
            .queue(Print(hex::encode(fingerprint))).unwrap()
            .queue(Print("\n")).unwrap()
            .queue(ResetColor).unwrap();
        
        stdout().flush().unwrap()
    }
    
    pub fn verification_successful(fingerprint: Fingerprint) {
        stdout()
            .queue(SetForegroundColor(Color::Rgb { r: 51, g: 179, b: 117 })).unwrap()
            .queue(Print("\nVerification successful!\n")).unwrap()
            .queue(ResetColor).unwrap()
            .queue(Print("This message has been signed by ")).unwrap()
            .queue(SetForegroundColor(Color::Rgb { r: 122, g: 124, b: 125 })).unwrap()
            .queue(Print(hex::encode(fingerprint))).unwrap()
            .queue(Print("\n")).unwrap()
            .queue(ResetColor).unwrap();
        
        stdout().flush().unwrap()
    }
}

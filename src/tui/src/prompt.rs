use std::{io::{self, BufRead, Write}, str::FromStr};

use passterm::prompt_password_tty;

use crate::template::EN_CONFIRMATION_DIVIDER;

pub struct Prompt;

impl Prompt {
    
    pub fn read_password() -> String {
        
        prompt_password_tty(Some("Private key password: ")).unwrap()
    }
    
    /// Rich ask prompt
    pub fn ask<'a>(message: Option<&'a str>, divider: Option<&'a str>) -> String {
        
        if let Some(message) = message {
            print!("{message}")
        }
        if let Some(divider) = divider {
            print!("{divider}")
        }
        let _ = io::stdout().flush();
        
        let mut lock = io::stdin().lock();
        let mut input = String::new();
        lock.read_line(&mut input).unwrap();
        drop(lock);
        input.pop();
        input
    }
    
    /// Confirmation prompt
    pub fn ask_confirmation(message: Option<&str>) -> bool {
        let mut iter = 0usize;
        loop {
            let res = Prompt::ask(message, Some(EN_CONFIRMATION_DIVIDER)).to_lowercase();
            if res == "yes" || res == "y" {
                break true
            } else if res == "no" || res == "n" {
                break false
            } else {
                if iter == 35 {
                    println!("You find yourself funny?");
                } else {
                    println!("Invalid choice.");
                }
                iter += 1;
                continue;
            }
        }
    }
    
    /// Rich ask prompt
    pub fn ask_parse<'a, T: FromStr>(message: Option<&'a str>, divider: Option<&'a str>) -> T {
        
        loop {
            if let Some(message) = message {
                print!("{message}")
            }
            if let Some(divider) = divider {
                print!("{divider}")
            }
            let _ = io::stdout().flush();
            
            let mut lock = io::stdin().lock();
            let mut input = String::new();
            lock.read_line(&mut input).unwrap();
            drop(lock);
            input.pop();
            
            match input.parse::<T>() {
                Err(_) => {
                    println!("Incorrect input.")
                },
                Ok(res) => break res
            }
        }
    }
}

//! # Mikomikagi binary
//! 
//! This binary is the main command line utility for using mikomikagi
//! 

use std::alloc::System;

use log::Level;
use zalloc::ZeroizingAlloc;

#[global_allocator]
static ZEROIZE_ALLOCATOR: ZeroizingAlloc<System> = ZeroizingAlloc(System);

// Command line arguments
pub mod cli;

// Keyring initialization
pub mod keyring;

// Utilities
pub mod utils;

// Subcommand routine
pub mod command;

fn main() {
    // Clap/CLI parsing
    cli::parse();

    // Initialize logger
    simple_logger::init_with_level(Level::Warn)
        .expect("Failed to initialize logger. Mikomikagi will not start without a logger");
    
    // Open keyring
    let keyring = keyring::init();
    
    // Handle subcommand
    command::handle_subcommand(&keyring);
    
    // Close keyring
    keyring.close();
}

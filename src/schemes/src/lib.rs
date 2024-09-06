//! ### Scheme
//! 
//! This crate define and implements all the post-quantum signature schemes and key encapsulation mechanisms supported by Mikomikagi
//!  

// ---------------------------------- Imports --------------------------------------

/// General scheme error enumeration
pub mod error;

/// Utilities and structures for trait definition
pub mod utils;

/// Digital signature algorithm definition and implementation
pub mod signature;

/// Key Encapsulation mechanism algorithm definition and implementation
pub mod encryption;

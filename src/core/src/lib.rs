//! # Core
//! 
//! This crate defines all the primitives, generic structure and according methods of Mikomikagi.
//! 
//! ## Modules
//! 
//! All the structures or traits are sorted in module specifying their usage.
//! 
//! ## Serialization/Deserialization
//! 
//! All key structure implements serialization in the [borsh](https://borsh.io) format
//! 
//! ## Hashing
//! 
//! Some structure implements specific hashing routines, trait is defined in the `hash` module
//! 

// Keys structure definition
pub mod keys;

// Exported structure definition
pub mod export;

// Identity/Attached informations structure definition
pub mod identity;

// Hashing routine definition
pub mod hash;

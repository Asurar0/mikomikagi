use std::{fs, io, path::PathBuf};

use log::warn;
use mikomikagi_keyring::backend::{LMDBKeyring, LMDBKeyringOptions};
use mikomikagi_lib::Keyring;

static DEFAULT_PATH: &str = ".mikomikagi.d/";

use crate::cli::Args;

/// Open keyring at startup. Parse needed arguments or use defaults. 
pub fn init() -> Keyring<LMDBKeyring> {
    let args = Args::global();
    
    // Get path to keyring
    let path = args.keyring_path.clone().unwrap_or({
        let mut p = dirs::home_dir().unwrap();
        p.push(PathBuf::from(&DEFAULT_PATH).as_path());
        p
    });
    
    // Check if the directory exist, otherwise log and initilialize
    if let Err(err) = fs::read_dir(&path) {
        match err.kind() {
            io::ErrorKind::NotFound => panic!("No directory found at specified path. Be sure you have the right access, typed the correct path or that the program isn't sandboxed."),
            io::ErrorKind::PermissionDenied => panic!("Permission denied. Operating system refuse access to this path, be sure you own this file."),
            kind => panic!("Unknown error happened while opening keyring: {kind}")
        }
    }
    let mut data_mdb_path = path.to_owned();
    data_mdb_path.push("data.mdb");
    let file = fs::File::open(data_mdb_path);
    if let Err(err) = &file {
        match err.kind() {
            io::ErrorKind::NotFound => {
                warn!("Keyring not found at specified directory. Initializing a new one.");
                Keyring::<LMDBKeyring>::init(LMDBKeyringOptions { path: path.clone() }).unwrap()
            },
            io::ErrorKind::PermissionDenied => panic!("Permission denied. Operating system refuse access to this path, be sure you own this file."),
            kind => panic!("Unknown error happened while opening keyring: {kind}")
        }
    }
    
    // Open the keyring in the correct mode
    if args.subcommand.requires_write() {
        Keyring::<LMDBKeyring>::open_write(LMDBKeyringOptions { path }).unwrap()
    } else {
        Keyring::<LMDBKeyring>::open(LMDBKeyringOptions { path }).unwrap()
    }
}

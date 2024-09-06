//! ### Command line arguments
//! 
//! This module define the command line arguments of mikomikagi.
//! Clap `Command` builder is used to define the arguments in the `command` function.
//! The `parse` function collect the matches and parse them into the `Args` structure shared globally
//! across the executable

// ---------------------------------- Imports --------------------------------------

use std::{path::PathBuf, sync::OnceLock};
use clap::{Arg, ArgAction, Command};

// ---------------------------------- Definitions ----------------------------------

/// Globally accessible arguments
static GLOBAL_ARGS: OnceLock<Args> = OnceLock::new();

/// Application's arguments.
pub struct Args {
    /// Requested subcommand
    pub subcommand: Subcommand,
    /// Keyring path
    pub keyring_path: Option<PathBuf>,
    /// Output file
    pub output: Option<PathBuf>,
    /// Force command despite warnings
    pub force: bool,
    /// Process data from stdin instead
    pub stdin: bool
}

impl Args {
    
    #[inline(always)]
    /// Access globally shared arguments, parse them otherwise
    pub fn global<'a>() -> &'a Args {
        GLOBAL_ARGS.get_or_init(parse)
    }
}

/// Requested subcommand
pub enum Subcommand {
    /// Verify data 
    Verify {
        fingerprint: Option<[u8;32]>,
        owner: Option<String>,
        path: PathBuf,
        stdout: bool
    },
    /// Sign data
    Sign {
        fingerprint: Option<[u8;32]>,
        owner: Option<String>,
        path: PathBuf,
    },
    /// Encrypt data with someone public key
    Encrypt {
        fingerprint: Option<[u8;32]>,
        owner: Option<String>,
        path: Option<PathBuf>,
    },
    /// Decrypt data with someone your private key
    Decrypt {
        fingerprint: Option<[u8;32]>,
        owner: Option<String>,
        path: Option<PathBuf>,
    },
    /// Generate new keypair
    GenKey {
        interactive: bool
    },
    /// Keyring management
    Keyring {
        subcommand: KeyringSubcommand
    },
}

impl Subcommand {
    
    /// Indicate if this subcommand requires write access to the keyring
    pub fn requires_write(&self) -> bool {
        match self {
            Subcommand::Verify { fingerprint: _, owner: _, path: _, stdout: _ } => false,
            Subcommand::Sign { fingerprint: _, owner: _, path: _ } => false,
            Subcommand::Decrypt { fingerprint: _, owner: _, path: _ } => false,
            Subcommand::Encrypt { fingerprint: _, owner: _, path: _ } => false,
            Subcommand::GenKey { interactive: _ } => true,
            Subcommand::Keyring { subcommand } => subcommand.requires_write(),
        }
    }
}

/// Keyring subcommand's subcommands
pub enum KeyringSubcommand {
    /// List all the keys in the keyring
    List,
    /// Remove keys from the keyring
    Info {
        fingerprint: Option<[u8;32]>,
        owner: Option<String>,
    },
    Remove {
        fingerprint: Option<[u8;32]>,
        owner: Option<String>,
    },
    /// Import an exported key to the keyring
    Import {
        input: PathBuf,
    },
    /// Export keys from the keyring
    Export {
        fingerprint: Option<[u8;32]>,
        owner: Option<String>,
        secret_key: bool,
    }
}

impl KeyringSubcommand {
    pub fn requires_write(&self) -> bool {
        match self {
            KeyringSubcommand::List => false,
            KeyringSubcommand::Info { fingerprint: _, owner: _ } => false,
            KeyringSubcommand::Remove { fingerprint: _, owner: _ } => true,
            KeyringSubcommand::Import { input: _ } => true,
            KeyringSubcommand::Export { fingerprint: _, owner: _, secret_key: _ } => true,
        }
    }
}

/// Command line interface commands definition
pub fn command() -> clap::Command {
    clap::Command::new("Mikomikagi")
        .about("Post-Quantum signing tool")
        .long_about("Mikomikagi is a post-quantum signing and encryption tool.")
        .version("1.0.0")
        .subcommand_required(true)
        .after_long_help("Developed with 💜 by Asurar0")
        .disable_help_subcommand(true)
        .args_conflicts_with_subcommands(true)
        
        // Global arguments
        .arg(
            Arg::new("stdin")
                .help("Process data from standard input")
                .long_help("Sign or encrypt data coming from the standard input.")
                .long("stdin")
                .global(true)
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("keyring_path")
                .help("Path to the keyring directory")
                .long_help("Path to the keyring directory")
                .long("keyring-path")
                .global(true)
                .action(ArgAction::Set)
        )
        .arg(
            Arg::new("force")
                .help("Force command to execute despite warnings")
                .long_help("Force command to execute despite warnings")
                .long("force")
                .global(true)
                .action(ArgAction::SetTrue)
        )
        .arg(
            Arg::new("output")
                .help("Path of output data")
                .short('o')
                .long("output")
                .long_help("Output path of generated signated/exported/encrypted data")
                .action(ArgAction::Set)
                .global(true)
                .value_hint(clap::ValueHint::FilePath)
        )
        
        // Subcommand definitions
        .subcommand(sign())
        .subcommand(verify())
        .subcommand(encrypt())
        .subcommand(decrypt())
        .subcommand(genkey())
        .subcommand(keyring())
}

// ---------------------------------- Arguments ----------------------------------

// Definition of arguments that are shared between subcommands. Define here to avoid
// repetition as an argument cannot be global and required at the same time
fn _shared_args() -> [Arg; 1] {
    [
        Arg::new("scheme")
            .help("scheme")
            .short('s')
            .long("scheme")
            .help("Signature scheme to use")
            .long_help("Signature scheme to use. [SPHINCS+SHA256]")
            .action(ArgAction::Set)
            .required(false)
            .value_hint(clap::ValueHint::Other),
    ]
}

/// Keypair selection arguments
fn select_args() -> [Arg; 2] {
    [
        Arg::new("fingerprint")
            .help("Fingerprint of the key to interact with")
            .long_help("Fingerprint of the key to interact with")
            .short('f')
            .long("fingerprint")
            .action(ArgAction::Set),
        Arg::new("owner")
            .help("Key's owner name")
            .long_help("Owner of the key")
            .long("owner")
            .action(ArgAction::Set)
    ]
}

// ---------------------------------- Subcommands ----------------------------------

/// Sign subcommand definition
fn sign() -> Command {
    Command::new("sign")
        .about("Sign message or file.")
        .long_about("Create signature from supplied data with the specified scheme.")
        .arg_required_else_help(true)
        .args(select_args())
        .arg(
            Arg::new("message")
                .help("Path to message to sign")
                .long_help("Path to message to sign")
                .short('m')
                .long("message")
                .action(ArgAction::Set)
        )
}

/// Sign subcommand definition
fn encrypt() -> Command {
    Command::new("encrypt")
        .about("Encrypt a message or file")
        .long_about("Encrypt a message or file")
        .arg_required_else_help(true)
        .args(select_args())
        .arg(
            Arg::new("message")
                .help("Path to message to sign")
                .long_help("Path to message to sign")
                .short('i')
                .long("input")
                .conflicts_with("stdin")
                .action(ArgAction::Set)
        )
}

/// Sign subcommand definition
fn decrypt() -> Command {
    Command::new("decrypt")
        .about("Decrypt a message or file")
        .long_about("Decrypt a message or fil")
        .arg_required_else_help(true)
        .args(select_args())
        .arg(
            Arg::new("message")
                .help("Path to message to sign")
                .long_help("Path to message to sign")
                .short('i')
                .long("input")
                .conflicts_with("stdin")
                .action(ArgAction::Set)
        )
}

/// Verify subcommand definition
fn verify() -> Command {
    Command::new("verify")
        .about("Verify message or file.")
        .long_about("Verify supplied signature with the request signature scheme.")
        .arg_required_else_help(true)
        .args(select_args())
        .arg(
            Arg::new("message")
                .help("Path to message to sign")
                .long_help("Path to message to sign")
                .short('m')
                .long("message")
                .action(ArgAction::Set)
        )
        .arg(
            Arg::new("print")
                .help("Print the signed message to stdout")
                .long_help("Print the signed message to stdout")
                .short('s')
                .long("stdout")
                .action(ArgAction::SetTrue)
        )
}

/// Genkey subcommand definition
fn genkey() -> Command {
    Command::new("genkey")
        .about("Generate new keypair.")
        .long_about("Generate new public/private keypair of the specified scheme and optionally attach identities to it.")
        
        // Genkey arguments
        .arg(
            Arg::new("interactive")
                .help("Enable interactive setup for keypair generation.")
                .long_help("Enable interactive setup for keypair generation.")
                .short('i')
                .long("interactive")
                .action(ArgAction::SetTrue)
        )
}

fn keyring() -> Command {
    Command::new("keyring")
        .about("Manage your imported/generated keys")
        .long_about("Manage imported keys")
        .args_conflicts_with_subcommands(true)
        .subcommand_required(true)
        
        .subcommand(
            Command::new("list")
                .about("List all the imported keys in keyring")
                .long_about("List all the imported keys in keyring")
        )
        .subcommand(
            Command::new("info")
                .about("Get details about a specific key")
                .long_about("Fetch all informations relatives to a specific key")
                .arg_required_else_help(true)
                .args(select_args())
        )
        .subcommand(
            Command::new("remove")
                .about("Remove a key from the keyring")
                .long_about("Remove a specific key from the keyring. Either pass the fingerprint or owner's name")
                .arg_required_else_help(true)
                .args(select_args())
        )
        .subcommand(
            Command::new("export")
                .about("Export keys and attached informations from the keyring")
                .long_about("Export keys and attached informations from the keyring")
                .arg_required_else_help(true)
                .args(select_args())
                .arg(
                    Arg::new("secret_key")
                        .help("Export private key instead of public key")
                        .long_help("Export private key instead of public key")
                        .short('s')
                        .long("private-key")
                        .action(ArgAction::SetTrue)
                )
        )
        .subcommand(
            Command::new("import")
                .about("Import keys into the keyring")
                .long_about("Import keys and attached informations into the keyring")
                .arg_required_else_help(true)
                
                .arg(
                    Arg::new("input")
                        .help("Path to the key to import")
                        .long_help("File path to the key file to import")
                        .short('i')
                        .long("input")
                        .action(ArgAction::Set)
                )
        )
        
    
}

// ---------------------------------- Parsing ----------------------------------

/// Parse arguments from command matches.
pub fn parse() -> Args {
    
    let command = command().get_matches();
    
    // First extract global options
    let stdin = *command.get_one::<bool>("stdin").unwrap();
    let force = *command.get_one::<bool>("force").unwrap();
    let keyring_path = command.get_one::<String>("keyring_path").map(PathBuf::from);
    let output = command.get_one::<String>("output").map(PathBuf::from);
    
    if let Some((subcommand, matches)) = command.subcommand() {
        
        // Then extract subcommand
        let subcommand = match subcommand {
            "sign" => {                
                Subcommand::Sign {
                    fingerprint: matches.get_one::<String>("fingerprint").map(|s| {
                        
                        let vec = hex::decode(s).unwrap();
                        let fingerprint: [u8;32] = vec.try_into().unwrap();
                        
                        fingerprint
                    }), 
                    owner: matches.get_one::<String>("owner").cloned(),
                    path: matches.get_one::<String>("message").map(PathBuf::from).unwrap().clone()
                }
            },
            "verify" => {
                Subcommand::Verify {
                    fingerprint: matches.get_one::<String>("fingerprint").map(|s| {
                        
                        let vec = hex::decode(s).unwrap();
                        let fingerprint: [u8;32] = vec.try_into().unwrap();
                        
                        fingerprint
                    }), 
                    owner: matches.get_one::<String>("owner").cloned(),
                    path: matches.get_one::<String>("message").map(PathBuf::from).unwrap().clone(),
                    stdout: *matches.get_one::<bool>("print").unwrap()
                }
            },
            "encrypt" => {                
                Subcommand::Encrypt {
                    fingerprint: matches.get_one::<String>("fingerprint").map(|s| {
                        
                        let vec = hex::decode(s).unwrap();
                        let fingerprint: [u8;32] = vec.try_into().unwrap();
                        
                        fingerprint
                    }), 
                    owner: matches.get_one::<String>("owner").cloned(),
                    path: matches.get_one::<String>("message").map(PathBuf::from)
                }
            },
            "decrypt" => {                
                Subcommand::Decrypt {
                    fingerprint: matches.get_one::<String>("fingerprint").map(|s| {
                        
                        let vec = hex::decode(s).unwrap();
                        let fingerprint: [u8;32] = vec.try_into().unwrap();
                        
                        fingerprint
                    }), 
                    owner: matches.get_one::<String>("owner").cloned(),
                    path: matches.get_one::<String>("message").map(PathBuf::from)
                }
            },
            "genkey" => {
                
                let interactive = *matches.get_one::<bool>("interactive").unwrap();
                
                Subcommand::GenKey { interactive }
            },
            "keyring" => {
                
                let (subcommand, matches) = matches.subcommand().unwrap();
                
                let subcommand = match subcommand {
                    "list" => KeyringSubcommand::List,
                    "info" => KeyringSubcommand::Info { 
                        fingerprint: matches.get_one::<String>("fingerprint").map(|s| {
                            
                            let vec = hex::decode(s).unwrap();
                            let fingerprint: [u8;32] = vec.try_into().unwrap();
                            
                            fingerprint
                        }), 
                        owner: matches.get_one::<String>("owner").cloned()
                    },
                    "remove" => KeyringSubcommand::Remove { 
                        fingerprint: matches.get_one::<String>("fingerprint").map(|s| {
                            
                            let vec = hex::decode(s).unwrap();
                            let fingerprint: [u8;32] = vec.try_into().unwrap();
                            
                            fingerprint
                        }), 
                        owner: matches.get_one::<String>("owner").cloned()
                    },
                    "export" => KeyringSubcommand::Export {
                        fingerprint: matches.get_one::<String>("fingerprint").map(|s| {
                            
                            let vec = hex::decode(s).unwrap();
                            let fingerprint: [u8;32] = vec.try_into().unwrap();
                            
                            fingerprint
                        }), 
                        owner: matches.get_one::<String>("owner").cloned(),
                        secret_key: *matches.get_one::<bool>("secret_key").unwrap(),
                    },
                    "import" => KeyringSubcommand::Import {
                        input: matches.get_one::<String>("input").map(PathBuf::from).unwrap().clone()
                    },
                    _ => unreachable!()
                };
                
                Subcommand::Keyring { subcommand }
            },
            _ => unreachable!()
        };
        
        Args { subcommand, keyring_path, output, force, stdin }        
    } else {
        panic!("No subcommand supplied");
    }
}

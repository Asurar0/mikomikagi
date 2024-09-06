use clap_complete::{generate_to, shells::{Bash, Fish, Zsh, Elvish, PowerShell}};
use std::env;
use std::io::Error;

// Importing command line definition
#[path ="src/cli.rs"]
#[allow(unused, dead_code)]
mod cli;

fn main() -> Result<(), Error> {
    let outdir = match env::var_os("OUT_DIR") {
        None => return Ok(()),
        Some(outdir) => outdir,
    };
    
    // Generate autocompletion files for major shells
    let mut cmd = cli::command();
    generate_to(Bash, &mut cmd, "mikomikagi", outdir.clone())?;
    generate_to(Fish, &mut cmd, "mikomikagi", outdir.clone())?;
    generate_to(Zsh, &mut cmd, "mikomikagi", outdir.clone())?;
    generate_to(Elvish, &mut cmd, "mikomikagi", outdir.clone())?;
    generate_to(PowerShell, &mut cmd, "mikomikagi", outdir)?;

    Ok(())
}

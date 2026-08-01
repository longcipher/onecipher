use std::io;

use clap::CommandFactory;
use clap_complete::{Shell, generate};

use crate::{CliError, cli::Cli};

pub(crate) fn run(shell: &str) -> Result<(), CliError> {
    let shell: Shell = shell.parse().map_err(|_| {
        CliError::InvalidArgs(format!(
            "unsupported shell: {shell} (expected: bash, zsh, fish, powershell, elvish)"
        ))
    })?;
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_string();
    generate(shell, &mut cmd, bin_name, &mut io::stdout());
    Ok(())
}

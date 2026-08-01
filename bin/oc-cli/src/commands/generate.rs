use oc_signer::{Mnemonic, MnemonicStrength};

use crate::CliError;

pub(crate) fn run(words: u32) -> Result<(), CliError> {
    let strength = match words {
        12 => MnemonicStrength::Words12,
        15 => MnemonicStrength::Words15,
        18 => MnemonicStrength::Words18,
        21 => MnemonicStrength::Words21,
        24 => MnemonicStrength::Words24,
        _ => return Err(CliError::InvalidArgs("--words must be 12, 15, 18, 21, or 24".into())),
    };

    let mnemonic = Mnemonic::generate(strength)?;
    let phrase = mnemonic.phrase()?;
    let phrase_str = String::from_utf8(phrase.expose().to_vec())
        .map_err(|e| CliError::InvalidArgs(format!("invalid UTF-8 in mnemonic: {e}")))?;

    println!("{phrase_str}");
    Ok(())
}

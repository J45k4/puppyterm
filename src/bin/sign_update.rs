use std::{env, fs};

use anyhow::{Context, Result};
use puppyterm::updater::sign_payload;

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let secret_key_b64 = args
        .next()
        .context("usage: sign_update <private-key-b64> <input> <output-sig>")?;
    let input_path = args
        .next()
        .context("usage: sign_update <private-key-b64> <input> <output-sig>")?;
    let output_path = args
        .next()
        .context("usage: sign_update <private-key-b64> <input> <output-sig>")?;

    let payload = fs::read(&input_path).with_context(|| format!("reading {input_path}"))?;
    let signature = sign_payload(&secret_key_b64, &payload)?;
    fs::write(&output_path, signature).with_context(|| format!("writing {output_path}"))?;
    Ok(())
}

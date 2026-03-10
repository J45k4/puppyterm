use std::env;

use anyhow::{Context, Result};
use puppyterm::updater::derive_public_key_base64;

fn main() -> Result<()> {
    let secret_key_b64 = env::args()
        .nth(1)
        .context("usage: derive_update_public_key <private-key-b64>")?;
    println!("{}", derive_public_key_base64(&secret_key_b64)?);
    Ok(())
}

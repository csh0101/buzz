//! Operator key loading from secret backends instead of plaintext config.
//!
//! Nostr keys are secp256k1 — cloud KMS services cannot sign with them
//! (KMS supports NIST curves/RSA/HMAC only), so the correct pattern is a
//! *secret store*: fetch the key material at startup, keep it in process
//! memory, never on disk or in env dumps.
//!
//! Supported sources:
//! - `env:VAR` — legacy/dev (e.g. `env:BUZZ_OPERATOR_KEY`)
//! - `file:/path` — file with 0600 perms (e.g. mounted from a vault agent)
//! - `cmd:<command...>` — any secret-store CLI that prints the key on
//!   stdout: macOS Keychain (`security find-generic-password -s NAME -w`),
//!   Vault (`vault kv get -field=nsec secret/buzz/operator`),
//!   AWS Secrets Manager (`aws secretsmanager get-secret-value ...`).

use std::process::Command;

use anyhow::{bail, Context, Result};
use nostr::Keys;

/// Parsed `--key-source` value.
pub enum KeySource {
    Env(String),
    File(std::path::PathBuf),
    Cmd(Vec<String>),
}

impl KeySource {
    /// Parse `env:VAR`, `file:PATH`, or `cmd:PROGRAM ARG...`.
    pub fn parse(spec: &str) -> Result<Self> {
        if let Some(var) = spec.strip_prefix("env:") {
            if var.is_empty() {
                bail!("env: source requires a variable name");
            }
            return Ok(Self::Env(var.to_string()));
        }
        if let Some(path) = spec.strip_prefix("file:") {
            if path.is_empty() {
                bail!("file: source requires a path");
            }
            return Ok(Self::File(path.into()));
        }
        if let Some(cmdline) = spec.strip_prefix("cmd:") {
            let parts: Vec<String> = cmdline.split_whitespace().map(str::to_string).collect();
            if parts.is_empty() {
                bail!("cmd: source requires a command");
            }
            return Ok(Self::Cmd(parts));
        }
        bail!("unknown key source scheme (want env:, file:, or cmd:)");
    }

    /// Fetch the key material and build the operator identity.
    pub fn load_keys(&self) -> Result<Keys> {
        let material = match self {
            Self::Env(var) => std::env::var(var).with_context(|| format!("{var} is not set"))?,
            Self::File(path) => std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?,
            Self::Cmd(parts) => {
                let output = Command::new(&parts[0])
                    .args(&parts[1..])
                    .output()
                    .with_context(|| format!("failed to run secret command `{}`", parts[0]))?;
                if !output.status.success() {
                    bail!(
                        "secret command `{}` failed: {}",
                        parts[0],
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                String::from_utf8(output.stdout).context("secret command output is not UTF-8")?
            }
        };
        Keys::parse(material.trim()).context("key source did not yield a valid nsec/hex key")
    }
}

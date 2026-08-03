//! Hash-chained append-only audit log (JSONL).
//!
//! Every entry carries the SHA-256 of the previous line, so tampering with
//! or deleting historical entries breaks the chain — the same pattern the
//! relay's `buzz-audit` uses. Verify offline with a small script: recompute
//! each `hash` over the entry minus the hash field and compare with
//! `prev_hash` of the next entry.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Hash-chained JSONL audit sink.
pub struct AuditLog {
    path: PathBuf,
    state: Mutex<AuditState>,
}

struct AuditState {
    seq: u64,
    prev_hash: String,
}

impl AuditLog {
    /// Open (or create) the audit file, recovering chain state from the last
    /// line so restarts continue the existing chain.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let mut seq = 0u64;
        let mut prev_hash = "genesis".to_string();
        if path.exists() {
            let file = std::fs::File::open(path)
                .with_context(|| format!("failed to open {}", path.display()))?;
            for line in BufReader::new(file).lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(entry) = serde_json::from_str::<Value>(&line) {
                    seq = entry.get("seq").and_then(Value::as_u64).unwrap_or(seq);
                    if let Some(hash) = entry.get("hash").and_then(Value::as_str) {
                        prev_hash = hash.to_string();
                    }
                }
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            state: Mutex::new(AuditState { seq, prev_hash }),
        })
    }

    /// Append one audit entry. `actor` is a pubkey, SSO subject, or
    /// `"anonymous"` for unauthenticated rejections.
    pub fn log(&self, actor: &str, action: &str, detail: Value) {
        if let Err(err) = self.append(actor, action, detail) {
            tracing::error!(error = %err, "audit log write failed");
        }
    }

    fn append(&self, actor: &str, action: &str, detail: Value) -> Result<()> {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.seq += 1;
        let mut entry = json!({
            "seq": state.seq,
            "ts": chrono::Utc::now().to_rfc3339(),
            "actor": actor,
            "action": action,
            "detail": detail,
            "prev_hash": state.prev_hash,
        });
        let digest = Sha256::digest(entry.to_string().as_bytes());
        let hash = hex::encode(digest);
        entry
            .as_object_mut()
            .context("audit entry is not an object")?
            .insert("hash".to_string(), json!(hash));

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{entry}")?;
        file.sync_data()?;
        state.prev_hash = hash;
        Ok(())
    }
}

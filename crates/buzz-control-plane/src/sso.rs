//! Casdoor SSO integration: OIDC login URLs, code exchange, RS256 JWT
//! verification against Casdoor's JWKS, and a persistent SSO↔npub binding
//! store (JSONL, rebuilt into memory on startup).
//!
//! The binding is what turns "logged in with the company account" into
//! "allowed to provision as this Nostr pubkey" — the same role Builderlab
//! plays in the hosted deployment.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::{json, Value};

/// Static Casdoor configuration.
pub struct CasdoorConfig {
    /// e.g. `http://localhost:8000` — must match the JWT `iss` claim.
    pub endpoint: String,
    pub client_id: String,
    pub client_secret: String,
    /// Our callback, e.g. `http://localhost:8900/auth/casdoor/callback`.
    pub redirect_uri: String,
}

/// Verified identity extracted from a Casdoor access token.
pub struct CasdoorIdentity {
    pub sub: String,
    pub name: String,
    pub email: Option<String>,
    pub org: Option<String>,
}

#[derive(Deserialize)]
struct CasdoorClaims {
    sub: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    owner: Option<String>,
    #[serde(default)]
    exp: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Casdoor OIDC client with a cached JWKS.
pub struct CasdoorClient {
    config: CasdoorConfig,
    http: reqwest::Client,
    jwks: tokio::sync::RwLock<Option<(JwkSet, Instant)>>,
}

impl CasdoorClient {
    /// Create a client for the given Casdoor deployment.
    pub fn new(config: CasdoorConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
            jwks: tokio::sync::RwLock::new(None),
        }
    }

    /// Authorization URL to send the user's browser to.
    pub fn login_url(&self, state: &str) -> String {
        format!(
            "{}/login/oauth/authorize?client_id={}&response_type=code&redirect_uri={}&scope=openid%20profile%20email&state={state}",
            self.config.endpoint, self.config.client_id, self.config.redirect_uri
        )
    }

    /// Exchange an authorization code for an access token.
    pub async fn exchange_code(&self, code: &str) -> Result<String> {
        // Scoped so the non-Send Serializer drops before the await.
        let form_body = {
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            form.append_pair("grant_type", "authorization_code");
            form.append_pair("client_id", &self.config.client_id);
            form.append_pair("client_secret", &self.config.client_secret);
            form.append_pair("code", code);
            form.append_pair("redirect_uri", &self.config.redirect_uri);
            form.finish()
        };
        let response = self
            .http
            .post(format!(
                "{}/api/login/oauth/access_token",
                self.config.endpoint
            ))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form_body)
            .send()
            .await
            .context("casdoor token exchange request failed")?;
        let body = response.text().await?;
        let token: TokenResponse =
            serde_json::from_str(&body).with_context(|| format!("casdoor token error: {body}"))?;
        Ok(token.access_token)
    }

    async fn jwks(&self) -> Result<JwkSet> {
        {
            let cache = self.jwks.read().await;
            if let Some((set, at)) = cache.as_ref() {
                if at.elapsed() < Duration::from_secs(300) {
                    return Ok(set.clone());
                }
            }
        }
        let set: JwkSet = self
            .http
            .get(format!("{}/.well-known/jwks", self.config.endpoint))
            .send()
            .await
            .context("casdoor JWKS fetch failed")?
            .json()
            .await
            .context("casdoor JWKS parse failed")?;
        *self.jwks.write().await = Some((set.clone(), Instant::now()));
        Ok(set)
    }

    /// Verify a Casdoor access token (RS256, issuer, audience, expiry).
    pub async fn verify_access_token(&self, token: &str) -> Result<CasdoorIdentity> {
        let header = decode_header(token).context("malformed JWT header")?;
        let kid = header.kid.ok_or_else(|| anyhow!("JWT has no kid"))?;
        let jwks = self.jwks().await?;
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid.as_str()))
            .ok_or_else(|| anyhow!("unknown JWT kid"))?;
        let key = DecodingKey::from_jwk(jwk).context("unsupported JWK")?;

        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&[self.config.endpoint.as_str()]);
        validation.set_audience(&[self.config.client_id.as_str()]);
        let claims = decode::<CasdoorClaims>(token, &key, &validation)
            .context("JWT verification failed")?
            .claims;
        let _ = claims.exp; // expiry already enforced by `decode`.
        if claims.sub.is_empty() || claims.name.is_empty() {
            bail!("JWT missing sub/name claims");
        }
        Ok(CasdoorIdentity {
            sub: claims.sub,
            name: claims.name,
            email: claims.email,
            org: claims.owner,
        })
    }
}

/// Persistent SSO-subject ↔ npub bindings (JSONL + in-memory index).
pub struct BindingStore {
    path: PathBuf,
    by_sub: Mutex<HashMap<String, String>>,
}

impl BindingStore {
    /// Open (or create) the bindings file, rebuilding the in-memory index.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let mut by_sub = HashMap::new();
        if path.exists() {
            let file = std::fs::File::open(path)
                .with_context(|| format!("failed to open {}", path.display()))?;
            for line in BufReader::new(file).lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(entry) = serde_json::from_str::<Value>(&line) {
                    if let (Some(sub), Some(npub)) = (
                        entry.get("sso_sub").and_then(Value::as_str),
                        entry.get("npub").and_then(Value::as_str),
                    ) {
                        by_sub.insert(sub.to_string(), npub.to_string());
                    } else if let Some(sub) = entry.get("sso_sub").and_then(Value::as_str) {
                        // Tombstone from an unbind.
                        by_sub.remove(sub);
                    }
                }
            }
        }
        Ok(Self {
            path: path.to_path_buf(),
            by_sub: Mutex::new(by_sub),
        })
    }

    /// Bind an SSO subject to a Nostr pubkey (hex). Re-binding replaces the
    /// previous entry; history stays in the JSONL file.
    pub fn bind(&self, sub: &str, npub: &str, sso_name: &str) -> Result<()> {
        {
            let mut map = match self.by_sub.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            map.insert(sub.to_string(), npub.to_string());
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(
            file,
            "{}",
            json!({"sso_sub": sub, "npub": npub, "sso_name": sso_name, "ts": chrono::Utc::now().to_rfc3339()})
        )?;
        file.sync_data()?;
        Ok(())
    }

    /// Remove the binding for an SSO subject (appends a tombstone).
    pub fn unbind_sub(&self, sub: &str) -> Result<bool> {
        let removed = {
            let mut map = match self.by_sub.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            map.remove(sub).is_some()
        };
        if removed {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            writeln!(
                file,
                "{}",
                json!({"sso_sub": sub, "npub": null, "unbound": true, "ts": chrono::Utc::now().to_rfc3339()})
            )?;
            file.sync_data()?;
        }
        Ok(removed)
    }

    /// Look up the bound npub (hex) for an SSO subject.
    pub fn npub_for(&self, sub: &str) -> Option<String> {
        let map = match self.by_sub.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.get(sub).cloned()
    }

    /// Look up the SSO subject bound to a Nostr pubkey (hex), if any.
    pub fn sub_for_npub(&self, npub: &str) -> Option<String> {
        let map = match self.by_sub.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        map.iter()
            .find(|(_, v)| v.as_str() == npub)
            .map(|(k, _)| k.clone())
    }
}

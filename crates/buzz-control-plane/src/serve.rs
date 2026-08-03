//! Self-serve community provisioning HTTP service.
//!
//! End users cannot call the relay's operator API — the operator key is
//! deployment-level. This service sits in between: callers authenticate with
//! **their own** Nostr key (NIP-98 against this service's origin), and the
//! service re-signs the provisioning request with the operator key, pinning
//! the caller as `initial_owner_pubkey` with `create_only` semantics.
//!
//! Hardening over the bare prototype:
//! - replay cache on user NIP-98 event ids
//! - per-user sliding-window rate limits (auth attempts + community creates)
//! - hash-chained JSONL audit log
//! - optional Casdoor SSO gate: `--require-sso` demands the caller's npub is
//!   bound to a company SSO identity before they may provision
//!
//! DNS is solved once, upfront, by the deployment (wildcard record like
//! `*.chat.company.com` -> ingress). Communities created here inherit that
//! wildcard — no per-community DNS work.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Json, Redirect},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use nostr::Keys;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::audit::AuditLog;
use crate::guard::{RateLimiter, ReplayCache};
use crate::nostr_http;
use crate::sso::{BindingStore, CasdoorClient, CasdoorConfig};

/// Shared state for the self-serve service.
pub struct ServeState {
    /// Operator identity used to re-sign upstream calls.
    operator_keys: Keys,
    /// Upstream relay operator origin (must match RELAY_OPERATOR_API_ORIGIN).
    relay_origin: String,
    /// This service's own public origin — NIP-98 `u` tags are verified
    /// against it.
    public_origin: String,
    /// Suffix appended to user-chosen names, e.g. `.chat.company.com`.
    host_suffix: String,
    http: reqwest::Client,
    replay: ReplayCache,
    auth_rate: RateLimiter,
    create_rate: RateLimiter,
    audit: Arc<AuditLog>,
    sso: Option<CasdoorClient>,
    bindings: Option<Arc<BindingStore>>,
    require_sso: bool,
}

/// CLI configuration for [`serve`].
pub struct ServeConfig {
    pub listen: String,
    pub public_origin: String,
    pub host_suffix: String,
    pub data_dir: String,
    pub require_sso: bool,
    pub casdoor: Option<CasdoorConfig>,
    /// Max community creations per user per hour.
    pub rate_create_max: u32,
}

#[derive(Deserialize)]
struct CreateCommunityBody {
    /// User-chosen community name (lowercase DNS label, no dots).
    name: String,
}

#[derive(Deserialize)]
struct AvailabilityQuery {
    name: String,
}

#[derive(Deserialize)]
struct BindBody {
    casdoor_token: String,
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
}

fn api_error(status: StatusCode, message: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "error": message })))
}

/// Community names that would shadow infrastructure subdomains on the
/// public host suffix (e.g. `api.` / `sso.` under the wildcard cert).
pub(crate) const RESERVED_NAMES: &[&str] = &[
    "api", "sso", "www", "mail", "admin", "relay", "casdoor", "cdn", "static", "auth", "login",
    "status", "metrics", "health",
];

/// Validate a user-chosen community name as a single DNS label.
fn validate_name(name: &str) -> Result<&str, (StatusCode, Json<Value>)> {
    let valid = !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
        && !name.ends_with('-');
    if !valid {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid name: 1-32 chars of [a-z0-9-], no leading/trailing hyphen",
        ));
    }
    if RESERVED_NAMES.contains(&name) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid name: reserved for infrastructure",
        ));
    }
    Ok(name)
}

/// Authenticate the calling end user via NIP-98 against this service's
/// origin, with rate limiting and replay protection. Returns the user's
/// pubkey (hex).
fn authenticate_user(
    state: &ServeState,
    headers: &HeaderMap,
    method: &str,
    path_with_query: &str,
    body: Option<&[u8]>,
) -> Result<String, (StatusCode, Json<Value>)> {
    let auth_str = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Nostr "))
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "missing Nostr auth"))?;
    let event_json = String::from_utf8(
        BASE64
            .decode(auth_str)
            .map_err(|_| api_error(StatusCode::UNAUTHORIZED, "invalid base64 in Nostr auth"))?,
    )
    .map_err(|_| api_error(StatusCode::UNAUTHORIZED, "invalid UTF-8 in Nostr auth"))?;

    // Reject replays before doing real verification work.
    let event_id = serde_json::from_str::<Value>(&event_json)
        .ok()
        .and_then(|v| v.get("id").and_then(Value::as_str).map(str::to_string))
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "NIP-98 event has no id"))?;
    if !state.replay.check_and_insert(&event_id) {
        state.audit.log(
            "anonymous",
            "auth.replay_rejected",
            json!({ "event_id": event_id }),
        );
        return Err(api_error(StatusCode::UNAUTHORIZED, "replay detected"));
    }

    let url = format!("{}{}", state.public_origin, path_with_query);
    let pubkey = buzz_auth::verify_nip98_event(&event_json, &url, method, body)
        .map_err(|e| api_error(StatusCode::UNAUTHORIZED, &format!("NIP-98: {e}")))?;
    let hex_key = pubkey.to_hex();

    if !state.auth_rate.allow(&hex_key) {
        state.audit.log(&hex_key, "auth.rate_limited", json!({}));
        return Err(api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many authenticated requests",
        ));
    }
    Ok(hex_key)
}

async fn create_community(
    State(state): State<Arc<ServeState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let user_hex = authenticate_user(&state, &headers, "POST", "/communities", Some(&body))?;

    // SSO gate: the caller's npub must be bound to a company identity.
    if state.require_sso {
        let bound = state
            .bindings
            .as_ref()
            .and_then(|store| store.sub_for_npub(&user_hex));
        if bound.is_none() {
            state
                .audit
                .log(&user_hex, "community.create.sso_required", json!({}));
            return Err(api_error(
                StatusCode::FORBIDDEN,
                "bind your company SSO account first (POST /bindings)",
            ));
        }
    }

    if !state.create_rate.allow(&user_hex) {
        state
            .audit
            .log(&user_hex, "community.create.rate_limited", json!({}));
        return Err(api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "community creation rate limit exceeded",
        ));
    }

    let request: CreateCommunityBody = serde_json::from_slice(&body)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")))?;
    let name = validate_name(&request.name)?;
    let host = format!("{name}{}", state.host_suffix);

    // Operator-signed upstream call; the *user* becomes the owner. create_only
    // so an existing community can never be taken over by re-creating it.
    let payload = serde_json::to_vec(&json!({
        "host": host,
        "initial_owner_pubkey": user_hex,
        "create_only": true,
    }))
    .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    let url = format!("{}/operator/communities", state.relay_origin);
    let (status, text) = nostr_http(
        &state.http,
        &state.operator_keys,
        nostr::nips::nip98::HttpMethod::POST,
        &url,
        Some(&payload),
    )
    .await
    .map_err(|e| {
        api_error(
            StatusCode::BAD_GATEWAY,
            &format!("upstream relay error: {e}"),
        )
    })?;

    let value: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }));
    if !status.is_success() {
        let msg = value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("upstream provisioning failed");
        state.audit.log(
            &user_hex,
            "community.create.failed",
            json!({ "host": host, "upstream_status": status.as_u16(), "error": msg }),
        );
        return Err(api_error(status, msg));
    }

    state.audit.log(
        &user_hex,
        "community.create.ok",
        json!({ "host": host, "community_id": value.get("community_id") }),
    );
    tracing::info!(user = %user_hex, host = %host, "community self-provisioned");
    Ok(Json(json!({
        "community_id": value.get("community_id"),
        "host": host,
        "owner_pubkey": user_hex,
        "status": value.get("status").cloned().unwrap_or(json!("created")),
    })))
}

async fn availability(
    State(state): State<Arc<ServeState>>,
    Query(query): Query<AvailabilityQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let name = validate_name(&query.name)?;
    let host = format!("{name}{}", state.host_suffix);
    let encoded: String = url::form_urlencoded::byte_serialize(host.as_bytes()).collect();
    let url = format!(
        "{}/operator/communities/availability?host={encoded}",
        state.relay_origin
    );
    let (status, text) = nostr_http(
        &state.http,
        &state.operator_keys,
        nostr::nips::nip98::HttpMethod::GET,
        &url,
        None,
    )
    .await
    .map_err(|e| {
        api_error(
            StatusCode::BAD_GATEWAY,
            &format!("upstream relay error: {e}"),
        )
    })?;
    let mut value: Value = serde_json::from_str(&text)
        .map_err(|_| api_error(StatusCode::BAD_GATEWAY, "invalid upstream response"))?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert("host".to_string(), json!(host));
    }
    if !status.is_success() {
        return Err(api_error(status, "upstream availability check failed"));
    }
    Ok(Json(value))
}

/// Redirect the user's browser to Casdoor's authorization page.
async fn casdoor_login(
    State(state): State<Arc<ServeState>>,
) -> Result<Redirect, (StatusCode, Json<Value>)> {
    let sso = state
        .sso
        .as_ref()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "SSO not configured"))?;
    // State is a nonce for CSRF protection; a production deployment should
    // also persist and validate it. Prototype: static marker.
    Ok(Redirect::to(&sso.login_url("buzz")))
}

/// Casdoor callback: exchange the code, verify the token, show the identity.
/// The user then binds this SSO identity to their npub via `POST /bindings`.
#[axum::debug_handler]
async fn casdoor_callback(
    State(state): State<Arc<ServeState>>,
    Query(query): Query<CallbackQuery>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let sso = state
        .sso
        .as_ref()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "SSO not configured"))?;
    let token = sso
        .exchange_code(&query.code)
        .await
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, &format!("casdoor exchange: {e}")))?;
    let identity = sso
        .verify_access_token(&token)
        .await
        .map_err(|e| api_error(StatusCode::UNAUTHORIZED, &format!("casdoor token: {e}")))?;
    state.audit.log(
        &identity.sub,
        "sso.login.ok",
        json!({ "name": identity.name }),
    );
    Ok(Json(json!({
        "sso_sub": identity.sub,
        "sso_name": identity.name,
        "email": identity.email,
        "access_token": token,
        "next_step": "POST /bindings with NIP-98 auth and {\"casdoor_token\": access_token}",
    })))
}

/// Bind the caller's npub (from NIP-98) to a Casdoor SSO identity (from the
/// access token in the body).
async fn bind_sso(
    State(state): State<Arc<ServeState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let sso = state
        .sso
        .as_ref()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "SSO not configured"))?;
    let bindings = state
        .bindings
        .as_ref()
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "SSO not configured"))?;

    let user_hex = authenticate_user(&state, &headers, "POST", "/bindings", Some(&body))?;
    let request: BindBody = serde_json::from_slice(&body)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {e}")))?;
    let identity = sso
        .verify_access_token(&request.casdoor_token)
        .await
        .map_err(|e| api_error(StatusCode::UNAUTHORIZED, &format!("casdoor token: {e}")))?;

    bindings
        .bind(&identity.sub, &user_hex, &identity.name)
        .map_err(|e| api_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    state.audit.log(
        &user_hex,
        "sso.bind.ok",
        json!({ "sso_sub": identity.sub, "sso_name": identity.name }),
    );
    tracing::info!(user = %user_hex, sso = %identity.name, "sso binding created");
    Ok(Json(json!({
        "bound": true,
        "npub": user_hex,
        "sso_sub": identity.sub,
        "sso_name": identity.name,
    })))
}

/// Run the self-serve provisioning service until shutdown.
pub async fn serve(
    operator_keys: Keys,
    relay_origin: &str,
    config: ServeConfig,
) -> anyhow::Result<()> {
    let data_dir = std::path::Path::new(&config.data_dir);
    let public_origin = config.public_origin.trim_end_matches('/').to_string();
    let relay_origin = relay_origin.trim_end_matches('/').to_string();
    let need_bindings =
        config.require_sso || config.casdoor.is_some() || data_dir.join("bindings.jsonl").exists();
    let bindings = if need_bindings {
        Some(Arc::new(BindingStore::open(
            &data_dir.join("bindings.jsonl"),
        )?))
    } else {
        None
    };
    let audit = Arc::new(AuditLog::open(&data_dir.join("audit.jsonl"))?);

    // Builderlab-compatible hosted API for the desktop's "Create a new
    // community" flow — only when SSO is configured.
    let hosted_router = match (&config.casdoor, &bindings) {
        (Some(casdoor_config), Some(bindings)) => Some(
            Arc::new(crate::hosted::HostedState::new(
                crate::hosted::HostedConfig {
                    casdoor: CasdoorClient::new(CasdoorConfig {
                        endpoint: casdoor_config.endpoint.clone(),
                        client_id: casdoor_config.client_id.clone(),
                        client_secret: casdoor_config.client_secret.clone(),
                        redirect_uri: format!("{public_origin}/api/goose/v1/auth/casdoor/callback"),
                    }),
                    casdoor_endpoint: casdoor_config.endpoint.clone(),
                    casdoor_client_id: casdoor_config.client_id.clone(),
                    bindings: bindings.clone(),
                    audit: audit.clone(),
                    operator_keys: operator_keys.clone(),
                    relay_origin: relay_origin.clone(),
                    host_suffix: config.host_suffix.clone(),
                    public_origin: public_origin.clone(),
                },
            ))
            .router(),
        ),
        _ => None,
    };

    let state = Arc::new(ServeState {
        operator_keys,
        relay_origin,
        public_origin,
        host_suffix: config.host_suffix,
        http: reqwest::Client::new(),
        replay: ReplayCache::new(),
        auth_rate: RateLimiter::new(60, 60),
        create_rate: RateLimiter::new(config.rate_create_max, 3600),
        audit,
        sso: config.casdoor.map(CasdoorClient::new),
        bindings,
        require_sso: config.require_sso,
    });
    if state.require_sso && state.sso.is_none() {
        anyhow::bail!(
            "--require-sso needs --casdoor-endpoint/--casdoor-client-id/--casdoor-client-secret"
        );
    }

    let mut app = Router::new()
        .route("/communities", post(create_community))
        .route("/communities/availability", get(availability))
        .route("/bindings", post(bind_sso))
        .route("/auth/casdoor/login", get(casdoor_login))
        .route("/auth/casdoor/callback", get(casdoor_callback))
        .route("/healthz", get(|| async { Json(json!({"status": "ok"})) }))
        .with_state(state);
    if let Some(hosted) = hosted_router {
        app = app.merge(hosted);
    }

    let listener = tokio::net::TcpListener::bind(&config.listen).await?;
    tracing::info!(listen = %config.listen, "self-serve provisioning service up");
    axum::serve(listener, app).await?;
    Ok(())
}

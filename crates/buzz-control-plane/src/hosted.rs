//! Builderlab-compatible hosted-community API (`/api/goose/v1/*`) backed by
//! Casdoor SSO and the relay operator API.
//!
//! The OSS desktop ships a "Create a new community" flow whose Rust client
//! (`desktop/src-tauri/src/builderlab.rs`) speaks to Block's hosted control
//! plane. This module re-implements that exact contract on our own control
//! plane so the desktop flow works unchanged against a self-hosted
//! deployment:
//!
//! - browser login: `/auth/login` -> Casdoor OIDC -> `/auth/casdoor/callback`
//!   -> one-time exchange code -> `/auth/login/exchange` -> session credential
//! - session auth: `X-BB-Session-Credential` header (checked by `/auth/me`)
//! - identity binding: challenge/verify with a signed kind:24243 Nostr event
//! - communities: list/availability/create/archive/unarchive/transfer mapped
//!   onto operator-API calls with the bound npub as owner

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Json, Redirect},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use nostr::{FromBech32, JsonUtil, Keys, PublicKey, ToBech32};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::audit::AuditLog;
use crate::nostr_http;
use crate::sso::{BindingStore, CasdoorClient};

const SESSION_TTL_HOURS: i64 = 24;
const EXCHANGE_TTL_SECONDS: i64 = 120;
const CHALLENGE_TTL_MINUTES: i64 = 5;
const HOSTED_COMMUNITY_LIMIT: usize = 5;
const KIND_NOSTR_IDENTITY_BINDING: u16 = 24243;

/// Everything the hosted API needs, shared across handlers.
pub struct HostedState {
    pub casdoor: CasdoorClient,
    pub casdoor_endpoint: String,
    pub casdoor_client_id: String,
    pub bindings: Arc<BindingStore>,
    pub audit: Arc<AuditLog>,
    pub operator_keys: Keys,
    pub relay_origin: String,
    pub host_suffix: String,
    /// This service's own public origin (used as Casdoor redirect base).
    pub public_origin: String,
    pub http: reqwest::Client,
    sessions: Mutex<HashMap<String, Session>>,
    exchanges: Mutex<HashMap<String, PendingExchange>>,
    challenges: Mutex<HashMap<String, Challenge>>,
}

#[derive(Clone)]
struct Session {
    sub: String,
    name: String,
    email: Option<String>,
    expires_at: DateTime<Utc>,
}

struct PendingExchange {
    sub: String,
    name: String,
    email: Option<String>,
    created_at: DateTime<Utc>,
}

struct Challenge {
    nonce: String,
    verification_code: String,
    origin: String,
    expires_at: DateTime<Utc>,
    sso_sub: String,
}

/// Construction parameters for [`HostedState`].
pub struct HostedConfig {
    pub casdoor: CasdoorClient,
    pub casdoor_endpoint: String,
    pub casdoor_client_id: String,
    pub bindings: Arc<BindingStore>,
    pub audit: Arc<AuditLog>,
    pub operator_keys: Keys,
    pub relay_origin: String,
    pub host_suffix: String,
    pub public_origin: String,
}

impl HostedState {
    /// Create the hosted state with empty session/exchange/challenge stores.
    pub fn new(config: HostedConfig) -> Self {
        Self {
            casdoor: config.casdoor,
            casdoor_endpoint: config.casdoor_endpoint,
            casdoor_client_id: config.casdoor_client_id,
            bindings: config.bindings,
            audit: config.audit,
            operator_keys: config.operator_keys,
            relay_origin: config.relay_origin,
            host_suffix: config.host_suffix,
            public_origin: config.public_origin,
            http: reqwest::Client::new(),
            sessions: Mutex::new(HashMap::new()),
            exchanges: Mutex::new(HashMap::new()),
            challenges: Mutex::new(HashMap::new()),
        }
    }

    /// Build the router for the Builderlab-compatible surface.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/api/goose/v1/auth/login", get(auth_login))
            .route(
                "/api/goose/v1/auth/casdoor/callback",
                get(auth_casdoor_callback),
            )
            .route(
                "/api/goose/v1/auth/login/exchange",
                post(auth_login_exchange),
            )
            .route("/api/goose/v1/auth/me", get(auth_me))
            .route(
                "/api/goose/v1/buzz/nostr-identities/current",
                post(identity_current),
            )
            .route(
                "/api/goose/v1/buzz/nostr-identities/challenge",
                post(identity_challenge),
            )
            .route(
                "/api/goose/v1/buzz/nostr-identities/verify",
                post(identity_verify),
            )
            .route(
                "/api/goose/v1/buzz/nostr-identities/delete",
                post(identity_delete),
            )
            .route(
                "/api/goose/v1/buzz/communities/list",
                post(communities_list),
            )
            .route(
                "/api/goose/v1/buzz/communities/availability",
                post(communities_availability),
            )
            .route("/api/goose/v1/buzz/communities", post(communities_create))
            .route(
                "/api/goose/v1/buzz/communities/archive",
                post(communities_archive),
            )
            .route(
                "/api/goose/v1/buzz/communities/unarchive",
                post(communities_unarchive),
            )
            .route(
                "/api/goose/v1/buzz/communities/transfer",
                post(communities_transfer),
            )
            .with_state(self)
    }
}

fn hosted_error(code: &str, message: &str) -> Json<Value> {
    Json(json!({ "error": { "code": code, "message": message } }))
}

fn setup_needed_error() -> Json<Value> {
    Json(json!({
        "error": {
            "code": "missing_mapping",
            "message": "Connect your Buzz identity before creating a community.",
            "setup_needed": true,
        }
    }))
}

fn random_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn six_digit_code() -> String {
    let bytes = uuid::Uuid::new_v4().into_bytes();
    (0..6).map(|i| (b'0' + bytes[i] % 10) as char).collect()
}

fn base64url_nonce() -> String {
    // 32 random bytes -> 43 base64url chars, matching the desktop validator.
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Extract the hosted session from the X-BB-Session-Credential header.
fn require_session(
    state: &HostedState,
    headers: &HeaderMap,
) -> Result<(String, Session), (StatusCode, Json<Value>)> {
    let credential = headers
        .get("X-BB-Session-Credential")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                hosted_error("unauthorized", "Sign in first."),
            )
        })?;
    let mut sessions = match state.sessions.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    sessions.retain(|_, s| s.expires_at > Utc::now());
    sessions
        .get(&credential)
        .cloned()
        .map(|s| (credential, s))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                hosted_error("unauthorized", "Session expired. Sign in again."),
            )
        })
}

/// The bound npub (hex) for the session's SSO subject, or a setup error.
fn require_bound_npub(
    state: &HostedState,
    session: &Session,
) -> Result<String, (StatusCode, Json<Value>)> {
    state
        .bindings
        .npub_for(&session.sub)
        .ok_or_else(|| (StatusCode::OK, setup_needed_error()))
}

// ---------------------------------------------------------------------------
// Auth: browser login through Casdoor, session credential for the desktop.
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct LoginQuery {
    #[serde(rename = "returnTo")]
    return_to: String,
}

async fn auth_login(
    State(state): State<Arc<HostedState>>,
    Query(query): Query<LoginQuery>,
) -> Result<Redirect, (StatusCode, Json<Value>)> {
    // The desktop passes a loopback callback; refuse anything else so this
    // endpoint can't become an open redirector.
    if !query.return_to.starts_with("http://127.0.0.1:")
        && !query.return_to.starts_with("http://localhost")
    {
        return Err((
            StatusCode::BAD_REQUEST,
            hosted_error("invalid_return_to", "returnTo must be a loopback URL."),
        ));
    }
    let encoded_state = URL_SAFE_NO_PAD.encode(query.return_to.as_bytes());
    let redirect_uri = format!("{}/api/goose/v1/auth/casdoor/callback", state.public_origin);
    let encoded_uri: String =
        url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect();
    let url = format!(
        "{}/login/oauth/authorize?client_id={}&response_type=code&redirect_uri={encoded_uri}&scope=openid%20profile%20email&state={encoded_state}",
        state.casdoor_endpoint, state.casdoor_client_id,
    );
    Ok(Redirect::to(&url))
}

#[derive(Deserialize)]
struct CasdoorCallbackQuery {
    code: String,
    state: String,
}

async fn auth_casdoor_callback(
    State(state): State<Arc<HostedState>>,
    Query(query): Query<CasdoorCallbackQuery>,
) -> Result<Redirect, (StatusCode, Json<Value>)> {
    let return_to_bytes = URL_SAFE_NO_PAD
        .decode(query.state.as_bytes())
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                hosted_error("invalid_state", "Bad state."),
            )
        })?;
    let return_to = String::from_utf8(return_to_bytes).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            hosted_error("invalid_state", "Bad state."),
        )
    })?;
    if !return_to.starts_with("http://127.0.0.1:") && !return_to.starts_with("http://localhost") {
        return Err((
            StatusCode::BAD_REQUEST,
            hosted_error("invalid_state", "Bad state."),
        ));
    }
    let token = state
        .casdoor
        .exchange_code(&query.code)
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                hosted_error("sso_exchange", &e.to_string()),
            )
        })?;
    let identity = state
        .casdoor
        .verify_access_token(&token)
        .await
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                hosted_error("sso_verify", &e.to_string()),
            )
        })?;

    let exchange_code = uuid::Uuid::new_v4().simple().to_string();
    {
        let mut exchanges = match state.exchanges.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        exchanges
            .retain(|_, p| Utc::now() - p.created_at < Duration::seconds(EXCHANGE_TTL_SECONDS));
        exchanges.insert(
            exchange_code.clone(),
            PendingExchange {
                sub: identity.sub,
                name: identity.name,
                email: identity.email,
                created_at: Utc::now(),
            },
        );
    }
    Ok(Redirect::to(&format!("{return_to}?code={exchange_code}")))
}

#[derive(Deserialize)]
struct ExchangeBody {
    code: String,
}

async fn auth_login_exchange(
    State(state): State<Arc<HostedState>>,
    Json(body): Json<ExchangeBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let pending = {
        let mut exchanges = match state.exchanges.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        exchanges.remove(&body.code)
    };
    let pending = pending
        .filter(|p| Utc::now() - p.created_at < Duration::seconds(EXCHANGE_TTL_SECONDS))
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                hosted_error("invalid_code", "Login code expired or unknown."),
            )
        })?;

    let credential = random_token();
    let expires_at = Utc::now() + Duration::hours(SESSION_TTL_HOURS);
    {
        let mut sessions = match state.sessions.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        sessions.insert(
            credential.clone(),
            Session {
                sub: pending.sub.clone(),
                name: pending.name.clone(),
                email: pending.email.clone(),
                expires_at,
            },
        );
    }
    state.audit.log(
        &pending.sub,
        "hosted.login.ok",
        json!({ "name": pending.name }),
    );
    Ok(Json(json!({
        "session_credential": credential,
        "expires_at": expires_at.to_rfc3339(),
    })))
}

async fn auth_me(
    State(state): State<Arc<HostedState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let (_, session) = require_session(&state, &headers)?;
    Ok(Json(json!({
        "email": session.email,
        "name": session.name,
        "expires_at": session.expires_at.to_rfc3339(),
    })))
}

// ---------------------------------------------------------------------------
// Nostr identity binding (challenge/verify with a signed kind:24243 event).
// ---------------------------------------------------------------------------

async fn identity_current(
    State(state): State<Arc<HostedState>>,
    headers: HeaderMap,
    Json(_body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let (_, session) = require_session(&state, &headers)?;
    let Some(npub_hex) = state.bindings.npub_for(&session.sub) else {
        return Ok(setup_needed_error());
    };
    identity_json(&npub_hex)
}

fn identity_json(npub_hex: &str) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let public_key = PublicKey::from_hex(npub_hex).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            hosted_error("internal", &e.to_string()),
        )
    })?;
    let npub = public_key.to_bech32().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            hosted_error("internal", &e.to_string()),
        )
    })?;
    Ok(Json(json!({
        "identity": { "npub": npub, "pubkey_hex": npub_hex },
    })))
}

#[derive(Deserialize)]
struct ChallengeBody {
    origin: String,
}

async fn identity_challenge(
    State(state): State<Arc<HostedState>>,
    headers: HeaderMap,
    Json(body): Json<ChallengeBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let (_, session) = require_session(&state, &headers)?;
    let challenge_id = uuid::Uuid::new_v4().to_string();
    let challenge = Challenge {
        nonce: base64url_nonce(),
        verification_code: six_digit_code(),
        origin: body.origin,
        expires_at: Utc::now() + Duration::minutes(CHALLENGE_TTL_MINUTES),
        sso_sub: session.sub,
    };
    let response = json!({
        "challenge_id": challenge_id,
        "nonce": challenge.nonce,
        "verification_code": challenge.verification_code,
        "origin": challenge.origin,
        "expires_at": challenge.expires_at.to_rfc3339(),
    });
    let mut challenges = match state.challenges.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    challenges.retain(|_, c| c.expires_at > Utc::now());
    challenges.insert(challenge_id, challenge);
    Ok(Json(response))
}

#[derive(Deserialize)]
struct VerifyBody {
    challenge_id: String,
    nonce: String,
    signed_payload: String,
}

fn event_tag<'a>(event: &'a nostr::Event, name: &str) -> Option<&'a str> {
    event.tags.iter().find_map(|tag| {
        let slice = tag.as_slice();
        match slice {
            [key, value, ..] if key == name => Some(value.as_str()),
            _ => None,
        }
    })
}

async fn identity_verify(
    State(state): State<Arc<HostedState>>,
    headers: HeaderMap,
    Json(body): Json<VerifyBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let (_, session) = require_session(&state, &headers)?;
    let challenge = {
        let mut challenges = match state.challenges.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        challenges.remove(&body.challenge_id)
    }
    .filter(|c| c.expires_at > Utc::now() && c.sso_sub == session.sub && c.nonce == body.nonce)
    .ok_or_else(|| {
        (
            StatusCode::OK,
            hosted_error("invalid_challenge", "Challenge expired or unknown."),
        )
    })?;

    let event = nostr::Event::from_json(&body.signed_payload).map_err(|e| {
        (
            StatusCode::OK,
            hosted_error("invalid_payload", &format!("bad event: {e}")),
        )
    })?;
    if !event.verify_id() || !event.verify_signature() {
        return Err((
            StatusCode::OK,
            hosted_error("invalid_payload", "bad event id or signature"),
        ));
    }

    let expiry_matches = event_tag(&event, "expires_at")
        .and_then(|v| DateTime::parse_from_rfc3339(v).ok())
        .map(|d| d.with_timezone(&Utc) == challenge.expires_at)
        .unwrap_or(false);
    let fields_ok = event.kind.as_u16() == KIND_NOSTR_IDENTITY_BINDING
        && event.content.is_empty()
        && event_tag(&event, "challenge_id") == Some(body.challenge_id.as_str())
        && event_tag(&event, "nonce") == Some(challenge.nonce.as_str())
        && event_tag(&event, "verification_code") == Some(challenge.verification_code.as_str())
        && event_tag(&event, "audience") == Some("buzz:nostr-identity")
        && event_tag(&event, "action") == Some("bind_nostr_identity")
        && event_tag(&event, "protocol") == Some("buzz-nostr-identity")
        && event_tag(&event, "version") == Some("1")
        && event_tag(&event, "origin") == Some(challenge.origin.as_str())
        && expiry_matches;
    if !fields_ok {
        return Err((
            StatusCode::OK,
            hosted_error(
                "invalid_payload",
                "Binding event does not match the challenge.",
            ),
        ));
    }

    let npub_hex = event.pubkey.to_hex();
    if let Some(other_sub) = state.bindings.sub_for_npub(&npub_hex) {
        if other_sub != session.sub {
            return Err((
                StatusCode::OK,
                hosted_error(
                    "pubkey_already_bound",
                    "This Buzz identity is connected to another account.",
                ),
            ));
        }
    }
    if let Some(old_npub) = state.bindings.npub_for(&session.sub) {
        if old_npub != npub_hex {
            return Err((
                StatusCode::OK,
                hosted_error(
                    "identity_already_bound",
                    "This account is connected to another Buzz identity.",
                ),
            ));
        }
    }

    state
        .bindings
        .bind(&session.sub, &npub_hex, &session.name)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                hosted_error("internal", &e.to_string()),
            )
        })?;
    state.audit.log(
        &npub_hex,
        "hosted.bind.ok",
        json!({ "sso_sub": session.sub, "sso_name": session.name }),
    );
    identity_json(&npub_hex)
}

async fn identity_delete(
    State(state): State<Arc<HostedState>>,
    headers: HeaderMap,
    Json(_body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let (_, session) = require_session(&state, &headers)?;
    state.bindings.unbind_sub(&session.sub).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            hosted_error("internal", &e.to_string()),
        )
    })?;
    state.audit.log(&session.sub, "hosted.unbind.ok", json!({}));
    Ok(Json(json!({})))
}

// ---------------------------------------------------------------------------
// Communities (mapped onto the operator API with the bound npub as owner).
// ---------------------------------------------------------------------------

fn valid_hosted_name(name: &str) -> bool {
    // ^[a-z0-9]+(?:-[a-z0-9]+)*$ — same rule as the desktop frontend.
    // Infra-shadowing names (api/sso/...) are rejected too.
    !crate::serve::RESERVED_NAMES.contains(&name)
        && !name.is_empty()
        && name.len() <= 32
        && name.split('-').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
}

async fn operator_list_owned(
    state: &HostedState,
    npub_hex: &str,
) -> Result<Vec<Value>, (StatusCode, Json<Value>)> {
    let url = format!(
        "{}/operator/communities?owner_pubkey={npub_hex}",
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
        (
            StatusCode::OK,
            hosted_error("relay_unavailable", &format!("relay: {e}")),
        )
    })?;
    if !status.is_success() {
        return Err((
            StatusCode::OK,
            hosted_error("relay_unavailable", &format!("relay HTTP {status}")),
        ));
    }
    let value: Value = serde_json::from_str(&text).map_err(|_| {
        (
            StatusCode::OK,
            hosted_error("relay_unavailable", "bad relay response"),
        )
    })?;
    Ok(value
        .get("communities")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default())
}

fn to_hosted_community(state: &HostedState, entry: &Value, owner_pubkey: &str) -> Value {
    let host = entry
        .get("host")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let name = host
        .strip_suffix(state.host_suffix.as_str())
        .unwrap_or(host)
        .to_string();
    json!({
        "id": entry.get("community_id"),
        "name": name,
        "slug": name,
        "normalized_host": host,
        "owner_pubkey": entry.get("owner_pubkey").cloned().unwrap_or_else(|| json!(owner_pubkey)),
        "archived_at": entry.get("archived_at"),
    })
}

async fn communities_list(
    State(state): State<Arc<HostedState>>,
    headers: HeaderMap,
    Json(_body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let (_, session) = require_session(&state, &headers)?;
    let npub_hex = require_bound_npub(&state, &session)?;
    let entries = operator_list_owned(&state, &npub_hex).await?;
    let communities: Vec<Value> = entries
        .iter()
        .map(|entry| to_hosted_community(&state, entry, &npub_hex))
        .collect();
    Ok(Json(json!({ "communities": communities })))
}

#[derive(Deserialize)]
struct NameBody {
    name: String,
}

async fn communities_availability(
    State(state): State<Arc<HostedState>>,
    headers: HeaderMap,
    Json(body): Json<NameBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_session(&state, &headers)?;
    if !valid_hosted_name(&body.name) {
        return Ok(hosted_error(
            "invalid_name",
            "Use lowercase letters, numbers, and hyphens.",
        ));
    }
    let host = format!("{}{}", body.name, state.host_suffix);
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
        (
            StatusCode::OK,
            hosted_error("relay_unavailable", &format!("relay: {e}")),
        )
    })?;
    if !status.is_success() {
        return Ok(hosted_error(
            "relay_unavailable",
            "availability check failed",
        ));
    }
    let value: Value = serde_json::from_str(&text).map_err(|_| {
        (
            StatusCode::OK,
            hosted_error("relay_unavailable", "bad relay response"),
        )
    })?;
    let available = value
        .get("available")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if available {
        Ok(Json(json!({ "available": true, "normalized_host": host })))
    } else {
        Ok(Json(json!({
            "available": false,
            "normalized_host": host,
            "error": { "code": "taken", "message": "That Buzz address is already taken." },
        })))
    }
}

async fn communities_create(
    State(state): State<Arc<HostedState>>,
    headers: HeaderMap,
    Json(body): Json<NameBody>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let (_, session) = require_session(&state, &headers)?;
    let npub_hex = require_bound_npub(&state, &session)?;
    if !valid_hosted_name(&body.name) {
        return Ok(hosted_error(
            "invalid_name",
            "Use lowercase letters, numbers, and hyphens.",
        ));
    }

    // Enforce the hosted limit (5 active communities, same as Builderlab).
    let existing = operator_list_owned(&state, &npub_hex).await?;
    let active = existing
        .iter()
        .filter(|e| e.get("archived_at").is_none_or(Value::is_null))
        .count();
    if active >= HOSTED_COMMUNITY_LIMIT {
        return Ok(hosted_error(
            "limit_reached",
            "You've reached the limit of hosted communities.",
        ));
    }

    let host = format!("{}{}", body.name, state.host_suffix);
    let payload = serde_json::to_vec(&json!({
        "host": host,
        "initial_owner_pubkey": npub_hex,
        "create_only": true,
    }))
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            hosted_error("internal", &e.to_string()),
        )
    })?;
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
        (
            StatusCode::OK,
            hosted_error("relay_unavailable", &format!("relay: {e}")),
        )
    })?;
    let value: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({}));
    if status == reqwest::StatusCode::CONFLICT {
        return Ok(hosted_error("taken", "That Buzz address is already taken."));
    }
    if !status.is_success() {
        return Ok(hosted_error("relay_unavailable", "provisioning failed"));
    }

    state.audit.log(
        &npub_hex,
        "hosted.community.create.ok",
        json!({ "host": host, "community_id": value.get("community_id") }),
    );
    let community = to_hosted_community(&state, &value, &npub_hex);
    Ok(Json(json!({ "community": community })))
}

/// Resolve (community_id -> host) within the caller's owned communities.
async fn resolve_owned_host(
    state: &HostedState,
    npub_hex: &str,
    community_id: &str,
) -> Result<String, (StatusCode, Json<Value>)> {
    let entries = operator_list_owned(state, npub_hex).await?;
    entries
        .iter()
        .find(|e| e.get("community_id").and_then(Value::as_str) == Some(community_id))
        .and_then(|e| e.get("host").and_then(Value::as_str))
        .map(str::to_string)
        .ok_or_else(|| {
            (
                StatusCode::OK,
                hosted_error("not_owner", "Only the community owner can do that."),
            )
        })
}

async fn archive_like(
    state: &HostedState,
    headers: &HeaderMap,
    body: &Value,
    verb: &str,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let (_, session) = require_session(state, headers)?;
    let npub_hex = require_bound_npub(state, &session)?;
    let community_id = body
        .get("community_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                hosted_error("invalid_request", "community_id required"),
            )
        })?;
    let host = resolve_owned_host(state, &npub_hex, community_id).await?;
    let payload =
        serde_json::to_vec(&json!({ "host": host, "owner_pubkey": npub_hex })).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                hosted_error("internal", &e.to_string()),
            )
        })?;
    let url = format!("{}/operator/communities/{verb}", state.relay_origin);
    let (status, text) = nostr_http(
        &state.http,
        &state.operator_keys,
        nostr::nips::nip98::HttpMethod::POST,
        &url,
        Some(&payload),
    )
    .await
    .map_err(|e| {
        (
            StatusCode::OK,
            hosted_error("relay_unavailable", &format!("relay: {e}")),
        )
    })?;
    if !status.is_success() {
        let value: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({}));
        let msg = value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("failed");
        return Ok(hosted_error("relay_unavailable", msg));
    }
    state.audit.log(
        &npub_hex,
        &format!("hosted.community.{verb}.ok"),
        json!({ "host": host }),
    );
    let value: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({}));
    let community = to_hosted_community(state, &value, &npub_hex);
    Ok(Json(json!({ "community": community })))
}

async fn communities_archive(
    State(state): State<Arc<HostedState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    archive_like(&state, &headers, &body, "archive").await
}

async fn communities_unarchive(
    State(state): State<Arc<HostedState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    archive_like(&state, &headers, &body, "unarchive").await
}

async fn communities_transfer(
    State(state): State<Arc<HostedState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let (_, session) = require_session(&state, &headers)?;
    let npub_hex = require_bound_npub(&state, &session)?;
    let community_id = body
        .get("communityId")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                hosted_error("invalid_request", "communityId required"),
            )
        })?;
    let transferee_npub = body
        .get("transfereeNpub")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                hosted_error("invalid_request", "transfereeNpub required"),
            )
        })?;
    let transferee_hex = PublicKey::from_bech32(transferee_npub)
        .map(|k| k.to_hex())
        .map_err(|_| {
            (
                StatusCode::OK,
                hosted_error("invalid_request", "transfereeNpub must be an npub"),
            )
        })?;
    if state.bindings.sub_for_npub(&transferee_hex).is_none() {
        return Ok(hosted_error(
            "transferee_not_registered",
            "That person needs a connected Buzz identity first.",
        ));
    }
    // Caller must currently own it (resolve also yields the expected owner).
    resolve_owned_host(&state, &npub_hex, community_id).await?;
    let payload = serde_json::to_vec(&json!({
        "community_id": community_id,
        "new_owner_pubkey": transferee_hex,
        "expected_owner_pubkey": npub_hex,
    }))
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            hosted_error("internal", &e.to_string()),
        )
    })?;
    let url = format!("{}/operator/communities/transfer", state.relay_origin);
    let (status, text) = nostr_http(
        &state.http,
        &state.operator_keys,
        nostr::nips::nip98::HttpMethod::POST,
        &url,
        Some(&payload),
    )
    .await
    .map_err(|e| {
        (
            StatusCode::OK,
            hosted_error("relay_unavailable", &format!("relay: {e}")),
        )
    })?;
    if status == reqwest::StatusCode::CONFLICT {
        return Ok(hosted_error(
            "not_owner",
            "Only the community owner can do that.",
        ));
    }
    if !status.is_success() {
        return Ok(hosted_error("relay_unavailable", "transfer failed"));
    }
    state.audit.log(
        &npub_hex,
        "hosted.community.transfer.ok",
        json!({ "community_id": community_id, "to": transferee_hex }),
    );
    let value: Value = serde_json::from_str(&text).unwrap_or_else(|_| json!({}));
    let community = to_hosted_community(&state, &value, &transferee_hex);
    Ok(Json(json!({ "community": community })))
}

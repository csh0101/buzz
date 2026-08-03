# buzz-control-plane

Self-hosted **control plane** prototype for the Buzz relay — the missing piece
between "running the OSS relay" and "onboarding communities for end users",
as described in `docs/nostr-in-buzz.zh-CN.md`.

The relay ships the server side of community provisioning
(`POST/GET /operator/communities*`, NIP-98-authenticated against the
deployment's `RELAY_OPERATOR_PUBKEYS`). This crate is the **caller** for that
surface: it holds the operator secret key and signs every request.

```
账号系统(你的实现)  -->  buzz-control-plane  --NIP-98-->  Relay /operator/communities
                            (持有 Operator 私钥)
```

## Concepts

- **Operator key** — a Nostr keypair whose *hex pubkey* is listed in the
  relay's `RELAY_OPERATOR_PUBKEYS`. It spans tenants and can create/archive/
  transfer communities. The secret never leaves the control plane.
- **Owner pubkey** — an *end user's* Nostr key. Provisioning bootstraps them
  as the community `owner` (a `relay_members` role within that tenant).
- **NIP-98 binding** — each request signs a kind:27235 event whose `u` tag is
  `{RELAY_OPERATOR_API_ORIGIN}{path}{?query}` (byte-exact, including the raw
  query string) and whose `payload` tag is the SHA-256 of the body. The relay
  verifies the signature, a ±60s `created_at` window, and replay-guards the
  event ID in Redis.

## Usage

```bash
# 1. Generate the operator keypair (once). Put the hex pubkey in the relay's
#    RELAY_OPERATOR_PUBKEYS and set RELAY_OPERATOR_API_ORIGIN on the relay.
buzz-control-plane keygen

# 2. Point the CLI at the relay (origin must byte-match RELAY_OPERATOR_API_ORIGIN)
export BUZZ_OPERATOR_ORIGIN=http://localhost:3000
export BUZZ_OPERATOR_KEY=nsec1...   # operator secret key

# 3. Provision a community for an end user
buzz-control-plane availability --host acme.example.com
buzz-control-plane provision --host acme.example.com --owner-pubkey <user-hex> --create-only

# 4. Operate it
buzz-control-plane list --owner-pubkey <user-hex>
buzz-control-plane transfer --community-id <uuid> \
    --new-owner-pubkey <hex> --expected-owner-pubkey <old-hex>
buzz-control-plane archive   --host acme.example.com --owner-pubkey <hex>
buzz-control-plane unarchive --host acme.example.com --owner-pubkey <hex>
```

Exit code is 0 on 2xx, non-zero otherwise (the HTTP status and body are
always printed).

### Notes on server semantics (verified against the relay)

- `provision` without `--create-only` is *convergence mode* and can rotate an
  existing owner — always use `--create-only` when provisioning on behalf of
  end users.
- `--create-only` is idempotent for the **same** owner (retry-safe, returns
  `created` again); it returns `409 community already exists` only when the
  host is owned by someone else.
- `transfer` is guarded by `--expected-owner-pubkey` (last-writer-wins
  protection), and ownership is limited per owner pubkey server-side.

## Relay-side configuration

```bash
RELAY_OPERATOR_PUBKEYS=<hex pubkey from keygen>   # comma-separated allowlist
RELAY_OPERATOR_API_ORIGIN=http://localhost:3000   # required when pubkeys set
```

Empty `RELAY_OPERATOR_PUBKEYS` disables provisioning entirely (fail closed).

## Local multi-tenant demo (no sudo required)

A working two-tenant setup on one relay process lives in
`examples/multitenant_demo.rs`:

- a Caddy reverse proxy listens on `:8088` and rewrites the request `Host`
  header to the community row (`acme.example`), forwarding to the relay on
  `:3000` — this is what a production ingress does per community domain;
- the demo resolves `acme.example` **per-process** via reqwest's
  `ClientBuilder::resolve()`, so macOS needs no `/etc/hosts`, no
  `/etc/resolver`, and no sudo;
- it then creates a channel (kind 9007), posts a message (kind 9), and shows
  both isolation directions: `localhost:3000` cannot see acme's events and
  vice versa.

```bash
cargo run -p buzz-control-plane --example multitenant_demo
```

To point the **desktop app** (which uses the system resolver) at a named
community, macOS requires one privileged write you must approve yourself
(GUI password prompt, nothing is typed into a terminal):

```bash
osascript -e 'do shell script "grep -q acme.example /etc/hosts || echo 127.0.0.1 acme.example >> /etc/hosts" with administrator privileges'
# then in the desktop app: add community  ws://acme.example:8088
```

## Self-serve provisioning service (`serve`)

`buzz-control-plane serve` turns the CLI into the always-on control plane a
deployment exposes to its users. Callers authenticate with **their own**
Nostr key (NIP-98 against this service's origin); the service re-signs with
the operator key and pins the caller as owner (`create_only`, so names can
never be taken over). No account system required — the key is the identity.

```bash
buzz-control-plane serve \
  --origin http://localhost:3000          \  # relay operator API
  --public-origin http://localhost:8900   \  # this service, as users reach it
  --host-suffix .chat.company.com         \  # covered by wildcard DNS + cert
  --listen 0.0.0.0:8900
```

Endpoints:

- `POST /communities` — NIP-98 (user key), body `{"name": "design"}` →
  creates `design.chat.company.com` with the caller as owner. 409 on name
  conflict, 401 without a valid user signature.
- `GET /communities/availability?name=design` — name check (operator-signed
  upstream).
- `GET /healthz` — liveness.

Demo (plays an employee end-to-end, incl. squatter + unsigned negatives):

```bash
cargo run -p buzz-control-plane --example self_serve_demo
```

### Hardening (implemented)

- **Replay cache** — every user NIP-98 event id is remembered for 120s;
  reusing a captured `Authorization` header returns `401 replay detected`.
- **Rate limiting** — per-user sliding windows: 60 authenticated requests/min
  and `--rate-create-max` community creates/hour (429 beyond).
- **Hash-chained audit log** — `<data-dir>/audit.jsonl`, every entry carries
  the previous entry's SHA-256 (same pattern as the relay's `buzz-audit`).
  Binds, creates, and rejections (SSO gate, replay, rate limit) are all
  recorded.
- **Operator key from a secret store** — `--key-source env:VAR | file:/path |
  cmd:<command...>`. Nostr keys are secp256k1 which cloud KMS cannot sign,
  so the correct pattern is fetching key material from a secret backend at
  startup (macOS Keychain: `cmd:security find-generic-password -s NAME -w`,
  Vault: `cmd:vault kv get -field=nsec secret/buzz/operator`, AWS Secrets
  Manager, …). Nothing plaintext on disk or in env dumps.
- **Builderlab-compatible hosted API** — `src/hosted.rs` implements the
  `/api/goose/v1/*` contract the desktop's "Create a new community" flow
  speaks (`desktop/src-tauri/src/builderlab.rs`), backed by Casdoor SSO:
  browser login (`/auth/login` → Casdoor → `/auth/casdoor/callback` →
  `/auth/login/exchange`), `X-BB-Session-Credential` sessions, the
  challenge/verify npub binding (signed kind:24243 event), and
  list/availability/create/archive/unarchive/transfer mapped onto the
  operator API. Point the desktop at it with `BUZZ_HOSTED_API_BASE_URL`
  (e.g. `http://localhost:8900/api/goose` in `.env`). E2E proof:
  `cargo run -p buzz-control-plane --example hosted_flow_demo <name>`
  (drive the browser leg once to capture the exchange code, then run the
  example with `EXCHANGE_CODE=...`).
- **Casdoor SSO gate** — `--require-sso` demands the caller's npub is bound
  to a company SSO identity before provisioning (the Builderlab role in the
  hosted deployment):
  - `GET /auth/casdoor/login` — browser redirect into Casdoor OIDC
  - `GET /auth/casdoor/callback` — code exchange + RS256 JWT verification
    against Casdoor's JWKS (iss/aud/exp enforced)
  - `POST /bindings` — NIP-98 (user key) + `{"casdoor_token": "..."}` binds
    the caller's npub to the SSO subject; persisted in
    `<data-dir>/bindings.jsonl`

### Casdoor local setup (docker-compose stack's Postgres)

```bash
podman run -d --name casdoor -p 8000:8000 \
  -e driverName=postgres \
  -e "dataSourceName=user=buzz password=buzz_dev dbname=casdoor sslmode=disable host=host.containers.internal port=5432" \
  -e dbName=casdoor docker.io/casbin/casdoor:latest
```

Then via the admin API (admin/123 at http://localhost:8000): create
organization `buzz`, application `buzz-control-plane` (redirect URI
`http://localhost:8900/auth/casdoor/callback`, grant types
`authorization_code` + `password`, cert `cert-built-in`), and users. Full
demo:

```bash
CASDOOR_CLIENT_ID=... CASDOOR_CLIENT_SECRET=... \
  cargo run -p buzz-control-plane --example sso_demo
```

## What this prototype deliberately does not do

This is the signing/transport half of a control plane. A production
deployment still needs, in front of or beside it:

- an account system (email/OIDC) with **signed-challenge npub binding** —
  ask the user to sign a challenge event with their Nostr key, verify it
  against their claimed pubkey, store the account ↔ npub mapping;
- secret management for the operator key (KMS/HSM instead of env vars);
- DNS/ingress that routes each community host to the relay (the relay
  resolves `community_id` from the request Host header);
- audit logging of operator actions.

#!/bin/bash
# Buzz Casdoor 初始化（幂等）——在 k3s-root 上、compose 栈起来之后运行。
# 通过 Caddy 公网入口调用 Casdoor API，完成：改管理员密码、建组织 buzz、
# 建应用 buzz-control-plane（授权码+密码模式）、建初始用户 alice，
# 并把 client-id/secret 写入 deploy/control-plane.env。
set -euo pipefail

SSO="https://sso.robogo-fat2.d-robotics.cc"
DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$(mktemp)"
ENV_FILE="$DEPLOY_DIR/.env"
ADMIN_PW_FILE="$DEPLOY_DIR/secrets/casdoor-admin-password"

api() { # api <path> <json-body>
  curl -sf -b "$JAR" -c "$JAR" -X POST "$SSO$1" \
    -H 'Content-Type: application/json' -d "$2"
}

# 1. 用（新）密码登录
ADMIN_PW="$(cat "$ADMIN_PW_FILE" 2>/dev/null || echo 123)"
rm -f "$JAR"; JAR="$(mktemp)"
curl -sf -c "$JAR" -X POST "$SSO/api/login" -H 'Content-Type: application/json' \
  -d "{\"organization\":\"built-in\",\"username\":\"admin\",\"password\":\"$ADMIN_PW\",\"type\":\"login\",\"application\":\"app-built-in\"}" \
  | grep -q '"status":"ok"' || { echo "!! casdoor admin 登录失败"; exit 1; }
echo "== admin 登录 OK"

# 2. 组织 buzz
api /api/add-organization '{"owner":"admin","name":"buzz","displayName":"Buzz","websiteUrl":"https://robogo-fat2.d-robotics.cc","passwordType":"plain","favicon":"","passwordObfuscatorType":"Plain"}' \
  >/dev/null && echo "== org buzz 已建" || echo "== org buzz 已存在（跳过）"

# 3. 应用 buzz-control-plane（含生产回调地址）
CALLBACK="https://api.robogo-fat2.d-robotics.cc/api/goose/v1/auth/casdoor/callback"
api /api/add-application "{\"owner\":\"admin\",\"name\":\"buzz-control-plane\",\"displayName\":\"Buzz Control Plane\",\"organization\":\"buzz\",\"homepageUrl\":\"https://robogo-fat2.d-robotics.cc\",\"redirectUris\":[\"$CALLBACK\"],\"grantTypes\":[\"authorization_code\",\"password\"],\"cert\":\"cert-built-in\",\"enablePassword\":true,\"enableSignUp\":false,\"enableSigninSession\":true}" \
  >/dev/null && echo "== app buzz-control-plane 已建" || echo "== app 已存在（将校正 redirectUris）"

# 幂等校正 redirectUris（已有应用可能缺回调）
APP_JSON=$(curl -sf -b "$JAR" "$SSO/api/get-application?id=admin/buzz-control-plane")
echo "$APP_JSON" | grep -q "$CALLBACK" || {
  NEW_APP=$(echo "$APP_JSON" | python3 -c "
import sys,json
d=json.load(sys.stdin); app=d['data'] if 'data' in d and d['data'] else d
uris=app.get('redirectUris') or []
if '$CALLBACK' not in uris: uris.append('$CALLBACK')
app['redirectUris']=uris
print(json.dumps(app))")
  curl -sf -b "$JAR" -X POST "$SSO/api/update-application?id=admin/buzz-control-plane" \
    -H 'Content-Type: application/json' -d "$NEW_APP" >/dev/null
  echo "== redirectUris 已校正"
}

# 4. 初始用户 alice / alice123（演示账号；正式用户在 $SSO 后台添加）
api /api/add-user '{"owner":"buzz","name":"alice","displayName":"Alice","password":"alice123","email":"alice@example.com","type":"normal-user"}' \
  >/dev/null && echo "== 用户 alice/alice123 已建" || echo "== 用户 alice 已存在（跳过）"

# 5. 输出 client-id/secret 到 control-plane.env
CLIENT_ID=$(echo "$APP_JSON" | python3 -c "import sys,json;d=json.load(sys.stdin);a=d.get('data') or d;print(a['clientId'])")
CLIENT_SECRET=$(echo "$APP_JSON" | python3 -c "import sys,json;d=json.load(sys.stdin);a=d.get('data') or d;print(a['clientSecret'])")
touch "$ENV_FILE"
sed -i '/^CASDOOR_CLIENT_ID=/d;/^CASDOOR_CLIENT_SECRET=/d' "$ENV_FILE"
cat >> "$ENV_FILE" <<EOF
CASDOOR_CLIENT_ID=$CLIENT_ID
CASDOOR_CLIENT_SECRET=$CLIENT_SECRET
EOF
chmod 600 "$ENV_FILE"
echo "== control-plane.env 已写入（client_id=$CLIENT_ID）"
echo "== Casdoor 初始化完成"

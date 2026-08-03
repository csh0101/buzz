# Buzz 生产部署（k3s-root / 114.111.19.49）

全套 Buzz 二开栈：relay（官方镜像）+ control-plane（本仓库 `crates/buzz-control-plane`）
+ Casdoor SSO + Postgres + Redis + MinIO，Caddy 持泛域名证书统一入口。

## 架构

```
互联网
  │  *.robogo-fat2.d-robotics.cc
  ▼
[你的 LB] ──TCP 透传──► k3s-root:80/443 (Caddy)
                            ├─ sso.* → casdoor:8000
                            ├─ api.* → control-plane:8900
                            └─ <社区名>.* → relay:3000（Host 分租户）
```

## 你要配的（就两件事）

### 1. LB 规则

| 监听 | 后端 | 说明 |
|---|---|---|
| TCP 443 | 114.111.19.49:443 | **TCP 透传（不要终结 TLS）**，证书在 Caddy 上 |
| TCP 80 | 114.111.19.49:80 | 仅用于 HTTP→HTTPS 跳转 |
| 健康检查 | TCP 443 或 HTTPS `https://api.robogo-fat2.d-robotics.cc/healthz` | 后者返回 200 |

### 2. DNS 解析（最后要补的）

```
*.robogo-fat2.d-robotics.cc   A   <LB 的 VIP>
```

当前泛解析直接指向 114.111.19.49（调试期可用）；LB 就绪后把这条记录改成 LB 地址即可，
服务器侧零改动。apex（robogo-fat2.d-robotics.cc 本身）可选加一条，社区都在子域下，非必需。

## 文件清单

| 文件 | 用途 |
|---|---|
| `docker-compose.yml` | 全栈定义（唯一宿主端口 80/443） |
| `Caddyfile` | TLS 终结 + 三级路由 |
| `certs/fullchain.pem` / `certs/privkey.pem` | TrustAsia 泛域名证书 |
| `secrets/operator-key` | relay operator nsec（0600，control-plane 用它签 operator API） |
| `secrets/casdoor-admin-password` | Casdoor admin 密码（初始化时生成） |
| `relay.env` | relay 配置（DB/Redis/S3/operator 公钥） |
| `control-plane.env` | Casdoor client-id/secret（由 setup-casdoor.sh 生成） |
| `.env` | compose 变量（PG_PASSWORD / MINIO_ROOT_PASSWORD） |
| `casdoor/app.conf` | Casdoor 配置（postgres 数据源） |
| `postgres-init/01-casdoor.sql` | 建 casdoor 库 |
| `setup-casdoor.sh` | Casdoor 幂等初始化（栈起后跑一次） |

## 首次部署步骤（已全部脚本化，此处仅存档）

```bash
# 1. 源码同步到服务器（control-plane 需在服务器上构建）
rsync -a --delete --exclude target --exclude node_modules --exclude .git \
  /Users/d-robotics/lab/buzz/ k3s-root:/opt/buzz/src/

# 2. 构建 control-plane 镜像（repo 根为构建上下文）
ssh k3s-root 'cd /opt/buzz/src && docker build -f deploy/Dockerfile.control-plane -t buzz-control-plane:local .'

# 3. 生成 operator 密钥对，写 relay.env / secrets/operator-key / .env

# 4. 起栈
ssh k3s-root 'cd /opt/buzz/src/deploy && docker compose up -d'

# 5. Casdoor 初始化
ssh k3s-root 'cd /opt/buzz/src/deploy && bash setup-casdoor.sh && docker compose up -d'
```

## 日常使用

- 桌面 App：默认 hosted API 已指向 `https://api.robogo-fat2.d-robotics.cc/api/goose`
  （`desktop/src-tauri/src/builderlab.rs`；本地开发用 `.env` 的 `BUZZ_HOSTED_API_BASE_URL` 覆盖）
- 用户流程：Create a new community → 浏览器 Casdoor 登录 → 起名 → 自动连上
- 加用户：`https://sso.robogo-fat2.d-robotics.cc` 后台（admin / 见 secrets/casdoor-admin-password），
  在 buzz 组织下加人；用户首次在 App 里登录后自动完成 npub 绑定
- 审计：control-plane 容器卷 `cp-data` 里的 `audit.jsonl`（哈希链）

## 运维速查

```bash
ssh k3s-root 'cd /opt/buzz/src/deploy && docker compose ps'
ssh k3s-root 'cd /opt/buzz/src/deploy && docker compose logs -f relay'
# 证书 2027-02-04 到期：替换 certs/ 两个文件后 `docker compose restart caddy`
```

# CheckPoint 服务端安装与运维手册（v1.3.0）

> 适用：生产/测试环境的部署、升级、备份、监控与故障处理
> 组件：FastAPI + SQLite（WAL）+ Docker（非 root / 只读根文件系统）+ TLS

---

## 1. 环境要求

| 项目 | 要求 |
|------|------|
| 主机 | Linux（已在 Kali Rolling / VM 8C 验证）或任意可运行 Docker 的 Linux |
| Docker | ≥ 24（本机 28.5.2），Docker Compose ≥ 2.20（本机 2.40.3） |
| 网络 | 客户端可访问服务端口（默认 8080/TCP，HTTPS） |
| 磁盘 | ≥ 1GB（镜像约 200MB；数据/备份按量） |
| 依赖 | 仅镜像内 pip 依赖（fastapi/uvicorn/pydantic/bcrypt/cryptography，版本已在 requirements.txt 锁定） |

**本机参考路径**：部署目录 `/opt/checkpoint`，VM IP `checkpoint.example.com`。

---

## 2. 目录结构

```
checkpoint/
├── docker-compose.yml            # 生产（TLS，仅监听 127.0.0.1:8080 或按需发布）
├── docker-compose.override.yml   # 内网联调覆盖（发布 8080 到内网；生产删除）
├── docker-compose.test.yml       # 隔离测试容器（临时 DB）
├── docker-compose.test-hi.yml    # 高限流测试实例（fuzz/负载）
├── Dockerfile                    # 基础镜像 digest 已锁定
├── entrypoint.sh                 # 证书检测 + 安全启动参数
├── main.py                       # 服务端
├── test_api.py                   # 全量测试套件（9 阶段）
├── scripts/                      # 容器内脚本（备份/fuzz/负载/走私探测）
├── ops/                          # 主机侧脚本（测试轮次/备份/巡检/证书轮换）
├── certs/                        # TLS 证书（cert.pem 644 / key.pem 600）
├── data/                         # SQLite + WAL + audit.jsonl + backups/
│   └── backups/                  # checkpoint-*.db.gz（保留 14 份）
└── .env                          # ADMIN_KEY / SIGN_PRIVATE_KEY / 开关（600）
```

---

## 3. 首次安装

```bash
# 1) 准备目录
mkdir -p /opt/checkpoint/{certs,data}
cd /opt/checkpoint

# 2) 放置文件：main.py test_api.py requirements.txt Dockerfile entrypoint.sh
#    docker-compose*.yml scripts/ ops/（从仓库复制）
chmod +x entrypoint.sh ops/*.sh

# 3) 生成 .env（两个密钥都必须强随机，勿复用）
python3 - <<'EOF'
import base64, os, secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
key = ec.generate_private_key(ec.SECP256R1())
der = key.private_bytes(serialization.Encoding.DER,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption())
with open("/opt/checkpoint/.env", "w") as f:
    f.write("ADMIN_KEY=ckpt-" + secrets.token_urlsafe(36) + "\n")
    f.write("SIGN_PRIVATE_KEY=" + base64.b64encode(der).decode() + "\n")
    f.write("TRUST_PROXY=0\nTOKEN_TTL_DAYS=30\nREBIND_GRACE_HOURS=24\n")
os.chmod("/opt/checkpoint/.env", 0o600)
EOF

# 4) 生成 TLS 证书（10 年，SAN 含部署 IP）
./ops/rotate-cert.sh checkpoint.example.com   # 首次执行即生成；会打印新指纹
#    记下 NEW_CERT_SHA256 —— 需写入客户端 DefaultCertPin 或配置 cert_sha256

# 5) 数据目录属主（容器以 UID 10001 运行）
sudo chown -R 10001:10001 data certs
chmod 600 certs/key.pem

# 6) 启动
sudo docker compose up -d --build
curl -k https://127.0.0.1:8080/health

# 7) 验证
sudo docker compose exec -T -e BASE_URL=https://127.0.0.1:8000 \
  checkpoint-auth python test_api.py rebind   # 快速冒烟（23 项）
```

> 提示：部署用户加入 docker 组后（`sudo usermod -aG docker <部署用户>`）可免 sudo 操作容器。
> 加入 docker 组等价 root 权限，仅限受控主机。

---

## 4. 环境变量参考（.env / compose environment）

| 变量 | 默认 | 说明 |
|------|------|------|
| `ADMIN_KEY` | 必填 | 管理员密钥；缺失时 admin 接口 403 |
| `SIGN_PRIVATE_KEY` | 建议必填 | 响应签名私钥（PKCS#8 DER base64）；缺失则响应不签名，新版客户端拒绝成功响应 |
| `DB_PATH` | /data/checkpoint.db | SQLite 路径 |
| `TOKEN_TTL_DAYS` | 30 | token 滑动有效期（1-3650） |
| `TRUST_PROXY` | 0 | 1=采信反代追加的 X-Forwarded-For **最右侧**地址（仅反代后开启） |
| `REGISTER_ENABLED` | 1 | 0=关闭开放注册 |
| `ADMIN_ALLOW_IPS` | 空 | 管理员接口 IP 白名单（逗号分隔；生产建议配置） |
| `MIN_CLIENT_VERSION` | 空 | 最低客户端版本（如 `1.3.0`），低于则 426 |
| `REBIND_GRACE_HOURS` | 24 | 首次绑定后允许改绑的宽限小时数；0=禁止改绑 |
| `AUDIT_LOG_PATH` | DB 同目录 audit.jsonl | 审计日志路径（JSONL，20MB 轮转一代） |
| `RATE_IP_LIMIT` | 30 | 同 IP 每分钟请求数（测试/负载专用，生产保持默认） |
| `RATE_ACTIVATE_LIMIT` | 10 | 同 machine_code 每分钟激活尝试 |
| `RATE_LOGIN_FAIL_LIMIT` | 8 | 同用户名+IP 每分钟登录失败数 |

---

## 5. 生产网络接入（推荐拓扑）

```
客户端 ──HTTPS(443)──> Nginx/Caddy(终结 TLS 或透传) ──HTTP/HTTPS──> 127.0.0.1:8080 (容器)
```

**Nginx 参考（TLS 终结在反代，容器退回 HTTP）**：

```nginx
server {
    listen 443 ssl;
    server_name checkpoint.example.com;
    ssl_certificate     /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 16k;          # 与容器 413 上限对齐
    client_body_timeout 10s;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # 追加真实 IP
        proxy_set_header Host $host;
        proxy_read_timeout 30s;
        proxy_connect_timeout 5s;
    }
}
```

- 反代后：`TRUST_PROXY=1`；容器不直接对外发布端口（保持 `127.0.0.1:8080:8000`）。
- 若反代也终结 TLS（推荐），请删除 `certs/` 或保留容器 TLS 由反代 `proxy_pass https://`（二选一，不要双重错误配置）。
- 反代**必须覆盖/追加** `X-Forwarded-For`（`$proxy_add_x_forwarded_for` 会追加；客户端伪造值只会出现在左侧，服务端取最右侧）。
- 反代层建议加请求体/头大小限制与连接数限制（与容器 `--limit-concurrency 200` 互补）。

---

## 6. 证书管理

| 动作 | 方法 |
|------|------|
| 首次生成 | `./ops/rotate-cert.sh <IP>`（会自动重启容器并打印指纹） |
| 轮换 | 同上；旧证书备份到 `certs/old/` |
| 客户端更新 | 新指纹写入 `client/Program.cs` 的 `DefaultCertPin` 重新发布；或临时在客户端配置加 `"cert_sha256": "<新指纹>"` |
| 检查指纹 | `openssl x509 -in certs/cert.pem -outform DER \| sha256sum` |

> 更换证书不影响数据库与 token；客户端因指纹锁定会拒绝旧/新不匹配的证书——务必同步发布客户端。

---

## 7. 备份与恢复

### 7.1 自动备份（已配置）

- 容器内 `scripts/backup.py`：SQLite 在线备份（backup API）→ 完整性校验 → gzip → `data/backups/checkpoint-YYYYmmddTHHMMSSZ.db.gz`，保留 14 份。
- root cron：每天 03:15 执行 `ops/backup-cron.sh`（日志 `logs/backup.log`）。
- 手工立即备份：
```bash
docker compose exec -T checkpoint-auth python scripts/backup.py
```

### 7.2 恢复流程（演练已通过）

```bash
# 1) 停服务
sudo docker compose stop

# 2) 解压备份到数据目录（保留原库直到确认成功）
cd data
cp checkpoint.db checkpoint.db.pre-restore-$(date +%s)
gunzip -c backups/checkpoint-XXXX.db.gz > checkpoint.db
chown 10001:10001 checkpoint.db && chmod 600 checkpoint.db
rm -f checkpoint.db-wal checkpoint.db-shm

# 3) 启动并校验
cd .. && sudo docker compose start
curl -k https://127.0.0.1:8080/health
docker compose exec -T checkpoint-auth python -c \
  "import sqlite3;c=sqlite3.connect('/data/checkpoint.db');print(c.execute('PRAGMA integrity_check').fetchone()[0])"
```

### 7.3 异机备份（建议）

在 `ops/backup-cron.sh` 末尾启用 rsync 行（注释已给出），指向 NAS/对象存储；并定期执行一次恢复演练。

---

## 8. 监控与巡检（已配置）

| 项 | 说明 |
|----|------|
| 容器健康 | Docker healthcheck：TCP 探活（`start_period 10s / interval 30s / retries 5`） |
| 服务探针 | `GET /health`（不签名、不限流） |
| 巡检 cron | 每 5 分钟：health + 容器状态 + 磁盘(≥85% 告警) + 管理员鉴权失败计数，日志 `logs/ops.log` |
| 审计日志 | `data/audit.jsonl`：admin 生成/撤销/批量吊销/改绑/IP 拒绝/鉴权失败，JSONL，20MB 轮转 |
| 应用日志 | `docker compose logs`（json-file 10m×3） |

**建议接入真实告警**：把 `logs/ops.log` 的 `ALERT` 行、`data/audit.jsonl` 的 `admin_auth_failed` 接入现有监控（filebeat/vector/promtail → 告警平台）。

---

## 9. 升级与迁移

```bash
# 1) 备份
docker compose exec -T checkpoint-auth python scripts/backup.py

# 2) 替换代码（main.py 等）与 compose 镜像版本
# 3) 重建并启动（自动迁移）
sudo docker compose up -d --build
docker compose logs --tail 50 | grep -E "迁移|数据库就绪|响应签名"

# 4) 回归
docker compose exec -T -e BASE_URL=https://127.0.0.1:8000 checkpoint-auth python test_api.py func
```

**迁移规则**：v1.0→v1.1 明文 token 自动哈希化；v1.1→v1.2 加 last_seen 索引；v1.2→v1.3 增列 `licenses.bound_at/batch`、`activations.user_id`。全部在事务内完成，失败自动回滚。

---

## 10. 安全加固清单（生产必查）

- [ ] `.env` 权限 600，`certs/key.pem` 600 且属主 10001
- [ ] `ADMIN_KEY` ≥32 字符随机；`SIGN_PRIVATE_KEY` 已配置
- [ ] `ADMIN_ALLOW_IPS` 已配置（至少本机/运维网段）
- [ ] 生产删除 `docker-compose.override.yml`（不直接对公网发布 8080）
- [ ] 反代 TLS + `TRUST_PROXY=1`，确认反代追加 XFF
- [ ] `REGISTER_ENABLED` 按业务决定（无注册需求则关闭）
- [ ] 主机：SSH 强密码/密钥、`MaxAuthTries 3`、非必要端口关闭
- [ ] 备份 cron 生效且做过一次恢复演练
- [ ] 巡检 cron 生效，日志有采集
- [ ] 客户端证书指纹与线上证书一致

---

## 11. 故障排查

| 现象 | 排查 |
|------|------|
| 容器 unhealthy | `docker compose logs --tail 100`；检查 .env/证书/数据目录权限 |
| 客户端"连接服务器失败" | 地址/端口/防火墙；证书指纹是否与当前 cert.pem 一致；`openssl s_client -connect IP:8080` |
| 所有响应无 `X-Signature` | `SIGN_PRIVATE_KEY` 未配置或解析失败（日志有告警） |
| 429 频繁 | 确认 TRUST_PROXY 与反代 XFF 配置；必要时调 RATE_*（谨慎） |
| 503 | 瞬态 DB 繁忙，查看日志；持续出现检查磁盘/IO |
| DB 锁错误 | 减少并发写或迁移 PostgreSQL（远期） |
| 迁移失败 | 查看 traceback；用备份恢复后重试 |

---

## 12. 容量与性能（本机实测，50/100 并发）

> 具体数值见 `<内部审计产物>/attack/load-*.json`（fuzz/负载/走私探测在同一隔离实例完成）：
> - /verify + /health 混合压测，100 并发下行 p99 与错误率见文件；
> - SQLite 单写者模型：写 QPS 受限于磁盘与 `BEGIN IMMEDIATE` 串行；读并发良好；预计中小规模（<100 写/秒、<1000 读/秒）足够；
> - 超规模建议：迁移 PostgreSQL + 多副本 + 负载均衡（架构已解耦，迁移成本集中在 DB 层）。
# CheckPoint 版本更新文档（v1.0.0 → v1.3.0）

> 本文是**面向使用者的整合版更新文档**：从最初版本到最新版本的完整演进、接口变化、升级路径与兼容性。
> 细粒度流水记录见 `shared/changelog.md`；各轮安全报告见 `SECURITY-AUDIT-REPORT.md`（v1.1.0）、`ATTACK-REPORT.md`（v1.2.0）、`ROUND3-HARDENING-REPORT.md`（v1.3.0）。

---

## 1. 版本总览

| 版本 | 日期 | 主题 | 核心变化 | 接口变化 |
|------|------|------|----------|----------|
| **v1.0.0** | 2026-11-17 | 初始版本 | 5 个业务接口 + 健康探针；SQLite + bcrypt；基础限流 | 初版契约 |
| **v1.1.0** | 2026-11-18 凌晨 | **全面安全加固**（25 项修复，5 项严重） | 响应签名+nonce、token 哈希/TTL、重新激活、撤销、登录限流、容器加固 | 增量：nonce、X-Signature、TTL、`/admin/revoke`、413/408；semantic：同机重激活 |
| **v1.2.0** | 2026-11-18 上午 | **红队演练修复**（11 项，3 次攻击成功） | HTTPS+证书锁定、XFF 修复、slow-drip 修复、依赖升级、`--raw` | 增量：TLS、`cert_sha256`、`--raw`、426 预留；行为：明文 HTTP 仅限开发 |
| **v1.3.0** | 2026-11-18 | **盲区清零**（20 项业务/运维/供应链） | 登录单会话、宽限改绑、批次止损、审计日志、备份/巡检/轮换、VM 加固 | 增量：`/admin/revoke_batch`、`/admin/rebind`、版次号、426；行为：登录单会话 |

**接口版本对应**：`shared/api-spec.json` 的 `api_version` 与上表版本号一致（当前 1.3.0）。

---

## 2. 版本兼容矩阵（客户端 × 服务端）

| 客户端版本 | v1.0 服务端 | v1.1 服务端 | v1.2 服务端 | v1.3 服务端 |
|-----------|-------------|-------------|-------------|-------------|
| **v1.0**（无验签） | ✔ | ✔（响应多签名头，忽略） | ⚠ 可用但无 TLS 锁定/验签（不建议） | ⚠ 同左；若启用 MIN_CLIENT_VERSION 则 426 |
| **v1.1**（验签+nonce） | ✘ 拒绝（服务端无签名） | ✔ | ✔（HTTP 仍可用但无 TLS 锁定） | ✔ |
| **v1.2**（TLS 锁定+--raw） | ✘ | ✘（无 TLS） | ✔ | ✔ |
| **v1.3**（版本头） | ✘ | ✘ | ✔ | ✔ |

> 结论：**服务端升级不强制客户端升级**（除 TLS 强制后 v1.0/v1.1 的 HTTP 客户端需配 https）；但客户端升级到 v1.2+ 才能获得防中间人/防伪造的完整保护。

---

## 3. 各版本详情

### 3.1 v1.0.0 —— 初始版本（2026-11-17）

**功能**
- 接口：`POST /register`、`/login`、`/activate`、`/verify`、`/admin/gen_keys`、`GET /health`
- 存储：SQLite（WAL）、bcrypt rounds=12、`secrets.token_urlsafe(32)`（43 字符）
- 限流：同 IP 30 次/分钟、同 machine_code 10 次激活/分钟
- 客户端：.NET 8 单文件 `checkpoint.exe`（activate/login/verify 三命令），输出遮蔽 token/key/password
- 部署：Docker（root，bind mount `/data`），Kali VM checkpoint.example.com:8080（内网 HTTP）
- 已具备的安全基线：参数化 SQL、统一失败文案（防卡密枚举）、bcrypt 上限校验（72 字节）、伪哈希时序对齐、管理员密钥常量时间比较（str 版本）

**已知不足（后续版本修复）**：无响应签名、token 明文入库且永不过期、卡密无撤销、登录无失败限流、`/docs` 暴露、容器 root、日志可能含密码等（见 v1.1.0）。

### 3.2 v1.1.0 —— 全面安全加固（2026-11-18 凌晨）

**背景**：对 v1.0.0 做全量安全审计（见 `SECURITY-AUDIT-REPORT.md`），发现 **25 项问题**（5 严重 / 8 高危 / 7 中危 / 5 加固级），全部修复。

**修复摘要**

| 严重度 | 关键修复 |
|--------|----------|
| 严重 | ① 响应签名（ECDSA P-256/SHA-256，`X-Signature`）+ 客户端 fail-closed 验签 → 防伪造服务器；② token 改 SHA-256 哈希入库（拖库不可复用）；③ token 滑动过期（默认 30 天）；④ 登录失败限流（用户名+IP 8 次/分钟）；⑤ 同机器重新激活（修「token 丢失即卡密作废」缺陷） |
| 高 | 关闭 `/docs` `/redoc` `/openapi.json`；XFF 改取**最右侧**（原最左侧可伪造绕限流）；请求体 16KB 上限（413）；请求体读取超时（408）；容器非 root + 只读根 FS + cap_drop + pids_limit；422 日志脱敏（原会把密码写日志）；密码控制字符/孤立代理对防 500 |
| 中 | 日志注入防护、管理员密钥字节级常量时间比较、5 项安全响应头、卡密撤销（`/admin/revoke`）、客户端禁用自动重定向、敏感参数 stdin（`-`）、依赖清理与锁定 |
| 加固 | read_only/tmpfs/pids_limit/init、移除 uvicorn `--proxy-headers`、机器码常量时间比较、`--limit-concurrency` |

**接口增量（v1.1.0）**
- 请求可选 `nonce`；响应顶层回显 `nonce`，全部业务响应带 `X-Signature`
- `/verify`：token 滑动过期；过期/撤销统一「验证失败」
- `/activate`：同 machine_code 重新激活成功并补发 token；不同机器仍统一失败
- 新增 `/admin/revoke`；新增 HTTP 413 / 408
- 客户端：`code=0` 必须验签+nonce 匹配（否则退出码 1）；支持 `-` 从 stdin 读敏感参数

**验证**：10 轮全量测试 × 128 项断言全过；Windows 真机 15/15（含假服务器/重放/篡改签名全部拒绝）；生产数据无损迁移（7/7 旧 token 有效）。

### 3.3 v1.2.0 —— 红队攻击模拟与修复（2026-11-18 上午）

**背景**：以 6 类攻击者视角实战演练（反编译 / 中间人 / 爆破 / 注入 / DoS / 业务滥用），发现 **11 项新问题（V26~V36）**，其中 **3 项攻击成功**，全部修复（见 `ATTACK-REPORT.md`）。

**成功攻击 → 修复**

| 攻击 | 战果 | 修复 |
|------|------|------|
| B1 被动窃听 | 明文 HTTP 下拿到完整卡密+机器码+token | **TLS（自签名证书）+ 客户端证书指纹锁定**（`DefaultCertPin`，`cert_sha256` 可覆盖） |
| B2 篡改请求 | 改 machine_code 字段即可偷走卡密绑定（DB 实证） | 同上（TLS 完整性保护） |
| C1 轮换 XFF 绕限流 | 35 个伪造 IP 全部绕过（uvicorn 默认 proxy_headers 架空应用层防线） | 启动参数 `--no-proxy-headers`；spoof 测试改轮换 XFF |
| E1 slow-drip | 每秒 1 字节挂连接 40s+ | body 读取**总超时 15s** + 单次 5s |
| E2 洪水连坐 healthcheck | 打满并发后 /health 503 → 重启风暴 | 并发 200 + **TCP 探活** healthcheck（retries 5） |
| F1 token 行膨胀 | 重新激活刷行不清理（表已累积 314 行） | 启动/登录/激活时**主动清理过期行** + last_seen 索引 |

**其他修复**：20KB 请求头（`--h11-max-incomplete-event-size 8192`）；DB 锁竞争 → 503（原 500）；`os.umask(0o077)` + 启动 chmod 600；依赖整体升级（fastapi 0.163.2 / starlette 1.10.0 / uvicorn 0.54.0 / pydantic 2.14.3 / bcrypt 5.0.0 / cryptography 50.0.2，修 OpenSSL 新通告）；新增客户端 **`--raw` 模式**（主程序可自验签，防客户端被补丁）。

**接口增量（v1.2.0）**
- 传输层：HTTPS（`/certs` 有证书即启用；无证书降级 HTTP 仅限开发）
- 客户端配置新增可选 `cert_sha256`；客户端 UA 升 1.2
- 新增 `--raw` 输出：`{"code":0,"raw":"<响应base64>","sig":"<签名>"}`
- 新增 HTTP 503（瞬态繁忙）

**验证**：10 轮全量（TLS）通过；e2e-v2 14/14（锁定成功、错误指纹拒绝、假证书 MITM 拒绝、--raw 独立验签、透传代理只见密文）。

### 3.4 v1.3.0 —— 盲区清零（2026-11-18）

**背景**：v1.2.0 后梳理出 20 项未覆盖盲区（业务逻辑 / 运维 / 信任边界 / 安全工程 / 人力层），全部处理（见 `ROUND3-HARDENING-REPORT.md`）。

**业务逻辑（真实漏洞与能力）**

| # | 内容 |
|---|------|
| 1 | **登录 token 无限增殖（真实漏洞）**：每次登录新 token、旧行不过期不清理 → 频繁/恶意登录可日增数万行。修复：**登录单会话**（新登录事务内注销该用户全部旧登录 token；`activations.user_id` + 索引） |
| 2 | **卡密抢绑**：新增 `REBIND_GRACE_HOURS`（默认 24h）——首次绑定后宽限期内可自助改绑（旧机器 token 全部注销）；超期拒绝；设 0 完全禁止 |
| 3 | 售后能力：`/admin/rebind`（改绑/解绑，注销旧 token） |
| 4 | 注册面：`REGISTER_ENABLED=0` 关闭注册 |
| 5 | 批次归属与止损：gen_keys 支持 `batch`（省略自动生成），`/admin/revoke_batch` 批量吊销未使用卡密 |
| 6 | 审计：`data/audit.jsonl`（生成/撤销/批量吊销/改绑/鉴权失败/IP 白名单拒绝，600 权限，20MB 轮转） |
| 7 | 版本门槛：`MIN_CLIENT_VERSION` + 客户端 `X-Client-Version`，低于版本 426 |
| 8 | 管理面纵深：`ADMIN_ALLOW_IPS` IP 白名单 |

**运维落地**
- 每日 03:15 自动备份（容器内在线备份+`PRAGMA integrity_check`+gzip+保留 14 份）；**恢复演练已执行通过**
- 每 5 分钟巡检（health/容器/磁盘≥85%/管理员鉴权失败计数），root cron 已生效
- `ops/rotate-cert.sh` 证书轮换（备份旧证书+重启+打印新指纹与客户端更新指引）
- **测试环境隔离**：`docker-compose.test.yml` 临时 DB（重建即清空）；10 轮回归生产库零写入
- 基础镜像 digest 锁定（供应链）
- **VM 主机加固**：部署用户密码改 24 位强随机（旧密码失效，存宿主机 ACL 受限文件）；sshd 加固（MaxAuthTries 3 / LoginGraceTime 20 / ClientAlive 300×2）；部署用户加入 docker 组

**接口增量（v1.3.0）**
- 登录单会话语义（旧 token 失效）
- 激活宽限期改绑语义（见 §4）
- `gen_keys` 请求可选 `batch`，响应新增 `batch`
- 新增 `/admin/revoke_batch`、`/admin/rebind`；新增 HTTP 426
- 客户端发送 `X-Client-Version: 1.3.0`，UA `CheckPoint-Client/1.3`

**验证**
- 10 轮全量回归（9 阶段 × 160 断言 = **1600 项，0 失败**）
- e2e-v3 真机 **10/10**（登录单会话、宽限改绑、--raw 验签、TLS 回归）
- 结构化 fuzz **1000 迭代 PASS**（0 失败/0 个 5xx/0 慢请求）
- 请求走私探测 **6/6 PASS**（全部 400、无 desync）
- 负载（TLS 混合压测）：50 并发 359.5 RPS（p99 204ms）；100 并发 300.6 RPS（p99 450ms）；**0 错误**

**文档**：新增 `docs/API.md`（接口调用）、`docs/SERVER-INSTALL.md`（安装运维）、`docs/INTEGRATION.md`（对接+机器码规范+--raw 验签示例）。

---

## 4. 行为变更清单（对接方必读，跨版本累积）

| # | 变更 | 引入版本 | 影响 |
|---|------|----------|------|
| 1 | 成功响应（code=0）必须验签+nonce；失败=不可信 | v1.1.0 | 旧客户端忽略签名仍可用，但无保护；新客户端对无签名成功响应退出码 1 |
| 2 | 卡密同机器重新激活 → 补发 token | v1.1.0 | 旧 token 仍有效（直到过期）；可用于自动找回 |
| 3 | token 30 天滑动过期 | v1.1.0 | 长期未用需重新激活；同机器激活自动补发 |
| 4 | 登录失败限流（用户名+IP 8 次/分钟） | v1.1.0 | 频密失败会被 429，含正确密码 |
| 5 | 生产传输改 HTTPS + 证书锁定 | v1.2.0 | 客户端必须配 https 地址并内置/配置正确指纹 |
| 6 | 请求体上限 16KB / 会 413 | v1.1.0 | 客户端请求都很小，无影响 |
| 7 | 请求体读取总超时 15s / 408 | v1.2.0 | 正常请求 <1s，无影响 |
| 8 | 登录单会话（新登录注销旧 token） | v1.3.0 | **多开/多实例需复用同一 token**，不要重复 login |
| 9 | 首次绑定后 24h 内可改绑（旧机器 token 立即失效） | v1.3.0 | 防抢绑；超期需客服 `/admin/rebind` |
| 10 | 客户端版本门槛（可选启用） | v1.3.0 | 服务端启用后旧客户端 426 |
| 11 | 响应新增顶层 `nonce` 字段 | v1.1.0 | 解析器需容忍额外字段 |
| 12 | 响应 `data.batch`（gen_keys） | v1.3.0 | 同上 |

---

## 5. 升级路径与数据迁移

**数据库自动迁移（启动时执行，幂等，事务保护）**

| 升级 | 迁移内容 |
|------|----------|
| v1.0 → v1.1 | `activations.token`（明文）→ `token_hash`（SHA-256）：重建表拷贝并哈希化，**原 token 继续有效** |
| v1.1 → v1.2 | 新增 `idx_activations_last_seen` 索引（旧 token 主动清理依赖） |
| v1.2 → v1.3 | 新增列：`licenses.bound_at`、`licenses.batch`、`activations.user_id`；全部 `ALTER TABLE ADD COLUMN` 幂等 |

**逐跳升级步骤（每跳都适用）**
1. 备份：`docker compose exec -T checkpoint-auth python scripts/backup.py`
2. 替换代码/compose 镜像版本 → `docker compose up -d --build`
3. 观察日志：`迁移：...` / `数据库就绪` / `响应签名已启用`
4. 冒烟：`test_api.py func`（或 `rebind` 快速 23 项）
5. 回归客户端：真机 activate/verify 各一条

**跨版本注意事项**
- v1.1 → v1.2：**必须先部署证书并把新指纹给客户端**（否则新客户端全部"连接失败"；过渡期可在客户端配置 `cert_sha256`）
- v1.2 → v1.3：登录单会话上线后，依赖"旧登录 token 长期有效"的集成需改为保存最新 token
- 任何跳：`SIGN_PRIVATE_KEY` 必须已配置（v1.1+ 响应签名）

---

## 6. 验证与测试演进

| 版本 | 测试能力 | 结果 |
|------|----------|------|
| v1.0 | func/mc/ip/escape/race（5 阶段） | 72 项通过 |
| v1.1 | 8 阶段（+sig/security/spoof），128 项/轮 | 10 轮 × 128 = 1280 项全过；真机 15/15 |
| v1.2 | 攻击回归：轮换 XFF、token 清理、slow-drip；隔离前测试 | 10 轮全过；e2e-v2 14/14；3 类攻击复打全部失败 |
| v1.3 | 9 阶段（+rebind）、**测试容器隔离**；新增 fuzz/负载/走私工具 | 10 轮 × 160 = 1600 项全过；e2e-v3 10/10；fuzz 1000 迭代 PASS；走私 6/6 PASS；负载 0 错误 |

**测试证据**：`<内部审计产物>/`（v1.1）、`<内部审计产物>/`（v1.2）、`<内部审计产物>/`（v1.3）。

---

## 7. 部署与文件结构变化

| 版本 | 部署形态 | 关键文件 |
|------|----------|----------|
| v1.0 | Docker root、bind mount、HTTP 8080 | Dockerfile、docker-compose.yml、main.py、test_api.py |
| v1.1 | 非 root 10001、只读 FS、cap_drop、tmpfs、init | + entrypoint 说明、requirements 锁定、certs 目录预留 |
| v1.2 | TLS（自签）+ 证书挂载、`--no-proxy-headers`、TCP 探活 healthcheck、基础镜像 digest 锁定 | + certs/、entrypoint.sh、Dockerfile digest |
| v1.3 | 测试隔离 compose、运维脚本、审计日志、备份目录 | + docker-compose.test(.hi).yml、scripts/（fuzz/load/smuggling/backup）、ops/（run-round/run-attack/backup-cron/healthcheck-cron/rotate-cert）、docs/ |

**当前生产运行形态（v1.3.0）**
```
容器 checkpoint-auth:1.3.0
├─ 非 root(10001) / 只读根 FS / cap_drop ALL / pids 128 / 内存 256M
├─ uvicorn: --no-proxy-headers --limit-concurrency 200 --ssl-* 
├─ 挂载: ./data:/data (600), ./certs:/certs:ro (600/644)
├─ healthcheck: TCP 探活 (start 10s / interval 30s / retries 5)
└─ 环境: ADMIN_KEY / SIGN_PRIVATE_KEY / TOKEN_TTL_DAYS / REBIND_GRACE_HOURS ...
```

---

## 8. 安全态势演进（攻击面关闭记录）

| 攻击面 | v1.0 | v1.1 | v1.2 | v1.3 |
|--------|------|------|------|------|
| 伪造服务器返回 code=0 | ✗ 可 | 签名+nonce → 拦截 | 同左 | 同左 |
| 抓包重放成功响应 | ✗ 可 | nonce → 拦截 | 同左 | 同左 |
| 链路窃听凭据 | ✗ 可 | ✗ 可（HTTP） | **TLS → 拦截** | 同左 |
| 篡改请求偷卡密绑定 | ✗ 可 | ✗ 可（HTTP） | **TLS → 拦截** | 同左 |
| XFF 轮换绕过限流 | ✗ 可 | 应用层修复但被 uvicorn 默认架空 | **--no-proxy-headers → 拦截** | 同左 |
| slow-drip 挂连接 | ✗ 可 | 单次超时（可绕） | **总超时 → 拦截** | 同左 |
| 洪水打 healthcheck | ✗ 可 | 未覆盖 | **TCP 探活 + 并发 200 → 缓解** | 同左 |
| 登录 token 无限增殖 | ✗ 可 | 部分（TTL 不覆盖活跃行） | 同左 | **单会话 → 拦截** |
| 卡密抢先绑定 | ✗ 可 | ✗ 可 | ✗ 可 | 宽限期夺回（缓解） |
| 拖库后 token 复用 | ✗ 可 | 哈希 → 失效 | 同左 | 同左 |
| 暴力破解登录 | ✗ 可 | 失败限流 → 拦截 | 同左 | 同左 |
| 管理员密钥爆破 | 30/min 兜底 | 同左 | 同左 | + IP 白名单 |
| 卡密泄露无法止损 | ✗ | /admin/revoke | 同左 | + 批次吊销 |
| 旧客户端带漏洞使用 | — | 可选兼容 | 可选兼容 | + MIN_CLIENT_VERSION 强制升级 |

---

## 9. 当前状态与后续路线

**当前（v1.3.0）**：服务端 `https://checkpoint.example.com:8080`（TLS + 响应签名 + 全部加固），客户端 v1.3 已发布；备份/巡检/轮换/审计已就绪；三份使用文档齐备。

**后续路线（详见 ROUND3-HARDENING-REPORT §四）**
1. pip `--require-hashes` + SBOM/CI 漏洞扫描
2. 双签名密钥并行（客户端内置双公钥，平滑轮换）
3. 管理面 TOTP 2FA
4. Prometheus 指标 + 告警
5. 反代层限流 + 走私复测（上线反代后必做）
6. 备份异机（rsync/NAS）+ 定期自动恢复演练
7. 离线签名票据（断网场景）
8. 覆盖率引导 fuzz（atheris）
9. 多管理员 RBAC + 操作审批
10. 数据规模增长后迁移 PostgreSQL
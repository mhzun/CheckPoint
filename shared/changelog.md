# CheckPoint 接口变更记录

格式：`[时间] 版本 - 变更内容（影响客户端的地方必须写明）`

---

## [2026-11-17 10:00] v1.0.0 - 初始契约发布

- 新建 `shared/api-spec.json`，定义 5 个业务接口：`/register`、`/login`、`/activate`、`/verify`、`/admin/gen_keys`
- 统一响应结构：`{"code": 0|1, "msg": 中文, "data": object|null}`
- 请求体统一 `application/json`，全部 POST

## [2026-11-17 10:30] v1.0.0-refine（不改变字段名与类型）

- **澄清**：字段长度/格式不合法时返回 **HTTP 200 + code=1 + 中文 msg**；只有「字段缺失、JSON 非法、字段类型错误」才返回 HTTP 422（msg 同样为中文）。客户端无需为这两种情况准备两套解析逻辑，一律读 `msg` 展示即可。
- **收紧**：`/activate` 在「卡密不存在 / 已使用 / 已过期」三种情况下均只返回 `{"code":1,"msg":"卡密无效或已失效"}`，不再返回「已绑定其他机器」这类可区分文案（避免卡密存在性泄露）。客户端若已实现该分支，请删除。
- **新增**：`GET /health` 运维探针（非业务接口，不计入 IP 限流），返回 `{"code":0,"msg":"服务正常","data":{"status":"ok"}}`。仅用于 Docker healthcheck / 运维巡检，客户端不需要调用。
- **确认**：`token` 由 `secrets.token_urlsafe(32)` 生成，实际长度 **43 字符**（URL-safe base64、无填充）。契约中「64 位字符串」的表述以安全红线为准，客户端必须按**变长字符串**处理（不要硬编码 64 或 43 位）。`/verify` 入参校验为 16-128 位 URL-safe 字符。
- 补充限流响应：HTTP 429 + `Retry-After: 60`，msg 为中文。

## [2026-11-17 22:35] v1.0.0-final - 服务端实现完成 + 回应客户端

- **实现完成**：5 个业务接口 + `GET /health` 全部实现，72 项自动化测试通过（含并发激活原子性、双限流、SQL 注入、bcrypt 参数、token 长度、卡密格式）。
- **契约补充（不改变字段名/类型）**：`/verify` 说明新增——激活 token 会比对 `machine_code`；**登录 token（`license_key` 为 NULL）不绑定机器，只校验存在性，不比对 `machine_code`**。
- **澄清 `machine_code` 来源**：由调用方（主程序）生成，客户端与服务端均只透传；服务端清洗规则为「去控制字符 → 去首尾空白 → 截断 128」，比对使用清洗后原值全等比较。原先 `server-to-client.md` 中「客户端自行生成」的表述已修正。
- **回应客户端 4 点**（详见 `shared/messages/server-to-client.md`）：
  1. machine_code 由调用方生成 —— 确认，无需客户端改动。
  2. 卡密本地正则预校验 —— 不要求，保持现状。
  3. 429 不自动重试 —— 确认，退避交给上层；服务端保证带 `Retry-After: 60`。
  4. **默认地址 `http://localhost:8080` 需改为 `http://127.0.0.1:8080`** —— 服务端仅监听 IPv4 回环，Windows 上 `localhost` 可能解析为 `::1` 导致连接失败。客户端已于 22:45 完成修改并重新发布。
- **已知差异**：契约文案「token 64 位」以安全红线（`secrets.token_urlsafe(32)`）为准，实际 43 字符，客户端已按变长处理。
- **未验证项（当时环境限制）**：本机无 Docker，镜像构建与 compose 启动未执行；`docker-compose.yml` 已通过 YAML 解析与关键字段核对。**后续已在 Kali 虚拟机上完成实际构建与部署，见下条。**

## [2026-11-17 23:10] 部署到 Kali 虚拟机（镜像构建 + 端到端联调通过）

- **环境**：Kali Rolling 2026.1（内核 6.18.12），Docker 28.5.2 + Compose 2.40.3（apt 源，国内镜像），已配 registry mirror（`docker.m.daocloud.io` / `docker.1panel.live`）。
- **部署**：`/opt/checkpoint`，镜像 `checkpoint-auth:1.0.0`，容器 `checkpoint-auth` 状态 healthy，`restart: unless-stopped`，256M 内存上限，`./data:/data` 持久化。
- **构建**：`docker compose up -d --build` 成功（pip 依赖安装耗时约 17 分钟，因容器内访问 PyPI 速度约 18 KB/s；镜像已缓存，后续重建很快）。
- **内网访问**：新增 `docker-compose.override.yml`（`ports: !override` → `8080:8000`）发布到 `checkpoint.example.com:8080`；基础 `docker-compose.yml` 未改动，仍为 `127.0.0.1:8080:8000`。**生产请删除 override**。
- **回归结果**：虚拟机内 功能 57/57、machine_code 限流 3/3、IP 限流 3/3；Windows 侧 HTTP 全链路 8 项通过；真实 `checkpoint.exe` 四条命令（activate 成功 / verify 假 token / 重复激活 / login 不存在用户）输出与退出码均符合契约。
- **持久化**：`docker compose restart` 后 `users=1 / licenses=7 / activations=2`，重启后仍可登录，证明数据在挂载卷。
- **运维提示（新增）**：Docker 端口映射下容器看到的源 IP 为 bridge 网关 `172.18.0.1`，内网客户端共享同一 30 次/分钟 IP 桶；生产需反代透传 `X-Forwarded-For` 且 `TRUST_PROXY=1`。
- **未做**：虚拟机 sshd 未启动，本次通过 VMware Tools（`vmrun`）执行命令；如需 SSH 运维，在虚拟机内执行 `sudo systemctl enable --now ssh`。
## [2026-11-18 01:30] v1.1.0 - 全面安全审计与加固（服务端 + 客户端 + 部署）

**本次变更为全量安全审计结果，接口有少量不破坏对接的增量变化，详见 `api-spec.json` v1.1.0。**

### 契约增量（客户端需知）

- **请求新增可选字段 `nonce`**（URL-safe base64，8-64 字符）：客户端每次请求随机生成并放入请求体；服务端把 nonce 原样回显到响应 JSON 顶层 `nonce` 字段，并纳入签名。
- **响应签名**：除 `/health` 外所有 JSON 响应带 `X-Signature` 头（ECDSA P-256/SHA-256，DER base64，签名内容 = 完整响应字节）。客户端内置公钥（`ResponseSignature.PublicKeyBase64`）。
- **客户端信任策略（fail-closed）**：`code=0` 的成功响应必须同时满足 ① X-Signature 验签通过 ② 响应 nonce == 请求 nonce；否则输出 `{"code":-1,"msg":"...","data":null}` 固定文案并返回退出码 1。业务失败响应（code=1）无签名时仅在 stderr 提示，不阻断。
- **客户端支持 stdin 传敏感参数**：参数位置填 `-` 表示从 stdin 读取一行（避免卡密/密码/token 出现在进程命令行，任务管理器/Win32_Process 可见）。完全向后兼容（直接传值仍可用）。
- **`/verify` 新增 token 滑动过期**：所有 token 自最后一次使用起最多存活 `TOKEN_TTL_DAYS` 天（默认 30，环境变量可调），超期验证失败且记录被清理。离线超过有效期的机器需重新激活。
- **`/activate` 新增「同机器重新激活」语义**：已激活卡密以相同 machine_code 再次激活 → 成功并补发新 token（找回场景）；不同 machine_code → 仍为统一失败文案。**主程序如遇到旧 token 失效，重新调 activate 即可恢复，无需人工干预。**
- **新增 `/admin/revoke`**：撤销卡密（幂等），撤销后激活被拒、已签发 token 全部立即失效。
- **限流增量**：同「用户名+IP」每分钟 8 次登录失败后触发 429（正确密码也被拒直到窗口滑出），防暴力破解；原 IP 30 次/分钟、machine_code 10 次/分钟不变。
- **新增错误码**：HTTP 413（请求体 > 16KB）、HTTP 408（请求体读取超时 10s）。

### 服务端修复（按审计项）

1. 关闭生产交互式文档：`/docs` `/redoc` `/openapi.json` 返回 404
2. 响应签名 + nonce 防伪造服务器/MITM/重放（`SIGN_PRIVATE_KEY`）
3. token 数据库仅存 SHA-256 哈希（数据库失窃不可复用），含 v1.0.0 数据自动迁移（原 token 继续有效）
4. token 滑动过期（TOKEN_TTL_DAYS，默认 30 天）
5. 登录失败限流（用户名+IP 维度，8 次/分钟，正确密码也阻断，防 DoS 式全锁）
6. 同机器重新激活（修复「token 丢失后卡密永久作废」缺陷）
7. 卡密撤销（status='revoked'，激活与验证均拒绝）
8. 请求体 16KB 上限（413）+ 请求体读取超时（408，防 slow-body 资源耗尽）
9. X-Forwarded-For 取【最右侧】受信地址（原实现取最左侧可被客户端伪造绕过限流）；IP 形态校验，非法值丢弃
10. uvicorn --proxy-headers 移除（避免与应用内 TRUST_PROXY 双重信任）
11. 密码拒绝控制字符（含 NUL，原可致 500）与无法 UTF-8 编码的孤立代理对（原可致 500）
12. 422 异常日志不再记录原始输入值（原 pydantic errors 会把 password 等写进日志）
13. 日志全面脱敏（repr + 截断，防日志注入；machine_code/用户名/IP/路径统一处理）
14. 管理员密钥常量时间比较改为 UTF-8 字节级（原对非 ASCII 密钥退化为 ==）；长度 < 32 启动警告
15. 安全响应头：X-Content-Type-Options / Cache-Control: no-store / X-Frame-Options / Referrer-Policy / CSP
16. uvicorn --limit-concurrency 100（配合请求体超时防连接耗尽）
17. machine_code 比较改为字节级常量时间比较

### 客户端修复

1. 内置公钥验签 + nonce 防重放（fail-closed，见上）
2. 敏感参数 stdin 支持（`-` 占位）
3. 禁用 HTTP 自动重定向（防重定向劫持重放请求体）
4. 新增 408/413 的固定文案映射

### 部署加固（Docker）

1. 容器以非 root（UID 10001）运行；数据目录需 `chown 10001:10001 ./data`
2. `read_only: true`（根文件系统只读）+ tmpfs /tmp
3. `cap_drop: [ALL]`、`pids_limit: 128`、`init: true`、保留 no-new-privileges / 内存上限 / 日志轮转
4. requirements 移除未使用的 python-multipart；新增 cryptography==44.0.1（签名）
5. ADMIN_KEY 已轮换为 53 字符高熵密钥（仅存 VM `/opt/checkpoint/.env`，600 权限，不入库不入文档）
6. SIGN_PRIVATE_KEY 部署于同一 .env（v1.1.0 签名密钥对，公钥编译进客户端）

### 测试

- 套件扩展为 8 个阶段：func / escape / race / sig / security / spoof / mc / ip
- 新增验证：签名与 nonce、文档关闭、413、安全头、登录限流、token TTL、撤销、旧库迁移、XFF 伪造防护、NUL/代理对密码、token 哈希入库、同机器重新激活
- 全量测试执行 ≥ 10 轮（每轮 8 阶段，结果见 `test-results/` 与审计报告）

## [2026-11-18 09:30] v1.2.0 - 红队攻击模拟与修复（ATTACK-REPORT.md）

**本轮以 6 类攻击者视角实战演练（反编译/MITM/爆破/注入/DoS/业务滥用），发现 11 项新问题（V26~V36），其中 3 项攻击成功突破，全部已修复。复打全部失败，10 轮全量测试通过。**

### 成功攻击与修复（重点）

1. **B2 中间人偷卡密绑定（严重）**：明文 HTTP 下，代理把 /activate 请求里的 machine_code 改成攻击者的即可偷走绑定（实测受害者卡密 bound_machine=ATTACKER-MACHINE）。修复：服务器 TLS 化（自签名证书，SAN 含部署 IP）+ 客户端证书指纹锁定（内置 DefaultCertPin，配置 cert_sha256 可覆盖）。
2. **B1 被动窃听（严重）**：明文链路可抓到完整卡密/机器码/token。修复：同上 TLS；透传代理实测只见密文。
3. **C1 轮换 XFF 绕过限流（高危）**：uvicorn 默认 proxy_headers=True + forwarded-allow-ips=127.0.0.1，用 XFF 第一个条目重写 client IP，架空应用层 TRUST_PROXY=0。修复：--no-proxy-headers。spoof 测试改为轮换 XFF（旧测试固定 XFF 掩盖了此漏洞）。
4. **E1 slow-drip 挂连接（高危）**：body 超时原为"单次 receive 10s"，每秒喂 1 字节可无限挂连接。修复：总时长上限 15s + 单次 5s。
5. **E2 洪水连坐 /health（中危）**：半开连接打满 --limit-concurrency 后 healthcheck 误判 unhealthy 引发重启风暴。修复：并发提至 200 + TCP 探活 + retries=5。
6. **F1 token 行无限膨胀（中危）**：无人 verify 的旧行永不清理。修复：last_seen 索引 + 启动/登录/激活时主动清理。
7. **V29 超大头（低）**：--h11-max-incomplete-event-size 8192。
8. **V34 客户端补丁绕过（结构性）**：新增 --raw 模式，主程序可独立验签摆脱对客户端的信任。
9. **V35 依赖滞后**：升级 fastapi 0.163.2 / uvicorn 0.54.0 / pydantic 2.14.3 / bcrypt 5.0.0 / cryptography 50.0.2（含 OpenSSL 新通告修复）/ starlette 1.10.0。
10. **V36 DB 权限**：os.umask(0o077) + entrypoint chmod 600。

### 客户端对接变化（增量）

- 生产地址改为 **https**；客户端内置证书指纹锁定，错误指纹直接拒绝连接。
- 配置文件新增可选 `cert_sha256`（64 位十六进制）覆盖内置指纹（仅开发环境用）。
- 新增 `--raw` 前缀输出原始响应+签名（供主程序自验签）。
- 其余字段/文案/退出码语义不变；503 为新增瞬态错误码（重试即可）。

### 测试

- 套件新增回归项：轮换 XFF spoof、token 清理、slow-drip 总超时。
- v1.2.0 TLS 环境下 10 轮 × 8 阶段全部通过（<内部审计产物>/）。
- Windows 真机 e2e-v2 14 项全过（TLS 锁定/错误指纹拒绝/假证书 MITM 拒绝/--raw 独立验签/透传代理密文/业务回归）。

## [2026-11-18 10:30] v1.3.0 - 盲区清零（业务/运维/供应链）+ 三份正式文档

**上一轮列出的 20 项盲区全部落地处理；新增能力详见 docs/API.md、docs/SERVER-INSTALL.md、docs/INTEGRATION.md。**

### 业务逻辑修复

1. **登录 token 无限增殖（真实漏洞）**：每次登录插入新 token 行，活跃行不被 TTL 清理，恶意/频繁登录可日增数万行。修复：**单会话**——新登录注销该用户全部旧登录 token（activations 增列 user_id）。
2. **卡密抢绑（squatting）缓解**：新增 `REBIND_GRACE_HOURS`（默认 24h）——首次绑定后宽限期内允许换机器改绑（旧机器 token 立即注销）；超期拒绝。管理员新增 `/admin/rebind`（改绑/解绑）处理客服场景。
3. **卡密无法追溯与批量止损**：gen_keys 支持 `batch` 批次号（省略自动生成）；新增 `/admin/revoke_batch` 按批吊销未使用卡密。
4. **注册面**：`REGISTER_ENABLED=0` 可关闭开放注册。
5. **管理面纵深**：`ADMIN_ALLOW_IPS` IP 白名单；全部管理员操作写审计日志（`data/audit.jsonl`，20MB 轮转）。
6. **客户端版本门槛**：`MIN_CLIENT_VERSION` + 客户端 `X-Client-Version` 头，低版本 426（可拒绝不验签的旧客户端）。

### 运维落地

7. **备份自动化**：容器内 `scripts/backup.py`（在线备份+完整性校验+gzip+保留 14 份）+ root cron 每日 03:15；**恢复演练已执行并通过**。
8. **巡检自动化**：`ops/healthcheck-cron.sh` 每 5 分钟（health/容器/磁盘≥85%/管理员鉴权失败计数）；cron 已安装。
9. **证书轮换**：`ops/rotate-cert.sh`（生成+备份旧证书+重启+打印新指纹与客户端更新指引）。
10. **环境隔离**：新增 `docker-compose.test.yml`（临时 DB，重建即清空）与 `test-hi`（高限流），10 轮回归不再污染生产库。
11. **供应链**：基础镜像改为 digest 锁定（`python:3.11-slim@sha256:07d482...`）。
12. **主机加固**：VM 部署用户密码已更换为 24 字符强随机（旧密码失效，新密码保存在宿主机 ACL 受限文件）；sshd 加固（MaxAuthTries 3 / LoginGraceTime 20 / ClientAlive 300×2）；部署用户加入 docker 组免 sudo。

### 测试与演练

13. 新增 `rebind` 测试阶段（宽限改绑/过期拒绝/管理员改绑解绑/批次吊销/审计），套件扩为 **9 阶段**；登录单会话、审计断言并入 func。
14. **结构化 fuzz 战役**（500 迭代随机畸形请求）、**负载测试**（50/100 并发）、**请求走私探测**（CL.TE/TE.CL/重复 CL/畸形 framing）脚本入镜像。
15. 隔离环境 10 轮全量回归（每轮 160 项断言）全部通过；e2e-v3 真机 10/10（登录单会话、宽限改绑新语义）。
16. 三份文档：`docs/API.md`（完整调用）、`docs/SERVER-INSTALL.md`（安装运维）、`docs/INTEGRATION.md`（对接+机器码规范+--raw 验签示例）。

### 接口增量（不破坏旧客户端）

- 登录单会话语义（旧 token 失效）
- 激活宽限期改绑语义
- gen_keys 请求可选 `batch`，响应新增 `batch`
- 新增 `/admin/revoke_batch`、`/admin/rebind`
- 新增 HTTP 426（版本门槛）

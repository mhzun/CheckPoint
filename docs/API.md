# CheckPoint API 调用文档（v1.3.0）

> 适用服务端版本：v1.3.0 ｜ 契约文件：`shared/api-spec.json`（机器可读）｜ 本文是人工使用指南
> 所有接口均为 **HTTPS + JSON**。生产地址示例：`https://checkpoint.example.com:8080`

---

## 0. 一分钟示例

```bash
# 发一张卡密（管理员）
curl -k https://checkpoint.example.com:8080/admin/gen_keys \
  -H "X-Admin-Key: $ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"count":1,"expire_days":365,"batch":"ORDER-2026-11","nonce":"demoNonce0001"}'
# => {"code":0,"msg":"生成成功","data":{"keys":["VIP-XXXXXXXX-XXXXXXXX-XXXXXXXX"],"batch":"ORDER-2026-11"},"nonce":"demoNonce0001"}

# 激活
curl -k https://checkpoint.example.com:8080/activate \
  -H "Content-Type: application/json" \
  -d '{"key":"VIP-XXXXXXXX-XXXXXXXX-XXXXXXXX","machine_code":"MY-PC-001","nonce":"demoNonce0002"}'
# => {"code":0,"msg":"激活成功","data":{"token":"<43字符>"},"nonce":"demoNonce0002"}

# 验证
curl -k https://checkpoint.example.com:8080/verify \
  -H "Content-Type: application/json" \
  -d '{"token":"<43字符>","machine_code":"MY-PC-001","nonce":"demoNonce0003"}'
# => {"code":0,"msg":"验证通过","data":{"valid":true},"nonce":"demoNonce0003"}
```

---

## 1. 传输层与信任模型

| 项目 | 说明 |
|------|------|
| 协议 | HTTPS（TLS）。服务端自签名证书（10 年，SAN 含部署 IP / localhost / checkpoint.local） |
| 证书 | `server/certs/cert.pem` 公开；私钥仅存服务端 `certs/key.pem`（600） |
| 客户端锁定 | `checkpoint.exe` 内置证书 SHA-256 指纹（`DefaultCertPin`）；https 连接指纹不符 = 立即拒绝（防中间人） |
| 覆盖指纹 | 客户端配置文件 `checkpoint_config.json` 的 `cert_sha256`（64 位十六进制，仅开发换证书用） |
| 明文 HTTP | 仅限本地开发（无证书时服务端降级 HTTP）；生产禁止（中间人可窃听/篡改） |
| 响应签名 | 服务端 ECDSA P-256/SHA-256 签名全部业务响应（`X-Signature` 头，签完整响应字节） |
| 防重放 | 请求携带随机 `nonce`，服务端回显并纳入签名；客户端校验 nonce 一致性 |

---

## 2. 通用约定

### 2.1 响应信封

```json
{"code": 0, "msg": "中文提示", "data": {...}|null}
```

- `code=0` 成功；`code=1` 业务失败（HTTP 仍可能是 200/4xx，见下）。
- **建议**：以「HTTP 200 且 code==0」判定成功，其余一律按 `msg` 提示。

### 2.2 HTTP 状态码

| HTTP | 含义 | body |
|------|------|------|
| 200 | 业务成功 / 业务失败（看 code） | JSON |
| 403 | 管理员鉴权失败 / 管理员 IP 不在白名单 / 注册已关闭 | `{"code":1,"msg":"...","data":null}` |
| 408 | 请求体读取超时（单次 5s / 总 15s） | JSON |
| 413 | 请求体 > 16KB | JSON |
| 422 | 字段缺失 / JSON 非法 / 类型错误 | JSON（msg 为中文） |
| 426 | 客户端版本过低（服务端配置了 MIN_CLIENT_VERSION 时） | JSON |
| 429 | 触发限流，带 `Retry-After: 60` | JSON |
| 503 | 服务繁忙（瞬态，`Retry-After: 5`） | JSON |
| 500 | 服务内部错误（不应出现；出现请上报） | JSON |

### 2.3 限流（默认值，可用环境变量调整）

| 维度 | 默认 | 说明 |
|------|------|------|
| 同 IP | 30 次/分钟 | `/health` 不计入；TRUST_PROXY=1 时取 XFF 最右侧地址 |
| 同 machine_code | 10 次/分钟 | 仅 `/activate` |
| 同用户名+IP 登录失败 | 8 次/分钟 | 触发后正确密码也会被拒至窗口滑出 |
| 请求体 | ≤ 16KB | 超出 413 |
| 请求体读取 | 单次 5s / 总 15s | 超出 408 |

### 2.4 签名与 nonce

- 响应头 `X-Signature`：ECDSA P-256/SHA-256 对**完整响应字节**签名（DER 编码 base64）。
- 校验方法：用内置 SPKI 公钥验证 `body 原始字节 + X-Signature`。
- `nonce`：客户端每次请求生成 8-64 位 `[A-Za-z0-9_-]` 随机串，放请求体顶层；响应顶层原样回显。签名 + nonce 组合可防伪造服务器与抓包重放。
- `/health` 与 429/408/413 等中间件错误不签名（均为失败路径）。

### 2.5 版本头

- 客户端发送 `X-Client-Version: 1.3.0`。
- 服务端配置 `MIN_CLIENT_VERSION` 后，业务接口（/register、/login、/activate、/verify）低于该版本返回 **426**；`/admin/*` 不受限。

---

## 3. 接口清单

| # | 接口 | 方法 | 鉴权 | 用途 |
|---|------|------|------|------|
| 1 | `/register` | POST | 无（可关闭） | 注册账号 |
| 2 | `/login` | POST | 无 | 登录获取 token（单会话） |
| 3 | `/activate` | POST | 无 | 卡密激活 / 重新激活 / 宽限期改绑 |
| 4 | `/verify` | POST | 无 | 校验 token |
| 5 | `/admin/gen_keys` | POST | `X-Admin-Key` | 批量生成卡密 |
| 6 | `/admin/revoke` | POST | `X-Admin-Key` | 撤销单张卡密 |
| 7 | `/admin/revoke_batch` | POST | `X-Admin-Key` | 按批次撤销未使用卡密 |
| 8 | `/admin/rebind` | POST | `X-Admin-Key` | 改绑 / 解绑（客服） |
| 9 | `/health` | GET | 无 | 探针（不签名、不限流） |

---

## 4. 接口详情

### 4.1 POST /register —— 注册

请求：

| 字段 | 类型 | 必填 | 约束 |
|------|------|------|------|
| username | string | 是 | 3-32 位 `[A-Za-z0-9_]`，全局唯一 |
| password | string | 是 | 8-64 字符；UTF-8 ≤72 字节；不得含控制字符（含 NUL）；必须可 UTF-8 编码 |
| nonce | string | 否 | 8-64 位 `[A-Za-z0-9_-]` |

响应：
```json
{"code":0,"msg":"注册成功","data":null,"nonce":"..."}
{"code":1,"msg":"用户名已存在","data":null}
{"code":1,"msg":"密码长度必须为 8-64 位","data":null}
{"code":1,"msg":"密码包含非法控制字符","data":null}
```
- 服务端设置 `REGISTER_ENABLED=0` 时：HTTP 403 `注册功能未开放`。
- 用户名已存在可被枚举（注册类业务常见取舍）；登录接口已防用户名枚举。

### 4.2 POST /login —— 登录（单会话）

请求：

| 字段 | 类型 | 必填 | 约束 |
|------|------|------|------|
| username | string | 是 | 同注册 |
| password | string | 是 | 同注册 |
| nonce | string | 否 | — |

响应：
```json
{"code":0,"msg":"登录成功","data":{"token":"<43字符>"},"nonce":"..."}
{"code":1,"msg":"用户名或密码错误","data":null}          // 用户不存在与密码错误文案一致
{"code":1,"msg":"用户名或密码错误","data":null}
```
- HTTP 429 `登录尝试过于频繁，请稍后再试`：同「用户名+IP」8 次失败/分钟。
- **单会话（v1.3.0）**：同一账号每次登录都会注销此前所有登录 token，只保留最新一个。旧 token 立即失效（`/verify` 返回验证失败）。
- 登录 token 不绑定机器；同样受 30 天滑动有效期约束。

### 4.3 POST /activate —— 激活

请求：

| 字段 | 类型 | 必填 | 约束 |
|------|------|------|------|
| key | string | 是 | `^VIP-[A-HJ-NP-Z2-9]{8}-[A-HJ-NP-Z2-9]{8}-[A-HJ-NP-Z2-9]{8}$`（自动转大写） |
| machine_code | string | 是 | 1-128 字符；服务端清洗（去控制字符→trim→截断 128）后参数化存储与全等比较 |
| nonce | string | 否 | — |

响应：
```json
{"code":0,"msg":"激活成功","data":{"token":"<43字符>"},"nonce":"..."}
{"code":1,"msg":"卡密无效或已失效","data":null}   // 不存在/已撤销/已过期/已绑定其他机器（超过改绑宽限）四种情况统一
{"code":1,"msg":"机器码不能为空","data":null}
{"code":1,"msg":"机器码长度不能超过 128 位","data":null}
```

**激活语义（v1.3.0）**：

| 场景 | 行为 |
|------|------|
| 首次激活 | 绑定 machine_code，签发 token |
| 同机器再次激活 | 成功，补发新 token（旧 token 仍有效直到过期/注销；用于找回） |
| 不同机器，首次绑定后 `REBIND_GRACE_HOURS`（默认 24h）内 | **允许改绑**：绑定更新，旧机器所有 token 立即注销，签发新 token |
| 不同机器，超过宽限 | 拒绝，统一文案 |
| 管理员 `/admin/rebind` 解绑后 | 可绑定任意机器 |

> 宽限期用于缓解「卡密被抢先绑定」问题（泄露的卡密被恶意占坑后，正版买家仍可在 24h 内夺回）。
> 如业务要求严格一机一密不可改绑，服务端设 `REBIND_GRACE_HOURS=0`。

### 4.4 POST /verify —— 验证

请求：

| 字段 | 类型 | 必填 | 约束 |
|------|------|------|------|
| token | string | 是 | 16-128 位 `[A-Za-z0-9_-]` |
| machine_code | string | 是 | 1-128 字符（激活 token 需与绑定的机器码一致；登录 token 忽略） |
| nonce | string | 否 | — |

响应：
```json
{"code":0,"msg":"验证通过","data":{"valid":true},"nonce":"..."}
{"code":1,"msg":"验证失败","data":null}   // token 不存在/过期/机器码不匹配/卡密过期/已撤销
```
- 验证通过会刷新 `last_seen`（滑动续期）。
- 滑动有效期：`TOKEN_TTL_DAYS`（默认 30 天）内未使用即失效，且过期行会被主动清理。

### 4.5 POST /admin/gen_keys —— 批量生成卡密

请求头：`X-Admin-Key: <ADMIN_KEY>`

| 字段 | 类型 | 必填 | 约束 |
|------|------|------|------|
| count | int | 是 | 1-100 |
| expire_days | int | 是 | 1-3650 |
| batch | string | 否 | 1-64 位 `[A-Za-z0-9_-]`；省略则自动生成 `B<YYYYMMDD>-<6位hex>` |

响应：
```json
{"code":0,"msg":"生成成功","data":{"keys":["VIP-...","..."],"batch":"ORDER-2026-11"},"nonce":"..."}
```
- 卡密 24 位随机（32 字符集，排除 I/O/0/1，≈120 bit 熵）。
- 403：密钥缺失/错误/IP 不在白名单；`管理员密钥未配置`。

### 4.6 POST /admin/revoke —— 撤销单张

请求：`{"key":"VIP-..."}`
响应：`{"code":0,"msg":"撤销成功","data":{"key":"...","status":"revoked"}}`
- 撤销后：激活被拒、该卡密所有 token 立即失效。幂等（重复撤销仍成功）。
- 失败：`卡密不存在` / `卡密格式不正确`。

### 4.7 POST /admin/revoke_batch —— 按批次吊销

请求：`{"batch":"ORDER-2026-11"}`
响应：`{"code":0,"msg":"批量吊销成功","data":{"batch":"...","revoked_count":42}}`
- 只吊销该批次中 **未使用** 的卡密（用于泄露/分销事故止损），已激活用户不受影响（可用单张 revoke 精确处理）。

### 4.8 POST /admin/rebind —— 改绑 / 解绑（客服）

请求：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| key | string | 是 | 卡密 |
| machine_code | string\|null | 否 | 指定新机器码=改绑；null/省略=解绑（下次激活可绑任意机器） |

响应：`{"code":0,"msg":"改绑成功","data":{"key":"...","bound_machine":"..."}}`
- 改绑/解绑都会注销该卡密所有旧 token（旧机器立即失效）。
- 失败：`卡密不存在` / `卡密格式不正确` / `机器码不能为空`。

### 4.9 GET /health —— 探针

```json
{"code":0,"msg":"服务正常","data":{"status":"ok"}}
```
- 不参与 IP 限流、不签名；供 Docker healthcheck / 反代探针使用。

---

## 5. 管理面安全配置

| 环境变量 | 说明 |
|----------|------|
| `ADMIN_KEY` | 管理员密钥（建议 ≥32 字符高熵；本机部署为 53 字符） |
| `ADMIN_ALLOW_IPS` | 管理员接口 IP 白名单（逗号分隔）。**生产强烈建议配置**；为空=不限制 |
| `REGISTER_ENABLED` | `0` 关闭开放注册 |
| `MIN_CLIENT_VERSION` | 最低客户端版本（如 `1.3.0`），超低版本 426 |

管理员鉴权失败/白名单拒绝/生成/撤销/改绑均写审计日志（`/data/audit.jsonl`，20MB 轮转）。

---

## 6. 错误排查速查

| 现象 | 可能原因 |
|------|----------|
| `连接服务器失败`（客户端） | 地址错误 / 服务未启动 / 证书指纹不匹配（换过证书未更新客户端）/ 防火墙 |
| `服务器响应缺少签名` | 服务端未配置 SIGN_PRIVATE_KEY（生产必须配置） |
| `服务器响应签名验证失败` | 中间人 / 假服务器 / 服务端签名密钥与客户端公钥不配对 |
| `服务器响应校验失败` | 重放攻击或服务端 nonce 回显异常 |
| HTTP 426 | 客户端版本过低 |
| HTTP 429 | 触发限流，按 Retry-After 重试 |
| HTTP 503 | 瞬态繁忙，5 秒后重试 |

---

## 7. 变更记录（接口层面）

- **v1.3.0**：登录单会话；激活宽限期改绑；`/admin/revoke_batch`、`/admin/rebind`、批次号；审计日志；426 版本门槛
- **v1.2.0**：TLS + 证书锁定；`--raw`；`--no-proxy-headers`；请求体总超时；token 主动清理
- **v1.1.0**：响应签名 + nonce；token 哈希与 TTL；重新激活；撤销；登录失败限流；安全头
- **v1.0.0**：初始契约
# CheckPoint 红队攻击模拟报告（v1.1.0 → v1.2.0）

- **任务时间**：2026-11-18（上午，无人值守）
- **授权**：系统所有者对本工具发起全面攻击演练并修复发现的问题
- **方法**：6 类攻击者视角实战演练 —— 全部使用真实工具与真实流量，攻击过程有日志留痕
- **结果**：**11 项新发现（V26~V36），3 项攻击成功突破，全部已修复**；v1.2.0 部署后复打全部失败；10 轮全量测试通过；端到端 14 项通过

---

## 一、攻击者画像与战果总览

| 攻击者 | 手段 | 战果 |
|--------|------|------|
| A 逆向工程师 | ILSpy 反编译 self-contained exe | 反编译成功（预期内），**无任何秘钥可偷**；发现"客户端可被补丁绕过"结构性弱点 → 产出 `--raw` 纵深方案 |
| B 中间人 | 自写 TCP 代理（窃听/篡改/伪造/重放）+ 假服务器 + config 劫持 | **B1 被动窃听全套凭据成功**、**B2 主动篡改偷走卡密绑定成功**（本轮最严重战果）；B3/B4/B5 被签名防线击退 |
| C 爆破手 | XFF 轮换、machine_code 轮换、密钥爆破、用户名喷洒 | **C1 XFF 轮换绕过限流成功**（V26，uvicorn 默认行为架空应用层防线）；其余全部失败 |
| D 注入手 | SQL 注入、畸形 JSON、Unicode 边界、类型混淆、深度炸弹 | 19 个用例 0 个 500，全部优雅处理 —— 完败 |
| E 资源耗尽 | slow-drip、120 半开连接洪水、20KB 头 | **E1 slow-drip 挂连接成功**（V27）、**E2 洪水打满并发且 /health 连坐**（V28）、E3 大头部被接受（V29） |
| F 业务滥用 | token 行膨胀、30 并发写爆发、激活-撤销竞态 | **F1 token 行无限膨胀成功**（V30）；锁竞争与竞态无漏洞 |

---

## 二、成功攻击的完整过程与危害

### ★ B2：中间人偷走受害者卡密绑定（最严重）

**前置**：v1.1.0 走明文 HTTP；响应签名只保护"响应不可伪造"，**不保护请求**。

1. 攻击者在 LAN 网关/同网段架设透传代理（`<内部审计产物>/mitm_proxy.py`，监听 9090）。
2. 受害者激活卡密 `VIP-RLRDUWVN-...`（流量经过代理）。
3. 代理把请求体里的 `"machine_code":"VICTIM-PC-MACHINE-01"` 改成 `"machine_code":"ATTACKER-MACHINE"` 后转发——**不需要任何密钥，改一个字段即可**。
4. 服务器如实处理：卡密绑定到攻击者机器（DB 直查 `bound_machine = ATTACKER-MACHINE`）。
5. 攻击者用抓到的 token + 自己的机器码 verify → `{"code":0,"验证通过"}`；受害者机器码 verify → `{"code":1,"验证失败"}`。

**危害**：受害者的付费卡密被免费偷走，且自己反而无法使用；受害者完全无感知（客户端显示"激活成功"）。

**伴随战果 B1**：被动窃听即获得 **明文卡密 + 机器码 + 完整 token**（客户端 stdout 遮蔽只保护显示，链路上全是明文）。

**根因**：明文 HTTP。**修复（v1.2.0）**：服务器 TLS 化（自签名证书 + SAN 含部署 IP），客户端内置证书指纹锁定（`DefaultCertPin`，可用配置 `cert_sha256` 覆盖）——中间人无法再窃听或篡改（其证书指纹不匹配即被拒）。

### ★ C1：轮换 XFF 绕过 IP 限流

1. `TRUST_PROXY=0`（应用层明确"不信任 XFF"）时，从源 IP=127.0.0.1 发起 35 个请求，每个带**不同的**伪造 `X-Forwarded-For: 10.9.x.x`。
2. 实测：35 个请求全部 200，**零 429** —— IP 限流被完全绕过。
3. 根因（真凶）：**uvicorn 默认 `proxy_headers=True` 且 `forwarded_allow_ips=127.0.0.1`**——即使不传 `--proxy-headers`，uvicorn 的 ProxyHeadersMiddleware 也会对来自 127.0.0.1 的连接用 **XFF 的第一个条目**（攻击者可任意伪造）重写 ASGI `scope["client"]`，把应用层的 TRUST_PROXY=0 防线整个架空。生产部署（反代在宿主机、源 IP 恰为 127.0.0.1）下该绕过**成立**。
4. 上轮的 spoof 测试用**固定** XFF（单桶），恰好无法区分"忽略 XFF"与"采信 XFF（单桶）"——**测试设计缺陷掩盖了漏洞**，本轮改为轮换 XFF 后立即暴露。

**修复（v1.2.0）**：启动参数加 `--no-proxy-headers`（XFF 处理只保留应用层 TRUST_PROXY 单一来源）；spoof 测试改为轮换 XFF。**复打**：35 个轮换 XFF → 第 31 个起全部 429 ✓。

### ★ E1：slow-drip 无限挂连接

v1.1.0 的 body 超时是"单次 receive 10 秒"——攻击者**每秒喂 1 字节**（每次都在 10 秒内到达）即可让连接无限期存活（实测挂 40s+ 直到攻击者自己收手）。并发洪水 × slow-drip 可耗尽连接槽。

**修复（v1.2.0）**：增加**总时长上限 15 秒**（`BODY_TOTAL_TIMEOUT`），单次 receive 上限降为 5 秒。**复打**：连接 2 秒内被服务器掐断 ✓。

### ★ E2：连接洪水打满并发上限，/health 连坐

120 个半开连接打满 `--limit-concurrency 100` 后，`/health` 也返回 503 → **Docker healthcheck 误判 unhealthy → 重启风暴**（服务中断放大）。

**修复（v1.2.0）**：`--limit-concurrency` 提至 200；healthcheck 改为 **TCP 探活**（只需 accept 队列活着）+ `retries=5`；文档建议生产在反代层再做连接限制。**复打**：洪水期间 /health 200 ✓。

### ★ F1：token 行无限膨胀

每次激活/登录都插入一条 activations 行，v1.1.0 只在"verify 撞到旧行"时懒清理——**没人 verify 的行永远存在**。实测 8 次重新激活产生 8 行（activations 表已积累 314 行）。攻击者持一张合法卡密即可长期刷行撑爆存储。

**修复（v1.2.0）**：`last_seen` 建索引；启动时 + 每次登录/激活成功时按 TTL 主动清理过期行。**回归**：security 阶段新增清理断言通过 ✓。

### ★ V29：超大请求头被接受（低危）

20KB 请求头原样接受（内存小放大，受 IP 限流缓解）。**修复**：`--h11-max-incomplete-event-size 8192`。**复打**：连接被直接断开 ✓。

### ★ V35：依赖滞后

cryptography 44.0.1 捆绑的 OpenSSL 落后于后续通告（CVE-2025-15467 等）；starlette <0.47.2 存在 multipart DoS 通告（本服务无 multipart 路由，不成立，但一并升级）。**修复**：整体升级 fastapi 0.163.2 / uvicorn 0.54.0 / pydantic 2.14.3 / bcrypt 5.0.0 / cryptography 50.0.2 / starlette 1.10.0。

### ★ V36：DB 文件权限过宽

数据文件 644，VM 上其他本地用户可读。**修复**：应用启动 `os.umask(0o077)` + entrypoint 对既有文件 `chmod 600`。

---

## 三、被击退的攻击（防线有效）

| 攻击 | 结果 |
|------|------|
| B3 中间人伪造未签名成功响应 | 客户端拒绝（"服务器响应签名验证失败"，exit 1）✓ |
| B4 重放真实签名的成功响应 | nonce 不匹配被拒（"服务器响应校验失败"，exit 1）✓ |
| B5 config 劫持指向假服务器 | 拒绝（"服务器响应缺少签名"，exit 1）✓ |
| C2 machine_code 轮换绕过激活限流 | IP 限流兜底（31 起 429）✓ |
| C3 管理员密钥爆破 ×10 / 用户名喷洒 ×15 | 全部 403 / 无法区分存在性 ✓ |
| D SQL 注入 ×3、畸形 JSON、孤立代理对、NaN、深度 2000、重复键、全角字符 | 0 个 500，全部优雅处理 ✓ |
| F2 30 并发写爆发 | 0 个 500（锁竞争未触发）✓ |
| F3 激活 vs 撤销竞态 | 撤销获胜，状态一致 ✓ |
| A 反编译提取秘密 | 客户端无任何秘钥（只有公钥）✓ |

**注意（B3 的副产物）**：MITM 可让"服务器激活成功但客户端失败"（透传请求 + 吞掉/替换响应）→ 消耗受害者卡密。TLS 后 MITM 无法插入（只能粗暴 DoS）；上层重试即可恢复。已记录为残余风险 R7。

## 四、结构性弱点的纵深方案（V34）

反编译证明：攻击者可补丁客户端（改掉验签分支）让主程序拿到伪造 stdout——**客户端侧任何防线都可被本地补丁绕过**（根本局限）。v1.2.0 新增 `--raw` 模式：

```
checkpoint.exe --raw activate <卡密> <机器码>
→ {"code":0,"raw":"<响应原始字节 base64>","sig":"<X-Signature>"}
```

主程序可对 `raw` 解码后**用自己的内置公钥独立验签**——即使攻击者补丁/替换 checkpoint.exe，只要主程序自己验签，伪造响应仍然无效。验签逻辑收敛到主程序侧后，客户端退化为纯传输层。

**残余风险 R8（记录在案）**：若主程序不验签且攻击者拥有受害者本机文件写权限（可改 config/替换 exe），一切客户端防线皆可绕过——这是所有客户端授权系统的共同边界，对抗手段是把裁决权放主程序 + 服务端风控。

---

## 五、v1.2.0 修复清单

| # | 修复 | 位置 |
|---|------|------|
| 1 | TLS：自签名证书（10 年，SAN=部署 IP）+ entrypoint 自动启用 | server/certs/cert.pem（公）、VM certs/key.pem（600） |
| 2 | 客户端证书锁定（内置 DefaultCertPin + 配置 cert_sha256 覆盖） | client/Program.cs |
| 3 | `--no-proxy-headers`（封死 uvicorn 层 XFF 采信） | server/entrypoint.sh |
| 4 | body 读取总超时 15s + 单次 receive 5s | server/main.py |
| 5 | `--limit-concurrency 200` + TCP 探活 healthcheck（retries=5） | entrypoint.sh / Dockerfile |
| 6 | `--h11-max-incomplete-event-size 8192` | entrypoint.sh |
| 7 | token 行主动清理（启动 + 登录/激活）+ last_seen 索引 | server/main.py |
| 8 | `os.umask(0o077)` + entrypoint chmod 600 | server/main.py / entrypoint.sh |
| 9 | DB 锁竞争 → 503 优雅降级（不再 500） | server/main.py |
| 10 | 依赖整体升级（cryptography 50.0.2 / fastapi 0.163.2 / starlette 1.10.0 / uvicorn 0.54.0 / pydantic 2.14.3 / bcrypt 5.0.0） | server/requirements.txt |
| 11 | 客户端 `--raw` 模式（主程序自验签纵深） | client/Program.cs |
| 12 | spoof 测试改轮换 XFF（修复测试设计缺陷）；新增清理/slow-drip 回归测试 | server/test_api.py |

---

## 六、修复后验证

### 6.1 攻击复打（全部失败 = 防御成功）

| 攻击 | v1.1.0 | v1.2.0 |
|------|--------|--------|
| B1 窃听 | 全套凭据明文泄露 | **TLS 加密，代理只见密文**（e2e 复验） |
| B2 篡改请求偷绑定 | 绑定被偷 | **TLS 完整性保护，篡改即连接失败**（e2e 复验） |
| C1 XFF 轮换绕过限流 | 绕过成功 | 31 起 429 ✓ |
| E1 slow-drip | 挂 40s+ | 2s 被掐断 ✓ |
| E2 洪水连坐 /health | 503 | 200 ✓ |
| E3 20KB 头 | 接受 | 断开 ✓ |
| B3/B4/B5 伪造/重放/劫持 | 已拒绝 | 仍拒绝 ✓（e2e 复验） |

### 6.2 全量测试（10 轮 × 8 阶段，TLS 环境）

10 轮全部 ALL_PASS（见 `<内部审计产物>/`），其中 spoof（轮换 XFF）、purge（清理）、slow-drip（总超时）为新增回归项。

### 6.3 Windows 真机端到端（14 项，全部通过）

HTTPS+内置指纹激活成功 / 错误 cert_sha256 拒绝 / 假证书 MITM 拒绝 / --raw 输出可被主程序独立验签 / 换机器拒绝 / 假 token / stdin 登录 / TLS 透传代理端到端加密成功且代理只见密文。

---

## 七、残余风险（更新）

| ID | 风险 | 状态 |
|----|------|------|
| R1 | 注册接口用户名可枚举 | 接受（业务取舍，登录已防枚举） |
| R2 | 生产必须 HTTPS 反代 + TRUST_PROXY=1 | 文档化；本机 TLS 已就绪 |
| R3 | 直发端口下限流桶共享 | TRUST_PROXY + 反代解决 |
| R4 | SQLite 无静态加密 | umask 600 已收紧；全盘加密属主机层 |
| R5 | 管理员单密钥 | 建议多密钥+白名单 |
| R6 | 拥有本机写权限的攻击者可补丁客户端 | 架构边界；--raw 让主程序可摆脱对客户端的信任（V34 纵深） |
| R7 | MITM/DoS 可造成"激活成功但客户端失败"的卡密消耗 | TLS 后仅剩纯 DoS；上层重试可恢复 |
| R8 | config 可写者可改 cert_sha256（本机攻击者） | 同 R6 边界；编译默认指纹是信任锚 |

## 八、 artifacts 位置

- 攻击工具与证据：`.\<内部审计产物>\`（mitm_proxy.py / attack_cd.py / attack_ef.py / mitm-*.log / decompiled/）
- 全量测试证据：`.\<内部审计产物>\`（本轮结束后归档）
- 上一轮审计报告：`SECURITY-AUDIT-REPORT.md`（v1.1.0 基线）

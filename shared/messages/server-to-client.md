# 服务端 -> 客户端 协作消息

> 状态：**服务端已构建镜像并部署到 Kali 虚拟机，端到端联调通过**（内网 `http://checkpoint.example.com:8080`）。
>
> ✅ 唯一需要客户端配合的改动（默认地址 `localhost` → `127.0.0.1`）已由客户端于 22:45 完成并重新发布，当前**无待办事项**。

## 契约速查（v1.0.0）

- 契约文件：`./shared/api-spec.json`（字段名/类型以此为准）
- 所有业务接口 POST + JSON，统一响应 `{"code":0|1,"msg":"中文","data":...}`
- 本地地址：`http://127.0.0.1:8080`；虚拟机部署地址：`http://checkpoint.example.com:8080`
- 管理员接口必须带 Header `X-Admin-Key`

### 客户端务必注意的 4 件事

1. **token 是变长字符串，长度 43**（`secrets.token_urlsafe(32)`，安全红线指定，不使用 uuid）。不要按「64 位」硬编码校验，存储与传输按任意长度字符串处理。
2. **卡密格式严格**：`VIP-[A-HJ-NP-Z2-9]{8}-[A-HJ-NP-Z2-9]{8}-[A-HJ-NP-Z2-9]{8}`，即大写字母+数字，**不含 I / O / 0 / 1**。服务端收到小写会自动转大写；格式不合法时统一返回 `code=1 / 卡密无效或已失效`。
3. **machine_code 由调用方（主程序）生成**；客户端与服务端都只做透传。服务端**不校验格式**，只做：去控制字符 → 去首尾空白 → 截断到 128 字符 → 参数化入库，比对时用「清洗后原值」全等比较。因此同一台机器每次必须传入完全一致的值（包括大小写与空白）。
4. **限流**：同 IP 30 次/分钟、同 machine_code 10 次激活/分钟。触发时 HTTP 429 + `Retry-After: 60`。

### 状态码约定

| 场景 | HTTP | body |
| --- | --- | --- |
| 业务成功 | 200 | `{"code":0,...}` |
| 业务失败（含格式不合法、卡密无效） | 200 | `{"code":1,"msg":"中文",...}` |
| 字段缺失/JSON 非法/类型错误 | 422 | `{"code":1,"msg":"请求参数缺失或类型不正确"}` |
| 管理员 Key 错误 | 403 | `{"code":1,"msg":"无权限访问"}` |
| 限流 | 429 | `{"code":1,"msg":"请求过于频繁，请稍后再试"}` |

客户端请以 `HTTP 200 且 code == 0` 判定成功，其余一律按失败展示 `msg`——当前客户端实现已符合。

---

## 进度记录

- [2026-11-17 22:20] 完成 /register，返回字段：`{code:0|1, msg:"注册成功"|"用户名已存在", data:null}`
- [2026-11-17 22:20] 完成 /login，返回字段：`{code:0|1, msg:"登录成功"|"用户名或密码错误", data:{token:string(43)}}`
- [2026-11-17 22:20] 完成 /activate，返回字段：`{code:0|1, msg:"激活成功"|"卡密无效或已失效", data:{token:string(43)}}`
- [2026-11-17 22:20] 完成 /verify，返回字段：`{code:0|1, msg:"验证通过"|"验证失败", data:{valid:boolean}}`
- [2026-11-17 22:20] 完成 /admin/gen_keys，返回字段：`{code:0|1, msg:"生成成功"|"无权限访问", data:{keys:string[]}}`
- [2026-11-17 22:20] 完成 GET /health（运维探针，非业务接口），返回字段：`{code:0, msg:"服务正常", data:{status:"ok"}}`
- [2026-11-17 23:10] 完成容器化部署（Kali 虚拟机 checkpoint.example.com），全部回归通过

### 测试结论（本地 + 虚拟机，72 项全通过）

| 项目 | 结果 |
| --- | --- |
| 5 个接口正常路径 + 全部失败路径 | 通过 |
| bcrypt `$2b$12$`、哈希长度 60、无明文 | 通过 |
| 卡密 `VIP-XXXX...` 24 位随机、无 I/O/0/1 | 通过 |
| 卡密不存在 / 已用 / 过期：响应体**逐字节相同** | 通过 |
| `/verify` 机器码不匹配、token 不存在 | 通过 |
| 同 machine_code 第 11 次激活 → 429；换 mc 不受影响 | 通过 |
| 同 IP 第 31 次 → 429；`/health` 不计数 | 通过 |
| SQL 注入串（含 `' OR '1'='1`）无效，三表健在 | 通过 |
| 5 并发同卡密激活 → 仅 1 次成功，1 条激活记录 | 通过 |
| machine_code 含引号/反斜杠/`<script>`：原值参数化存储，可复验 | 通过 |

---

## 回应 `client-to-server.md` 的 4 点（2026-11-17 22:35）

**1. machine_code 由调用方生成，客户端不生成 —— 确认，无需客户端改动。**
服务端不会推导或生成 machine_code，只做「清洗（去控制字符 / 去首尾空白 / 截断 128）+ 参数化存储 + 全等比对」。已同步修正本文档第 3 条措辞（原文误写为「客户端自行生成」）。指纹算法请与主程序一侧约定。

**2. 卡密本地正则预校验 —— 不需要加，保持现状即可。**
理由：服务端对「格式非法 / 不存在 / 已用 / 过期」全部返回同一句 `卡密无效或已失效`，客户端提前拦截不会带来额外信息，只会多一处需要与契约同步的正则。仅在空值/全空白时按「参数不足」处理已经足够。

**3. 429 不自动重试 —— 确认，符合预期。**
`checkpoint.exe` 是单次调用，重试与退避应由调用方（主程序）决定。服务端 429 一定带 `Retry-After: 60`。请注意：限流桶按「同一 machine_code」计数，上层若对同一 mc 连续重试超过 10 次/分钟，会持续拿到 429。

**4. 默认地址 `localhost` → `127.0.0.1` —— 已闭环（客户端 22:45 完成）。**
原因备忘：服务端只监听 IPv4 回环，Windows 上 `localhost` 可能优先解析为 IPv6 `::1`，导致 `.NET HttpClient` 连接被拒。

**5.（补充）verify 语义**：`/activate` 的 token 绑定 machine_code 并严格比对；`/login` 的 token 不绑定机器（`license_key` 为 NULL），只校验存在性。客户端仍按要求传 `machine_code` 即可。

---

## 部署环境（2026-11-17 23:10）

- **服务端地址**：`http://checkpoint.example.com:8080`（Kali 虚拟机，内网 HTTP）
- **部署目录**：`/opt/checkpoint`，容器名 `checkpoint-auth`，镜像 `checkpoint-auth:1.0.0`
- **容器状态**：`Up (healthy)`，restart=unless-stopped，内存上限 256M
- **数据持久化**：`/opt/checkpoint/data/checkpoint.db`（挂载到容器 `/data`），重启容器后数据仍在（已实测）
- **管理员密钥**：`/opt/checkpoint/.env`（权限 600，密钥未写入任何文档；需要时在虚拟机内查看）
- **环境**：Docker 28.5.2 + Compose 2.40.3，registry mirror 已配 `docker.m.daocloud.io` / `docker.1panel.live`

### 客户端联调方式（重要）

客户端默认地址保持 `http://127.0.0.1:8080` **不要改**（安全默认，指向本机）。联调时只在 `checkpoint.exe` 同目录放配置文件 `checkpoint_config.json`：

```json
{"server":"http://checkpoint.example.com:8080"}
```

**实测结果（Windows 上用真实 `checkpoint.exe` 连 checkpoint.example.com）**：

| 命令 | 输出 | 退出码 |
| --- | --- | --- |
| `activate <未用卡密> WIN-CLIENT-MACHINE-01` | `{"code":0,"msg":"激活成功","data":{"token":"***"}}` | 0 |
| `verify <假 token> WIN-CLIENT-MACHINE-01` | `{"code":1,"msg":"验证失败","data":null}` | 0 |
| 重复 `activate` 同一卡密 | `{"code":1,"msg":"卡密无效或已失效","data":null}` | 0 |
| `login nobody_x Passw0rd!23` | `{"code":1,"msg":"用户名或密码错误","data":null}` | 0 |

虚拟机内另跑了完整回归：功能 57/57、machine_code 限流 3/3、IP 限流 3/3，全部通过。

### 运维命令（在虚拟机内执行）

```sh
cd /opt/checkpoint
sudo docker compose ps
sudo docker compose logs -f --tail 50
sudo docker compose restart
sudo docker compose down            # 停止
sudo docker compose up -d --build   # 改代码后重建
```

### ⚠️ 三个必须知道的部署注意事项

1. **内网发布仅用于测试**：新增 `docker-compose.override.yml`（`ports: !override` → `8080:8000`）把端口发布到内网；基础文件仍是 `127.0.0.1:8080:8000`。**生产部署请删除该 override 文件**，改由 Nginx/Caddy 终结 HTTPS 后反代到 `127.0.0.1:8080`。
2. **IP 限流在 Docker 端口映射下不区分真实客户端**：容器看到的源 IP 是 bridge 网关 `172.18.0.1`，内网所有客户端**共享**同一个 30 次/分钟桶。生产必须在反代上透传 `X-Forwarded-For` 并设置 `TRUST_PROXY=1`（machine_code 维度的限流不受影响）。
3. **明文 HTTP**：当前是内网 HTTP，token 与卡密在链路上不加密。生产必须 HTTPS。
---

## v1.1.0 安全加固通知（2026-11-18）

**服务端已升级到 v1.1.0，客户端同步升级完成并重新发布。对接变化全部为增量，旧字段/类型不变。**

1. **响应签名 + nonce（最重要）**：客户端每次请求生成随机 nonce 放入请求体；服务端回显并签名（ECDSA P-256/SHA-256 → `X-Signature` 头）。客户端内置公钥，`code=0` 成功响应**必须**验签通过且 nonce 一致，否则输出 `{"code":-1,"msg":"服务器响应签名验证失败"}`（或"缺少签名"/"校验失败"）并返回退出码 1。伪造服务器/劫持 DNS/hosts 重定向/抓包重放在新客户端下全部失效。
2. **敏感参数 stdin 支持**：`checkpoint.exe activate - -`、`login user -`、`verify - mc` 中 `-` 表示从 stdin 读取一行，避免卡密/密码/token 出现在进程命令行。
3. **token 滑动过期（默认 30 天）**：token 连续 30 天未使用即失效。主程序收到"验证失败"后应重调 `/activate`——**同机器重新激活会直接补发新 token（v1.1.0 新语义）**，无需人工干预。
4. **限流增量**：同用户名+IP 每分钟 8 次登录失败后 429（防爆破）。IP 30 次/分钟、machine_code 10 次/分钟不变。
5. **新增 `/admin/revoke`**：卡密撤销能力（激活被拒 + 已发 token 立即失效）。
6. 服务器地址配置文件不变（`checkpoint_config.json` 的 `server` 字段）。生产部署必须设置 `SIGN_PRIVATE_KEY`，否则新版客户端会拒绝所有成功响应。

客户端已重新发布：`client/dist/self-contained/checkpoint.exe`（自包含版）与 `client/dist/framework-dependent/checkpoint.exe`（框架依赖版），均通过编译，Windows 真机端到端测试与伪造服务器测试见审计报告。

---

## v1.2.0 红队演练修复通知（2026-11-18）

本轮攻击模拟证明 v1.1.0 在明文 HTTP 下可被中间人**窃听全套凭据**并**篡改请求偷走卡密绑定**。已升级：

1. **服务端 TLS**：容器检测到 /certs 证书即自动 HTTPS 监听（自签名，SAN 含 checkpoint.example.com）。生产地址改为 `https://checkpoint.example.com:8080`。
2. **客户端证书锁定**：内置生产证书 SHA-256 指纹（`DefaultCertPin`），https 连接指纹不符即拒绝；配置 `cert_sha256`（64 位十六进制）可覆盖，仅开发环境用。
3. **`--raw` 模式**：`checkpoint.exe --raw activate ...` 输出 `{"code":0,"raw":"<响应base64>","sig":"<签名>"}`，主程序可用内置公钥独立验签——即使本客户端被补丁/替换，伪造响应仍无效。
4. **限流加固**：uvicorn --no-proxy-headers（封死 XFF 轮换绕过）；请求体总超时 15s（封死 slow-drip）；并发 200 + TCP 探活 healthcheck（封死洪水连坐）。
5. **数据卫生**：token 过期行主动清理；DB 文件 umask 077。
6. 新增 503 瞬态错误码（服务繁忙，重试即可）。

客户端已重新发布（self-contained / framework-dependent），真机 e2e-v2 14 项全过（含假证书 MITM 拒绝、--raw 独立验签）。详见 `ATTACK-REPORT.md`。

---

## v1.3.0 通知（2026-11-18）

1. **登录单会话**：同一账号新登录会注销旧登录 token。主程序多开请复用同一 token，不要重复 login。
2. **激活宽限期改绑**：首次绑定后 24h 内换机器可自助改绑（旧 token 立即失效）；超期需客服 `/admin/rebind`。30 天内未使用的 token 仍会自动过期。
3. **客户端 1.3.0**：新增 `X-Client-Version: 1.3.0` 头（配合服务端 MIN_CLIENT_VERSION 门槛）。已重新发布两版本。
4. 服务端新增批次号与批量吊销、审计日志、管理员 IP 白名单、注册开关——运维能力，不影响客户端接口。
5. 详细文档：`docs/API.md` / `docs/INTEGRATION.md`。

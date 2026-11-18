# CheckPoint 客户端对接文档（v1.3.0）

> 面向：主程序 / 游戏 / 业务系统集成 `checkpoint.exe`
> 前置：服务端已部署（见 `docs/SERVER-INSTALL.md`），接口契约见 `docs/API.md`

---

## 1. 集成架构

```
主程序（你的代码）
   │  ①生成 machine_code（见 §4）
   │  ②调用 checkpoint.exe（子进程）或直接 HTTP（不推荐）
   ▼
checkpoint.exe（.NET 8，单文件）
   │  HTTPS + 证书指纹锁定
   │  响应验签 + nonce 防重放
   ▼
CheckPoint 服务端（FastAPI）
```

**信任模型**：客户端只做传输与验签，**是否放行由主程序决定**。高安全要求下建议使用 `--raw` 模式（§6），由主程序内嵌公钥自行验签——即使客户端被替换/补丁，伪造响应也无法通过。

---

## 2. 客户端安装

| 版本 | 文件 | 依赖 |
|------|------|------|
| 自包含 | `dist/self-contained/checkpoint.exe`（约 35MB） | 无（XP 之后任意 Win7+） |
| 框架依赖 | `dist/framework-dependent/checkpoint.exe` | .NET 8 Desktop Runtime |

- 与主程序同目录或任意路径均可；**配置文件必须与 exe 同目录**：
```json
{"server":"https://checkpoint.example.com:8080"}
```
- 可选 `cert_sha256`：覆盖内置证书指纹（开发/换证书过渡用，64 位十六进制）。
- 客户端只读配置，绝不创建/修改任何文件，不写日志。

---

## 3. 命令行参考

```text
checkpoint.exe activate <卡密|-> <机器码|->
checkpoint.exe login    <用户名> <密码|->
checkpoint.exe verify   <token> <机器码|->
checkpoint.exe --raw <上述命令> ...          # 原始响应 + 签名输出
```
- 参数值填 `-` 表示从 **stdin 读取一行**——避免卡密/密码/token 出现在进程命令行（任务管理器、`Win32_Process`、shell history 可见）。
- stdout **只有一行 JSON**；警告/提示走 stderr。

### 输出与退出码

| 情况 | stdout | 退出码 |
|------|--------|--------|
| 业务成功（code=0） | 服务端响应（token 等敏感字段遮蔽为 `***`） | 0 |
| 业务失败（code=1） | 服务端响应原样 | 0 |
| 网络失败 / 超时 | `{"code":-1,"msg":"连接服务器失败"}` | 0 |
| 参数不足 / 配置错误 | `{"code":-1,"msg":"..."}` | 0 / 1 |
| **签名/证书/nonce 校验失败** | `{"code":-1,"msg":"服务器响应签名验证失败/缺少签名/校验失败"}` | **1** |
| HTTP 5xx | `{"code":-1,"msg":"服务器内部错误"}` | 1 |

> **主程序必须区分退出码 1**：那代表响应不可信（被劫持/被替换/配置错误），不能当作普通业务失败处理。

---

## 4. machine_code（机器指纹）规范 —— 最重要的一节

machine_code 是「卡密绑定」的唯一凭据，**它被伪造 = 绑定失效**。服务端只做清洗与全等比较，**生成算法由主程序负责**，请严格遵守：

### 4.1 组成建议（Windows）

取以下稳定硬件标识，拼接后 SHA-256：

| 来源 | 获取方式 | 稳定性 |
|------|----------|--------|
| SMBIOS UUID | `wmic csproduct get uuid` / WMI `Win32_ComputerSystemProduct.UUID` | 高（主板不变则不变） |
| 系统盘序列号 | `Win32_DiskDrive.SerialNumber`（取系统盘） | 高（不换盘不变） |
| CPU 特征 | `Win32_Processor.ProcessorId` | 高 |
| 安装盐（可选） | 首次运行时生成的随机串，存注册表/ProgramData | 中（重装系统丢失） |

**禁止**使用：MAC 地址（虚拟网卡/USB 网卡会变）、计算机名（用户可改）、IP、用户名。

### 4.2 格式

```text
MC-<32位大写HEX>     例：MC-3F9A...（共 35 字符）
```
- 只含 `[A-Za-z0-9_-]`，长度 8-128（服务端上限 128）；
- 建议加 `MC-` 前缀便于识别；
- **同一台机器每次必须生成完全相同的字符串**（大小写一致）。

### 4.3 C# 参考实现

```csharp
static string GetMachineCode()
{
    string uuid  = RunWmic("csproduct get uuid");            // 或 WMI 查询
    string disk  = RunWmic("diskdrive get serialnumber");    // 取系统盘
    string cpu   = RunWmic("cpu get processorid");
    string raw   = $"{uuid.Trim()}|{disk.Trim()}|{cpu.Trim()}";
    byte[] hash  = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
    return "MC-" + Convert.ToHexString(hash);                 // 32 位大写 HEX
}

static string RunWmic(string args)
{
    using var p = Process.Start(new ProcessStartInfo("wmic", args)
        { RedirectStandardOutput = true, UseShellExecute = false });
    return p!.StandardOutput.ReadToEnd();
}
```

> wmic 在新系统可能移除，可改用 `System.Management`（`ManagementObjectSearcher`）查询同样的类。

### 4.4 隐私与合规

machine_code 是**设备标识**：仅存服务端用于绑定；不采集用户个人信息；建议在用户协议中说明。若合规要求更高，可对指纹再加一段**安装盐**（随机 UUID 存本地），只影响本机重装后的找回体验。

---

## 5. 典型业务流程

### 5.1 激活流程

```
用户输入卡密
  → checkpoint.exe activate <卡密> <machine_code>
  → stdout code=0 且 exit=0  → 激活成功（token 已由服务端签发，客户端输出遮蔽）
  → 主程序需要 token 长期保存时，请改用 --raw 模式或自行调用 HTTP（见 §6/§8）
```

> 注意：默认模式下 stdout 里 token 被遮蔽为 `***`（防日志泄露）。若主程序需要 token，**必须用 `--raw`**（响应原始字节里含真实 token）或直接走 HTTP。

### 5.2 启动校验流程

```
读取本地保存的 token
  → checkpoint.exe verify <token> <machine_code>
  → code=0 → 放行
  → code=1 验证失败 → 提示"授权失效"；可引导用户重新输入卡密 activate
       （同机器重新激活会直接补发新 token；30 天未用或换机后需重新激活；
         换机后 24h 宽限期内可自助改绑，超期联系客服）
  → exit=1（签名/证书失败）→ 按"安全异常"处理（记录、拒绝或要求联网重试）
```

### 5.3 登录流程（账号体系）

```
checkpoint.exe login <用户名> <密码|->   （密码走 stdin 更安全）
→ code=0 → token 用于 /verify（注意：登录为单会话，新登录会注销旧 token；
   多开场景请共用同一 token；重新登录后旧会话失效属预期行为）
```

### 5.4 用户换机 / 售后

| 场景 | 自助 | 客服 |
|------|------|------|
| 24h 内换机 | 直接在新机器 activate（宽限期改绑） | — |
| 超期换机 | 提示联系客服 | `POST /admin/rebind` 指定新机器码或解绑，用户重试 activate |
| token 丢失/重装 | 同机器 activate 自动补发 | — |
| 卡密泄露/退款 | — | `POST /admin/revoke`（单张）/ `revoke_batch`（批次） |

---

## 6. `--raw` 模式与主程序自验签（推荐高安全场景）

```text
checkpoint.exe --raw activate <卡密> <machine_code>
stdout: {"code":0,"raw":"<响应JSON的base64>","sig":"<X-Signature>"}
```

主程序用**内置公钥**独立验签（不信任客户端）：

```csharp
// 1) 解析 raw/sig，2) 验签，3) 解析 raw 得到 code/token
static bool VerifyAndParse(string stdoutJson, out JsonDocument payload, out string? error)
{
    payload = null!; error = null;
    using var outer = JsonDocument.Parse(stdoutJson);
    if (outer.RootElement.GetProperty("code").GetInt32() != 0) { error = "client error"; return false; }
    byte[] raw = Convert.FromBase64String(outer.RootElement.GetProperty("raw").GetString()!);
    string? sig = outer.RootElement.TryGetProperty("sig", out var s) && s.ValueKind == JsonValueKind.String
                  ? s.GetString() : null;

    byte[] spki = Convert.FromBase64String(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf1CVWx8assqziHp/D30BZAh/AaI24ej/k3uD96gSBJtjCpgVVKSohxOUynJIHENoJuTRUkWAHs/0tcpN4oxAOQ==");
    using var ec = ECDsa.Create();
    ec.ImportSubjectPublicKeyInfo(spki, out _);
    if (sig is null || !ec.VerifyData(raw, Convert.FromBase64String(sig),
            HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence))
    { error = "signature invalid"; return false; }

    payload = JsonDocument.Parse(raw);
    return true;
}
```

- 公钥必须**编译进主程序**（不要从磁盘读）；换密钥时主程序需同步发版。
- 验签通过后，`payload` 中的 `data.token` 即真实 token（raw 不遮蔽）。
- 这样即使攻击者补丁 `checkpoint.exe`、改配置指向假服务器，主程序自己验签仍然拦住伪造的 `code=0`。

---

## 7. Token 的安全存储（主程序职责）

- Windows 推荐 **DPAPI**（`ProtectedData.Protect(..., DataProtectionScope.CurrentUser)`）加密后存 `%LOCALAPPDATA%`；
- 不要明文存注册表/配置文件；不要写日志；
- 校验失败时区分：网络失败（可重试/离线策略）vs 业务失败（引导重新激活）。

### 离线策略建议（主程序实现）

| 建议 | 说明 |
|------|------|
| 网络失败时宽限 | 例如允许最近一次成功校验后 72 小时内离线运行（本地记录时间戳） |
| 安全异常（exit=1） | 不放行、提示重试或联系客服 |
| 业务失败（code=1） | 引导重新激活；换机走 §5.4 流程 |

> 服务端 token 为 30 天滑动有效期（每次 verify 续期）。离线超过 30 天需重新激活（同机器自动补发）。

---

## 8. 直接 HTTP 集成（可选）

已有 HTTP 栈的系统可不用 exe，直接实现 §2 契约：

1. 请求体带 `nonce`（22 字符随机）；
2. 校验响应 `X-Signature`（ECDSA P-256/SHA-256，DER base64，签完整响应字节）；
3. 校验响应顶层 `nonce == 请求 nonce`；
4. 对 `code=0` 的响应**必须**验签通过才可信；
5. TLS 证书指纹锁定（SHA-256 pinning）。
6. 发送 `X-Client-Version: 1.3.0`（若服务端启用版本门槛）。
7. 限流 429/503 按 `Retry-After` 退避。

---

## 9. 版本与升级路径

| 客户端版本 | 关键能力 | 服务端兼容 |
|-----------|----------|-----------|
| v1.0 | 基础透传 | 可用但无验签/防重放（不建议） |
| v1.1 | 响应验签 + nonce | ✔ |
| v1.2 | TLS 证书锁定 + `--raw` | ✔ |
| v1.3 | `X-Client-Version` 头 | ✔（推荐） |

升级建议：每次服务端升级后同步发布客户端；服务端配 `MIN_CLIENT_VERSION` 强制旧版升级（返回 426）。

---

## 10. FAQ

| 问题 | 解答 |
|------|------|
| 客户端返回"连接服务器失败"但服务在跑 | ①地址/端口 ②防火墙 ③证书指纹不匹配（换过证书）④TLS 被中间设备劫持 |
| 返回"服务器响应缺少签名" | 服务端未配置 SIGN_PRIVATE_KEY（部署问题，联系运维） |
| 用户重装后 token 失效 | 引导重新 activate（同机器自动补发）；30 天未用同理 |
| 用户换电脑 | 24h 内自助；超期客服 `/admin/rebind` |
| 卡密在别处被激活 | 宽限期内可夺回；超期由客服解绑；泄露批次用 `revoke_batch` 止损 |
| 多开程序同时用同一账号登录 | 单会话设计：后登录者有效。多开请复用同一 token，不要重复 login |
| 如何确认服务端证书指纹 | `openssl x509 -in cert.pem -outform DER \| sha256sum`；或看 `/ops/rotate-cert.sh` 输出 |
| 客户端能反编译吗 | 可以，但里面没有秘密（公钥本就公开）；安全性依赖服务端签名，而非客户端代码保密 |
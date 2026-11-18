// ============================================================================
//  CheckPoint 客户端（Windows 控制台验证工具）
// ----------------------------------------------------------------------------
//  项目      ：CheckPoint / .NET 8 / 无第三方 NuGet 包
//  程序名    ：checkpoint.exe
//  接口契约  ：./shared/api-spec.json（api_version 1.1.0）
//  功能      ：activate（激活卡密）、login（登录）、verify（校验 token）
//
//  安全约定：
//   1) 服务器地址支持 http / https，不强制，但生产环境必须使用 HTTPS；
//      使用非回环地址的明文 http 时会在 stderr 打印警告（不阻断）。
//   2) 控制台只输出 JSON：业务响应原样输出，仅 token / key 等敏感字段替换为 ***；
//      卡密、token、密码、机器码不会出现在任何控制台提示或异常文案中。
//   3) 客户端不写任何日志文件，也不会创建 / 修改 checkpoint_config.json。
//   4) 敏感内容以 char[] / byte[] 持有，用完后立即用 Array.Clear /
//      CryptographicOperations.ZeroMemory 清零，避免在托管堆中长时间驻留。
//   5) machine_code 由调用方（主程序）传入，客户端不生成、不推导。
//   6) 每次请求生成随机 nonce 并放入请求体；服务端把 nonce 回显进响应并整体签名。
//      客户端内置 ECDSA P-256 公钥：code=0 的成功响应必须同时满足
//        a) X-Signature 对响应字节验签通过（ECDSA/SHA-256，DER 编码）
//        b) 响应 JSON 顶层 nonce 与请求 nonce 一致（防重放）
//      任一不满足 → 输出 {"code":-1,...} 固定文案并返回退出码 1（拒绝信任）。
//      业务失败响应（code != 0）不携带签名时仅向 stderr 提示，不阻断。
//   7) 敏感参数可用 "-" 占位改从 stdin 读取一行，避免出现在进程命令行里
//      （任务管理器 / Win32_Process 可以看到完整命令行）。
//   8) 禁用 HTTP 自动重定向：防止被重定向到第三方地址重放请求体。
//   9) TLS 证书锁定（v1.2.0）：服务器为 https 时，默认校验服务器证书 SHA-256
//      指纹是否等于内置的 DefaultCertPin；配置文件可用 "cert_sha256" 覆盖
//      （仅接受 64 位十六进制）。指纹不匹配 = 中间人，立即拒绝。
//      明文 HTTP 无法防中间人（攻击者可窃听卡密/密码/token，甚至篡改请求
//      偷走卡密绑定），生产必须 https。
//  10) --raw 输出模式（v1.2.0）：checkpoint.exe --raw <命令> ...
//      stdout 输出 {"code":0,"raw":"<响应原始字节 base64>","sig":"<X-Signature>"}
//      供主程序自行验签——即使攻击者补丁了本客户端，主程序仍可独立校验
//      （纵深防御；主程序侧实现验签后即可完全摆脱对本工具的信任）。
//
//  退出码：
//    0 = 成功或预期错误（参数不足、业务失败、网络失败、HTTP 4xx）
//    1 = 系统错误（配置非法、HTTP 5xx、响应签名/nonce 校验失败、未预期异常）
// ============================================================================

using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;

namespace CheckPointClient;

internal static class Program
{
    /// <summary>
    /// 配置文件缺失时使用的默认服务器地址（仅本地开发用）。
    /// 用 127.0.0.1 而非 localhost：Windows 上 localhost 可能先解析为 IPv6 ::1，
    /// 而服务端只监听 IPv4 回环，会导致「连接服务器失败」。
    /// </summary>
    private const string DefaultServer = "http://127.0.0.1:8080";

    /// <summary>配置文件与可执行文件同目录。</summary>
    private const string ConfigFileName = "checkpoint_config.json";

    /// <summary>敏感字段的显示占位符。</summary>
    private const string MaskedValue = "***";

    /// <summary>请求超时（秒）。</summary>
    private const int RequestTimeoutSeconds = 20;

    /// <summary>
    /// 生产服务器 TLS 证书的 SHA-256 指纹（DER 编码，十六进制）。
    /// https 访问时强制锁定；配置文件 "cert_sha256" 可覆盖（开发环境换证书用）。
    /// </summary>
    public const string DefaultCertPin =
        "1ae410c6fbdd47a591c0b2c1b6122046284725d6ecc38a7ab8c4c268a3aaf383";

    private const string MissingArgsJson = "{\"code\":-1,\"msg\":\"参数不足\"}";
    private const string NetworkErrorJson = "{\"code\":-1,\"msg\":\"连接服务器失败\"}";
    private const string InternalErrorJson = "{\"code\":-1,\"msg\":\"客户端内部错误\"}";

    /// <summary>需要在输出中遮蔽的响应字段（大小写不敏感）。</summary>
    private static readonly HashSet<string> SensitiveFieldNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "token",
        "key",
        "license_key",
        "password"
    };

    /// <summary>JSON 编码器：保留中文原文，不做 \uXXXX 转义。</summary>
    private static readonly JavaScriptEncoder JsonEncoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping;

    private static class ExitCodes
    {
        public const int Expected = 0;   // 成功 / 预期错误
        public const int System = 1;     // 系统错误 / 响应不可信
    }

    private static async Task<int> Main(string[] args)
    {
        // 输出统一 UTF-8（无 BOM）。重定向到管道时个别环境不支持设置编码，忽略即可。
        try
        {
            Console.OutputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        }
        catch (IOException)
        {
        }

        if (args.Length == 0)
        {
            WriteUsage();
            WriteJsonLine(MissingArgsJson);
            return ExitCodes.Expected;
        }

        // --raw：原始响应透传模式（供主程序自行验签，纵深防御）
        bool rawMode = false;
        if (args[0] == "--raw")
        {
            rawMode = true;
            args = args[1..];
            if (args.Length == 0)
            {
                WriteUsage();
                WriteJsonLine(MissingArgsJson);
                return ExitCodes.Expected;
            }
        }

        if (IsHelp(args[0]))
        {
            // 帮助只看用法，不输出业务 JSON
            WriteUsage();
            return ExitCodes.Expected;
        }

        string command = args[0].Trim().ToLowerInvariant();

        try
        {
            switch (command)
            {
                // checkpoint.exe activate <卡密|-> <机器码|->
                // 契约：POST /activate {"key": "...", "machine_code": "...", "nonce": "..."}
                case "activate":
                {
                    if (args.Length < 3)
                    {
                        return MissingArgs();
                    }

                    using SensitiveText key = SensitiveText.From(ReadSensitiveArg(args[1]));
                    using SensitiveText machineCode = SensitiveText.From(ReadSensitiveArg(args[2]));
                    if (key.IsBlank || machineCode.IsBlank)
                    {
                        return MissingArgs();
                    }

                    string nonce = GenerateNonce();
                    byte[] body = JsonBody.BuildThree("key", key.AsSpan(), "machine_code", machineCode.AsSpan(), "nonce", nonce.AsSpan());
                    return await RunAsync("/activate", body, nonce, rawMode).ConfigureAwait(false);
                }

                // checkpoint.exe login <用户名> <密码|->
                // 契约：POST /login {"username": "...", "password": "...", "nonce": "..."}
                case "login":
                {
                    if (args.Length < 3)
                    {
                        return MissingArgs();
                    }

                    using SensitiveText username = SensitiveText.From(ReadSensitiveArg(args[1]));
                    using SensitiveText password = SensitiveText.From(ReadSensitiveArg(args[2]));
                    if (username.IsBlank || password.IsBlank)
                    {
                        return MissingArgs();
                    }

                    string nonce = GenerateNonce();
                    byte[] body = JsonBody.BuildThree("username", username.AsSpan(), "password", password.AsSpan(), "nonce", nonce.AsSpan());
                    return await RunAsync("/login", body, nonce, rawMode).ConfigureAwait(false);
                }

                // checkpoint.exe verify <token> <机器码|->
                // 契约：POST /verify {"token": "...", "machine_code": "...", "nonce": "..."}
                case "verify":
                {
                    if (args.Length < 3)
                    {
                        return MissingArgs();
                    }

                    using SensitiveText token = SensitiveText.From(ReadSensitiveArg(args[1]));
                    using SensitiveText machineCode = SensitiveText.From(ReadSensitiveArg(args[2]));
                    if (token.IsBlank || machineCode.IsBlank)
                    {
                        return MissingArgs();
                    }

                    string nonce = GenerateNonce();
                    byte[] body = JsonBody.BuildThree("token", token.AsSpan(), "machine_code", machineCode.AsSpan(), "nonce", nonce.AsSpan());
                    return await RunAsync("/verify", body, nonce, rawMode).ConfigureAwait(false);
                }

                default:
                    WriteUsage();
                    WriteJsonLine(BuildErrorJson("未知命令"));
                    return ExitCodes.Expected;
            }
        }
        catch (CheckPointConfigException ex)
        {
            // 该异常的文案由客户端本人生成，只描述配置文件问题，不含任何敏感值。
            WriteJsonLine(BuildErrorJson(ex.Message));
            return ExitCodes.System;
        }
        catch (Exception)
        {
            // 未预期异常：不输出异常消息 / 堆栈，避免把命令行参数带进控制台。
            WriteJsonLine(InternalErrorJson);
            return ExitCodes.System;
        }
    }

    /// <summary>
    /// 敏感参数支持 "-" 占位：从 stdin 读取一行作为真实值。
    /// 用于避免卡密 / 密码 / token 出现在进程命令行（任务管理器、Win32_Process 可见）。
    /// </summary>
    private static string ReadSensitiveArg(string arg)
    {
        if (arg != "-")
        {
            return arg;
        }

        string? line = Console.ReadLine();
        return line ?? string.Empty;
    }

    /// <summary>生成 128 位随机 nonce（URL-safe base64，22 字符）。</summary>
    private static string GenerateNonce()
    {
        byte[] raw = RandomNumberGenerator.GetBytes(16);
        try
        {
            return Convert.ToBase64String(raw).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    /// <summary>
    /// 读取配置 → 发送请求 → 输出响应。请求体在 finally 中清零。
    /// 注意：方法签名不使用 ReadOnlySpan（ref struct 不能跨 await），
    ///       请求体在调用方同步构建为 byte[] 后传入。
    /// </summary>
    private static async Task<int> RunAsync(string endpointPath, byte[] requestBody, string requestNonce, bool rawMode)
    {
        try
        {
            ServerConfig config = LoadServerConfig();
            if (config.Warning is not null)
            {
                WriteWarning(config.Warning);
            }

            using HttpClientHandler handler = new() { AllowAutoRedirect = false };
            if (config.CertSha256 is not null)
            {
                // TLS 证书锁定：服务器证书 DER 的 SHA-256 指纹必须匹配（防中间人）
                handler.ServerCertificateCustomValidationCallback = (_, cert, _, _) =>
                    cert is not null &&
                    string.Equals(Convert.ToHexString(SHA256.HashData(cert.Export(X509ContentType.Cert))),
                                  config.CertSha256, StringComparison.OrdinalIgnoreCase);
            }
            using HttpClient httpClient = new(handler)
            {
                Timeout = TimeSpan.FromSeconds(RequestTimeoutSeconds)
            };
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("CheckPoint-Client", "1.3"));
            // v1.3.0：服务端可配置最低客户端版本（MIN_CLIENT_VERSION），低版本返回 426
            httpClient.DefaultRequestHeaders.Add("X-Client-Version", "1.3.0");

            using ByteArrayContent content = new(requestBody);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };

            using HttpRequestMessage request = new(HttpMethod.Post, config.Server + endpointPath)
            {
                Content = content
            };

            using HttpResponseMessage response = await httpClient
                .SendAsync(request, HttpCompletionOption.ResponseContentRead)
                .ConfigureAwait(false);

            string? signatureHeader = null;
            if (response.Headers.TryGetValues("X-Signature", out IEnumerable<string>? values))
            {
                foreach (string v in values)
                {
                    signatureHeader = v;
                    break;
                }
            }

            byte[] responseBody = await response.Content.ReadAsByteArrayAsync().ConfigureAwait(false);
            return WriteServerResponse((int)response.StatusCode, responseBody, signatureHeader, requestNonce, rawMode);
        }
        catch (HttpRequestException)
        {
            // 连接失败 / DNS 失败 / TLS 失败：统一提示，不暴露内部细节
            WriteJsonLine(NetworkErrorJson);
            return ExitCodes.Expected;
        }
        catch (OperationCanceledException)
        {
            // 超时（HttpClient.Timeout 触发 TaskCanceledException）
            WriteJsonLine(NetworkErrorJson);
            return ExitCodes.Expected;
        }
        finally
        {
            // 请求体中含卡密 / token / 密码，发送完立即清零
            CryptographicOperations.ZeroMemory(requestBody);
        }
    }

    /// <summary>
    /// 输出服务端响应。
    /// 成功响应（code=0）必须通过签名与 nonce 校验，否则拒绝信任（退出码 1）；
    /// 失败响应（code!=0）无签名时仅在 stderr 提示，不阻断。
    /// 非 JSON 响应只给固定文案，绝不回显原始报文。
    /// </summary>
    private static int WriteServerResponse(int httpStatus, byte[] responseBody,
                                           string? signatureHeader, string requestNonce, bool rawMode)
    {
        JsonDocument? document = null;
        try
        {
            if (responseBody.Length > 0)
            {
                try
                {
                    document = JsonDocument.Parse(new ReadOnlyMemory<byte>(responseBody));
                }
                catch (JsonException)
                {
                    // 非 JSON（例如反向代理返回的 HTML 错误页），走下面的兜底文案
                }
            }

            if (document is null ||
                (document.RootElement.ValueKind is not (JsonValueKind.Object or JsonValueKind.Array)))
            {
                WriteJsonLine(BuildFallbackJson(httpStatus));
                return httpStatus >= 500 ? ExitCodes.System : ExitCodes.Expected;
            }

            if (document.RootElement.ValueKind == JsonValueKind.Object)
            {
                int businessCode = TryGetBusinessCode(document.RootElement);

                // ---- 响应可信性校验 ----
                if (signatureHeader is not null)
                {
                    if (!ResponseSignature.Verify(responseBody, signatureHeader))
                    {
                        WriteWarning("[警告] 服务器响应签名无效，响应不可信，已拒绝");
                        WriteJsonLine(BuildErrorJson("服务器响应签名验证失败"));
                        return ExitCodes.System;
                    }
                }
                else if (businessCode == 0)
                {
                    // 成功响应绝不允许来自未签名的来源（防伪造服务器 / MITM）
                    WriteWarning("[警告] 服务器响应缺少签名，拒绝接受成功响应");
                    WriteJsonLine(BuildErrorJson("服务器响应缺少签名"));
                    return ExitCodes.System;
                }
                else
                {
                    WriteWarning("[警告] 服务器响应未签名（业务失败响应，仅提示不阻断）");
                }

                // ---- nonce 校验（防重放）：仅对成功响应强制 ----
                if (businessCode == 0)
                {
                    bool nonceOk = document.RootElement.TryGetProperty("nonce", out JsonElement nonceEl)
                                   && nonceEl.ValueKind == JsonValueKind.String
                                   && string.Equals(nonceEl.GetString(), requestNonce, StringComparison.Ordinal);
                    if (!nonceOk)
                    {
                        WriteWarning("[警告] 服务器响应 nonce 不匹配，疑似重放，已拒绝");
                        WriteJsonLine(BuildErrorJson("服务器响应校验失败"));
                        return ExitCodes.System;
                    }
                }
            }

            if (rawMode && document.RootElement.ValueKind == JsonValueKind.Object)
            {
                // --raw：把原始响应字节与签名交给主程序自行验签（纵深防御）
                WriteRawJson(responseBody, signatureHeader);
            }
            else
            {
                WriteMaskedJson(document.RootElement);
            }
            return httpStatus >= 500 ? ExitCodes.System : ExitCodes.Expected;
        }
        finally
        {
            // 响应体可能包含 token，输出完毕后清零
            CryptographicOperations.ZeroMemory(responseBody);
            document?.Dispose();
        }
    }

    /// <summary>读取响应 JSON 顶层 code 字段（缺失或非法返回 -2）。</summary>
    private static int TryGetBusinessCode(JsonElement root)
    {
        if (root.TryGetProperty("code", out JsonElement codeEl)
            && codeEl.ValueKind == JsonValueKind.Number
            && codeEl.TryGetInt32(out int code))
        {
            return code;
        }
        return -2;
    }

    /// <summary>
    /// --raw 输出：{"code":0,"raw":"<响应原始字节 base64>","sig":"<X-Signature 或 null>"}
    /// 主程序可对 raw base64 解码后用内置公钥独立验签，不信任本工具自身。
    /// </summary>
    private static void WriteRawJson(byte[] responseBody, string? signatureHeader)
    {
        ArrayBufferWriter<byte> buffer = new(1024);
        JsonWriterOptions options = new() { Encoder = JsonEncoder, Indented = false };
        using (Utf8JsonWriter writer = new(buffer, options))
        {
            writer.WriteStartObject();
            writer.WriteNumber("code", 0);
            writer.WriteString("raw", Convert.ToBase64String(responseBody));
            if (signatureHeader is not null)
            {
                writer.WriteString("sig", signatureHeader);
            }
            else
            {
                writer.WriteNull("sig");
            }
            writer.WriteEndObject();
        }
        WriteBytesLine(buffer.WrittenSpan);
    }

    /// <summary>递归复制 JSON，遇到敏感字段名时整体替换为 ***。</summary>
    private static void CopyWithMasking(Utf8JsonWriter writer, JsonElement element)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
            {
                writer.WriteStartObject();
                foreach (JsonProperty property in element.EnumerateObject())
                {
                    if (SensitiveFieldNames.Contains(property.Name))
                    {
                        writer.WriteString(property.Name, MaskedValue);
                    }
                    else
                    {
                        writer.WritePropertyName(property.Name);
                        CopyWithMasking(writer, property.Value);
                    }
                }

                writer.WriteEndObject();
                break;
            }

            case JsonValueKind.Array:
            {
                writer.WriteStartArray();
                foreach (JsonElement item in element.EnumerateArray())
                {
                    CopyWithMasking(writer, item);
                }

                writer.WriteEndArray();
                break;
            }

            default:
                // 字符串 / 数字 / 布尔 / null：按原始形态写出
                element.WriteTo(writer);
                break;
        }
    }

    private static void WriteMaskedJson(JsonElement root)
    {
        ArrayBufferWriter<byte> buffer = new(512);
        JsonWriterOptions options = new()
        {
            Encoder = JsonEncoder,
            Indented = false
        };

        using (Utf8JsonWriter writer = new(buffer, options))
        {
            CopyWithMasking(writer, root);
        }

        // 这里的缓冲内容已全部遮蔽，可以直接输出
        WriteBytesLine(buffer.WrittenSpan);
    }

    /// <summary>
    /// 读取同目录 checkpoint_config.json。客户端只读：文件不存在时返回默认地址，
    /// 绝不自动创建模板文件，也不回写任何内容。
    /// </summary>
    private static ServerConfig LoadServerConfig()
    {
        string configPath = Path.Combine(AppContext.BaseDirectory, ConfigFileName);

        if (!File.Exists(configPath))
        {
            return new ServerConfig(
                DefaultServer,
                $"[警告] 未找到 {ConfigFileName}，已使用默认服务器地址 {DefaultServer}；生产环境请手动创建该文件并填写 HTTPS 地址。",
                null);
        }

        string raw;
        try
        {
            using StreamReader reader = new(configPath, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            raw = reader.ReadToEnd();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new CheckPointConfigException("配置文件读取失败");
        }

        string server;
        string? certSha256Override = null;
        try
        {
            // 去掉可能存在的 BOM，再解析
            using JsonDocument document = JsonDocument.Parse(raw.TrimStart('\uFEFF'));
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                !document.RootElement.TryGetProperty("server", out JsonElement serverElement) ||
                serverElement.ValueKind != JsonValueKind.String)
            {
                throw new CheckPointConfigException("配置文件缺少 server 字段");
            }

            server = (serverElement.GetString() ?? string.Empty).Trim();

            if (document.RootElement.TryGetProperty("cert_sha256", out JsonElement pinEl))
            {
                if (pinEl.ValueKind != JsonValueKind.String)
                {
                    throw new CheckPointConfigException("配置文件 cert_sha256 必须为字符串");
                }
                string pinValue = (pinEl.GetString() ?? string.Empty).Trim();
                if (pinValue.Length > 0 && !System.Text.RegularExpressions.Regex.IsMatch(pinValue, "^[0-9a-fA-F]{64}$"))
                {
                    throw new CheckPointConfigException("配置文件 cert_sha256 格式无效（应为 64 位十六进制）");
                }
                certSha256Override = pinValue.Length > 0 ? pinValue.ToLowerInvariant() : null;
            }
        }
        catch (JsonException)
        {
            throw new CheckPointConfigException("配置文件不是合法的 JSON");
        }

        if (server.Length == 0)
        {
            throw new CheckPointConfigException("配置文件 server 字段为空");
        }

        if (!Uri.TryCreate(server, UriKind.Absolute, out Uri? uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new CheckPointConfigException("配置文件 server 地址无效（仅支持 http / https）");
        }

        // 不强制 HTTPS，但非回环地址的明文 HTTP 必须提示：生产环境只能用 HTTPS。
        string? warning = uri.Scheme == Uri.UriSchemeHttp && !uri.IsLoopback
            ? "[警告] 当前使用明文 HTTP 连接，token 与卡密可能被窃听甚至被篡改（中间人可偷走卡密绑定）；生产环境必须使用 HTTPS。"
            : null;

        // https 时启用证书锁定：配置覆盖优先，否则用内置生产证书指纹
        string? pin = uri.Scheme == Uri.UriSchemeHttps
            ? (certSha256Override ?? DefaultCertPin)
            : null;

        return new ServerConfig(server.TrimEnd('/'), warning, pin);
    }

    private static int MissingArgs()
    {
        WriteUsage();
        WriteJsonLine(MissingArgsJson);
        return ExitCodes.Expected;
    }

    private static bool IsHelp(string arg)
    {
        return arg is "-h" or "--help" or "/?" or "help";
    }

    private static string BuildErrorJson(string message)
    {
        // message 全部来自客户端内部固定文案，不含敏感数据
        return "{\"code\":-1,\"msg\":\"" + message + "\"}";
    }

    private static string BuildFallbackJson(int httpStatus)
    {
        string message = httpStatus switch
        {
            403 => "服务器拒绝访问",
            404 => "接口不存在",
            408 => "请求超时",
            413 => "请求体过大",
            422 => "请求参数不合法",
            429 => "请求过于频繁",
            >= 500 => "服务器内部错误",
            _ => "服务器返回内容无法解析"
        };
        return BuildErrorJson(message);
    }

    /// <summary>向 stdout 写一行 JSON（UTF-8 字节直写，不经过二次编码）。</summary>
    private static void WriteJsonLine(string json)
    {
        WriteBytesLine(Encoding.UTF8.GetBytes(json));
    }

    private static void WriteBytesLine(ReadOnlySpan<byte> utf8)
    {
        Stream stdout = Console.OpenStandardOutput();
        stdout.Write(utf8);
        stdout.WriteByte((byte)'\n');
        stdout.Flush();
    }

    /// <summary>警告写 stderr，保证 stdout 只有 JSON。</summary>
    private static void WriteWarning(string message)
    {
        Console.Error.Write(message);
        Console.Error.Write('\n');
        Console.Error.Flush();
    }

    private static void WriteUsage()
    {
        // 只打印参数占位符，不打印任何实际参数值
        Console.Error.Write("用法：" + Environment.NewLine);
        Console.Error.Write("  checkpoint.exe activate <卡密|-> <机器码|->" + Environment.NewLine);
        Console.Error.Write("  checkpoint.exe login <用户名> <密码|->" + Environment.NewLine);
        Console.Error.Write("  checkpoint.exe verify <token> <机器码|->" + Environment.NewLine);
        Console.Error.Write("  [--raw] 前缀：输出原始响应与签名，供主程序自行验签" + Environment.NewLine);
        Console.Error.Write("说明：参数值填 - 时从 stdin 读取一行，避免敏感值出现在进程命令行。" + Environment.NewLine);
        Console.Error.Flush();
    }
}

/// <summary>服务器配置（从 checkpoint_config.json 读取）。</summary>
internal sealed class ServerConfig
{
    public ServerConfig(string server, string? warning, string? certSha256)
    {
        Server = server;
        Warning = warning;
        CertSha256 = certSha256;
    }

    /// <summary>服务器基地址，已去掉结尾的 '/'。</summary>
    public string Server { get; }

    /// <summary>需要打印到 stderr 的提示（没有则为 null）。</summary>
    public string? Warning { get; }

    /// <summary>
    /// TLS 证书锁定指纹（仅 https 时非空）：服务器证书 DER 的 SHA-256 十六进制
    /// 必须与其一致，否则视为中间人拒绝连接。配置 cert_sha256 可覆盖内置默认。
    /// </summary>
    public string? CertSha256 { get; }
}

/// <summary>配置相关错误：文案固定，不含敏感信息。</summary>
internal sealed class CheckPointConfigException : Exception
{
    public CheckPointConfigException(string message) : base(message)
    {
    }
}

/// <summary>
/// 响应签名验证：内置 ECDSA P-256 公钥（与服务端 SIGN_PRIVATE_KEY 成对）。
/// 服务端对完整响应字节做 ECDSA/SHA-256 签名，DER 编码后放 X-Signature 头。
/// 公钥内置于客户端是信任锚：攻击者改不了客户端里的公钥就无法伪造签名。
/// </summary>
internal static class ResponseSignature
{
    private const string PublicKeyBase64 =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEf1CVWx8assqziHp/D30BZAh/AaI24ej/k3uD96gSBJtjCpgVVKSohxOUynJIHENoJuTRUkWAHs/0tcpN4oxAOQ==";

    private static readonly ECDsa? PublicKey = CreatePublicKey();

    private static ECDsa? CreatePublicKey()
    {
        try
        {
            byte[] spki = Convert.FromBase64String(PublicKeyBase64);
            ECDsa ec = ECDsa.Create();
            ec.ImportSubjectPublicKeyInfo(spki, out _);
            return ec;
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>验证响应字节签名；公钥缺失 / 签名非法 / 参数异常一律 false。</summary>
    public static bool Verify(byte[] data, string signatureBase64)
    {
        ECDsa? publicKey = PublicKey;
        if (publicKey is null || string.IsNullOrEmpty(signatureBase64))
        {
            return false;
        }

        try
        {
            byte[] signature = Convert.FromBase64String(signatureBase64);
            return publicKey.VerifyData(data, signature,
                HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (Exception)
        {
            return false;
        }
    }
}

/// <summary>
/// 敏感字符串容器：以 char[] 持有卡密 / token / 密码，Dispose 时手动清零。
/// 说明：命令行参数由运行时以 string 形式提供，那一份拷贝无法擦除（.NET 限制），
///       但本类之后的任何副本都只存在于可清零数组里，且不再产生新的 string 副本。
/// </summary>
internal sealed class SensitiveText : IDisposable
{
    private char[]? _chars;

    private SensitiveText(char[] chars)
    {
        _chars = chars;
    }

    public static SensitiveText From(string value)
    {
        return new SensitiveText(value.ToCharArray());
    }

    /// <summary>只读视图；Dispose 后为空。</summary>
    public ReadOnlySpan<char> AsSpan()
    {
        return _chars.AsSpan();
    }

    /// <summary>是否为空或全空白。</summary>
    public bool IsBlank
    {
        get { return _chars.AsSpan().IsWhiteSpace(); }
    }

    public void Dispose()
    {
        char[]? chars = _chars;
        if (chars is not null)
        {
            Array.Clear(chars);
            _chars = null;
        }
    }
}

/// <summary>
/// 请求体构造器：直接生成 UTF-8 JSON 字节。
/// 不拼接包含卡密 / token 的中间 string，编码缓冲区在用完后清零。
/// </summary>
internal static class JsonBody
{
    private static readonly JavaScriptEncoder Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping;

    /// <summary>构造 {"name1": value1, "name2": value2, "name3": value3} 的 UTF-8 字节。</summary>
    public static byte[] BuildThree(string name1, ReadOnlySpan<char> value1,
                                    string name2, ReadOnlySpan<char> value2,
                                    string name3, ReadOnlySpan<char> value3)
    {
        ArrayBufferWriter<byte> buffer = new(256);
        WriteByte(buffer, (byte)'{');
        WriteString(buffer, name1);
        WriteByte(buffer, (byte)':');
        WriteString(buffer, value1);
        WriteByte(buffer, (byte)',');
        WriteString(buffer, name2);
        WriteByte(buffer, (byte)':');
        WriteString(buffer, value2);
        WriteByte(buffer, (byte)',');
        WriteString(buffer, name3);
        WriteByte(buffer, (byte)':');
        WriteString(buffer, value3);
        WriteByte(buffer, (byte)'}');
        return buffer.WrittenSpan.ToArray();
    }

    private static void WriteByte(ArrayBufferWriter<byte> buffer, byte value)
    {
        Span<byte> single = stackalloc byte[1];
        single[0] = value;
        buffer.Write(single);
    }

    private static void WriteString(ArrayBufferWriter<byte> buffer, ReadOnlySpan<char> value)
    {
        WriteByte(buffer, (byte)'"');

        if (!value.IsEmpty)
        {
            // .NET 8 的 TextEncoder 只公开 Encode(ReadOnlySpan<char> -> Span<char>)，
            // 因此先按最坏情况申请字符缓冲区，再转成 UTF-8 字节。
            int charCapacity = value.Length * Encoder.MaxOutputCharactersPerInputCharacter + 8;
            char[] charBuffer = ArrayPool<char>.Shared.Rent(charCapacity);
            byte[] byteBuffer = ArrayPool<byte>.Shared.Rent(charCapacity * 3 + 4);
            try
            {
                OperationStatus status =
                    Encoder.Encode(value, charBuffer, out int charsConsumed, out int charsWritten);
                if (status != OperationStatus.Done || charsConsumed != value.Length)
                {
                    throw new InvalidOperationException("JSON 字符串编码失败");
                }

                int bytesWritten = Encoding.UTF8.GetBytes(charBuffer.AsSpan(0, charsWritten), byteBuffer);
                buffer.Write(byteBuffer.AsSpan(0, bytesWritten));
            }
            finally
            {
                // 缓冲区里是原始（未遮蔽的）敏感内容，立刻清零并归还
                ArrayPool<char>.Shared.Return(charBuffer, clearArray: true);
                ArrayPool<byte>.Shared.Return(byteBuffer, clearArray: true);
            }
        }

        WriteByte(buffer, (byte)'"');
    }
}

# CheckPoint

一个提供轻量、安全、便携、多功能的开源登录程序。

卡密（License Key）验证系统：**FastAPI 服务端 + .NET 8 客户端**，面向游戏 / 桌面软件 / 内部工具的授权校验场景。

- 服务端：注册 / 登录 / 卡密激活 / Token 验证 / 管理端（生成、撤销、批量吊销、改绑）
- 客户端：`checkpoint.exe`（activate / login / verify / `--raw`），Windows 单文件
- 存储：SQLite（WAL），bcrypt(12) 密码哈希，Token 仅存 SHA-256
- 传输：HTTPS + 客户端证书指纹锁定；响应 ECDSA P-256 签名 + nonce 防重放

## 安全特性（经过三轮对抗审计）

| 能力 | 说明 |
|------|------|
| 响应签名 + 防重放 | 服务端签名全部业务响应；客户端 fail-closed 验签 + nonce 校验 |
| TLS + 证书锁定 | 自签名证书 + 客户端内置指纹，中间人无法窃听/篡改 |
| Token 卫生 | SHA-256 入库、30 天滑动过期、登录单会话、过期行主动清理 |
| 抗滥用 | IP / machine_code / 登录失败多维限流；请求体上限与读取超时 |
| 业务安全 | 卡密撤销与批次吊销、24h 宽限改绑、管理员 IP 白名单、审计日志 |
| 部署加固 | 容器非 root / 只读根 FS / cap_drop / 只挂必要目录 |

审计与攻击报告：`SECURITY-AUDIT-REPORT.md`（25 项加固）、`ATTACK-REPORT.md`（红队演练，11 项修复）、`ROUND3-HARDENING-REPORT.md`（盲区清零）。

## 文档

- [API 调用文档](docs/API.md)
- [服务端安装与运维](docs/SERVER-INSTALL.md)
- [客户端对接指南（含机器码指纹规范）](docs/INTEGRATION.md)
- [版本更新文档](docs/CHANGELOG.md)

## 快速开始（服务端）

```bash
# 1) 生成 .env（ADMIN_KEY + SIGN_PRIVATE_KEY）
# 2) 生成 TLS 证书
./ops/rotate-cert.sh <部署IP>
# 3) 启动
sudo docker compose up -d --build
curl -k https://127.0.0.1:8080/health
```

详细步骤见 [docs/SERVER-INSTALL.md](docs/SERVER-INSTALL.md)。

## 目录结构

```
server/     FastAPI 服务端、容器编排、测试套件、运维脚本
client/     .NET 8 客户端源码（自包含/框架依赖两种发布配置）
shared/     API 契约（api-spec.json）、变更日志、协作消息
docs/       API / 安装 / 对接 / 版本更新 文档
```

## 许可

[Apache License 2.0](LICENSE)

## 安全披露

见 [SECURITY.md](SECURITY.md)。请勿在公开 Issue 中提交漏洞细节。
# 安全策略

## 报告漏洞

请通过私下渠道报告安全漏洞：

- 邮箱：`security@example.com`（**发布前请替换为真实联系方式**）
- 或使用 GitHub Security Advisories 的私密报告功能

请包含：复现步骤、影响版本、PoC（如有）。我们会在 **72 小时**内确认，并在修复后与您协商公开时间。

**请勿**在公开 Issue / PR / 讨论区披露未修复的漏洞细节。

## 支持范围

| 组件 | 版本 | 状态 |
|------|------|------|
| 服务端 | 最新 release | ✅ 支持 |
| 客户端 | 最新 release | ✅ 支持 |
| 更早版本 | — | 建议升级到最新版 |

## 安全基线（部署方必读）

- 必配 `ADMIN_KEY`（≥32 字符随机）与 `SIGN_PRIVATE_KEY`；
- 生产必须 HTTPS，配置 `ADMIN_ALLOW_IPS`，删除联调用的 `docker-compose.override.yml`；
- 定期备份（`ops/backup-cron.sh`）并演练恢复；订阅依赖安全通告。

详见 `docs/SERVER-INSTALL.md` 的「安全加固清单」。
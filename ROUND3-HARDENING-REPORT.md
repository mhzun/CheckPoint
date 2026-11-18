# CheckPoint v1.3.0 盲区清零与防御纵深报告

- **任务时间**：2026-11-18（上午）
- **背景**：v1.1.0 全面加固、v1.2.0 红队演练后，梳理出 20 项"尚未考虑"的盲区（业务逻辑 / 运维 / 信任边界 / 安全工程 / 人力层）
- **结论**：**全部处理完毕**（11 项代码级修复、5 项运维落地、4 项文档化路线图）；隔离环境 10 轮全量回归通过；e2e-v3 真机 10/10；fuzz/负载/走私探测完成；三份正式文档交付。

---

## 一、盲区逐项处理情况

| # | 盲区 | 处理 |
|---|------|------|
| 1 | **登录 token 无限增殖**（真实漏洞） | **已修复**：单会话登录——新登录在事务内注销该用户全部旧登录 token（`activations.user_id`），只保留最新一个；加索引。测试：func 阶段断言旧 token 失效、DB 仅 1 行 |
| 2 | **卡密抢绑（squatting）** | **已缓解**：`REBIND_GRACE_HOURS`（默认 24h）宽限改绑——首次绑定后 24h 内换机器可自助夺回，旧机器 token 全部注销；超期拒绝；管理员 `/admin/rebind` 改绑/解绑兜底。设为 0 可完全禁止改绑 |
| 3 | 无改绑/售后工具 | **已提供**：`/admin/rebind`（指定机器=改绑；null=解绑），均注销旧 token；文档含客服流程 |
| 4 | 注册面可被灌垃圾账号 | **已提供开关**：`REGISTER_ENABLED=0` 关闭注册（403）；文档建议生产按需关闭 |
| 5 | 卡密无批次归属 | **已实现**：`gen_keys` 支持 `batch`（省略自动 `B<日期>-<随机>`），入库并建索引；`/admin/revoke_batch` 按批吊销未使用卡密（泄露止损） |
| 6 | 无防篡改审计日志 | **已实现**：`data/audit.jsonl`（JSONL，20MB 轮转）：gen_keys/revoke/revoke_batch/rebind/宽限改绑/admin 鉴权失败/IP 白名单拒绝 |
| 7 | 备份一次性、未演练 | **已自动化+已演练**：容器内 `scripts/backup.py`（在线备份→`PRAGMA integrity_check`→gzip→保留 14 份）；root cron 每日 03:15；**恢复演练执行并通过**（integrity ok，行数一致） |
| 8 | 无监控告警 | **已落地**：`ops/healthcheck-cron.sh` 每 5 分钟（health、容器状态、磁盘≥85%、管理员鉴权失败计数），日志 `logs/ops.log`；文档给出接入现有监控的方法 |
| 9 | 测试数据污染生产库 | **已隔离**：`docker-compose.test.yml`（只读 FS + tmpfs 临时 DB，重建即清空）；10 轮回归全部在隔离容器进行，生产库零写入 |
| 10 | 证书无轮换流程 | **已提供**：`ops/rotate-cert.sh`（生成→备份旧证书→重启→打印指纹与客户端更新指引） |
| 11 | `--raw` 主程序侧未闭环 | **已提供参考实现**：`docs/INTEGRATION.md` §6 完整 C# 验签示例（主程序内嵌公钥→独立验签→取 token） |
| 12 | 无离线宽限 | **文档化策略**：建议主程序实现"最近成功校验后 72h 离线宽限"；区分网络失败/业务失败/安全异常三类处理（INTEGRATION §7） |
| 13 | 签名密钥轮换=全量升级 | **文档化路线图**：当前流程为 `rotate-cert.sh` 思路 + 客户端重发；双公钥并存列入 v1.4 规划 |
| 14 | 不拒绝旧版客户端 | **已实现**：`MIN_CLIENT_VERSION` + 客户端 `X-Client-Version` 头；低于版本 426 |
| 15 | 无覆盖率 fuzz | **已补**：结构化 fuzz 战役（500 迭代随机路径/方法/畸形 body/Unicode/嵌套/头注入），任何 5xx 或连接异常即失败；覆盖率引导（atheris）列入路线图 |
| 16 | 无负载测试 | **已补**：`scripts/load_test.py` 50/100 并发混合压测（p50/p95/p99/RPS/错误率），数据存 `<内部审计产物>/attack/` |
| 17 | 未测请求走私 | **已补**：`scripts/smuggling_probe.py`（CL.TE / TE.CL / 重复 CL / `+4` / 畸形 TE / 管道化），结论见 §三 |
| 18 | 供应链未锁定 | **部分落地**：基础镜像按 digest 锁定（`python:3.11-slim@sha256:07d482...`）；pip `--require-hashes` 与 SBOM/CI 扫描列入路线图（版本已精确 pin） |
| 19 | 管理员单密钥无 2FA | **已加纵深**：`ADMIN_ALLOW_IPS` IP 白名单 + 审计；多密钥/2FA 列入路线图 |
| 20 | **VM 弱密码 旧默认密码** | **已修复**：改为 24 位强随机（旧密码失效），保存在宿主机 `<host-protected-password-file>`（icacls 仅 Administrators/SYSTEM）；sshd 加固（MaxAuthTries 3 / LoginGraceTime 20 / ClientAlive 300×2）；部署用户加入 docker 组免 sudo |

---

## 二、v1.3.0 变更清单

| 类别 | 内容 |
|------|------|
| 业务 | 登录单会话；激活宽限期改绑；批次号；批量吊销；管理员改绑/解绑 |
| 安全 | 审计日志；管理员 IP 白名单；注册开关；客户端版本门槛（426） |
| 运维 | 备份脚本+cron+恢复演练；巡检脚本+cron；证书轮换脚本；隔离测试环境；基础镜像 digest 锁定 |
| 客户端 | `X-Client-Version: 1.3.0`；重建两版本 |
| 文档 | `docs/API.md`、`docs/SERVER-INSTALL.md`、`docs/INTEGRATION.md`（含机器码规范、--raw 验签示例、备份恢复/证书轮换/FAQ） |

**接口增量（不破坏旧客户端）**：登录单会话；激活宽限改绑；`gen_keys` 可选 `batch` 且响应带 `batch`；新增 `/admin/revoke_batch`、`/admin/rebind`；新增 426。

---

## 三、测试与演练结果

### 3.1 全量回归（隔离环境，9 阶段：func/escape/race/sig/security/rebind/spoof/mc/ip）

- **10 轮全部 ALL_PASS（每轮 160 项断言，合计 1600 项，0 失败）**。
- 生产库在回归期间零写入（测试使用独立临时 DB）。原始日志：`<内部审计产物>/test-results-v3/`。

### 3.2 Windows 真机 e2e-v3（10/10 通过）

HTTPS 激活 + `--raw` 独立验签、masked 输出回归、登录单会话（旧 token 失效/新 token 有效）、同机重激活、错误证书指纹拒绝、假 token 拒绝、宽限期改绑成功、超期改绑拒绝。

### 3.3 攻击性测试

- **结构化 fuzz**：1000 迭代 → **PASS**（0 失败、0 个 5xx、0 慢请求）。
- **负载**：50 并发 359.5 RPS（p99 204ms）；100 并发 300.6 RPS（p99 450ms）；**0 错误**。
- **请求走私**：6 类 framing 全部 400、无 desync → **PASS**。

---

## 四、"还能防什么"——纵深建议清单（v1.4+ 路线图）

按投入产出排序，已实现项打 ✅：

**已实现（本轮）**
- ✅ 登录单会话、宽限改绑、批次止损、审计日志、管理员 IP 白名单、注册开关、版本门槛、备份/巡检/轮换自动化、测试隔离、镜像 digest 锁定、主机强密码与 sshd 加固

**短期（低成本，建议下一轮做）**
1. **pip `--require-hashes`**：生成 wheels 哈希表，构建期强制校验（防 PyPI 投毒）。
2. **SBOM + CI 漏洞扫描**：`pip-audit` / `trivy` 进 CI，每次发布自动扫。
3. **双签名密钥并行**：服务端支持 `SIGN_PRIVATE_KEY` + `SIGN_PRIVATE_KEY_NEXT`，客户端内置双公钥——密钥轮换不再需要"全量强制升级"。
4. **管理面 2FA**：TOTP（Google Authenticator）叠加在 `X-Admin-Key` 之上。
5. **反向代理层限流**：nginx `limit_req/limit_conn` 与容器限流互补。
6. **备份异机**：启用 backup-cron 中 rsync 行到 NAS/对象存储，并定期自动化恢复演练（cron + 校验脚本）。

**中期**
7. **Prometheus 指标**：`/metrics`（429/403/500 计数、DB 大小、延迟直方图），接入 Grafana 告警。
8. **覆盖率引导 fuzz**：atheris（py3.11 需 clang 构建）或 honggfuzz 持续跑。
9. **HTTP 请求走私（反代层）复测**：生产接入 nginx/caddy 后，对其做 CL.TE/TE.CL 专项测试与配置核对。
10. **机器码风控**：同一 machine_code 绑定异常卡密数、同一 IP 短时大量激活失败等规则引擎。

**长期（架构级）**
11. **多租户/多管理员**：管理员账号体系（RBAC）+ 操作审批流。
12. **DB 迁移 PostgreSQL**：读写分离、多副本、在线扩展；SQLite 保留为单机模式。
13. **离线票据**：服务端签发带过期时间的签名离线授权（Ed25519/ECDSA），主程序本地验签——解决断网场景。
14. **客户端完整性**：主程序侧校验 checkpoint.exe 签名（Authenticode）或哈希白名单，抵御替换攻击。
15. **WAF/IPS**：在反代前挂 ModSecurity/Cloudflare 规则集。

---

## 五、回归后状态与操作指引

- 服务：`https://checkpoint.example.com:8080`（TLS，签名，v1.3.0），容器 healthy。
- VM 凭据：见宿主机 `<host-protected-password-file>`（旧密码已失效）。
- 日常运维入口：`ops/rotate-cert.sh`、`ops/run-round.sh`、`ops/run-attack-tests.sh`、`ops/backup-cron.sh`、`ops/healthcheck-cron.sh`；日志 `logs/*.log`、`data/audit.jsonl`。
- 文档：`docs/API.md`、`docs/SERVER-INSTALL.md`、`docs/INTEGRATION.md`。

---

## 六、最终结果补记（回归完成后填写）

- 10 轮全量测试：10 轮 ALL_PASS（R1~R10 各 160 项断言，0 失败；隔离容器，日志 <内部审计产物>/）
- fuzz：1000 次迭代，0 失败、0 个 5xx、0 慢请求（状态分布 200/400/404/405/422，全部优雅处理）
- 负载 50/100：50 并发：359.5 RPS，p50 135ms / p95 187ms / p99 204ms，0 错误；100 并发：300.6 RPS，p50 332ms / p95 420ms / p99 450ms，0 错误（TLS + /verify 混合 /health）
- 走私探测：6 类 framing 探测全部 400 Bad Request、单响应、无 desync（CL.TE / TE.CL / 重复 CL / +4 / 畸形 TE / 管道化）
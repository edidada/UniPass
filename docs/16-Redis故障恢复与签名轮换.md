# Redis 故障恢复与签名轮换

2026-10-19。本文记录 P2 的本地实现与演练，不代表多机、Sentinel、Redis Cluster 或生产滚动发布已验收。

## 认证运行代次

V6 新增 PG `auth_runtime_state` 单行控制记录与 `auth_runtime_recovery` 恢复审计。Redis 保存随机 UUID generation，PG 同时保存 generation 与 Redis `INFO server` 的 `run_id`。会话、API JWT、换令牌以及登录后复核都通过 `AccountState` 查询当前账号 gate/epoch 和运行代次；Redis 缺失、不可读、进程变化或两端不一致时拒绝认证。仅恢复 Redis 旧 generation 不能绕过进程变化检查。

`RedisSecurityState` 启动时执行恢复，依赖不可用则启动失败。后台默认每秒检查；调度池为 3，邮件网络调用不占用唯一调度线程。这个间隔不是恢复或吊销时延 SLA：数据库锁、网络、调度与重试都需要另行测量。每次受保护请求仍检查状态，不能依赖后台扫描来放行。

恢复步骤：

1. 在 PG 事务内锁定控制行；多个实例竞争时由此串行化，再读取 Redis marker 和进程标识。
2. 一致则直接结束；不一致则生成新代次，按 UUID 排序锁定 ACTIVE/OPEN 身份并递增 epoch，撤销所有未撤销授权族。
3. 保存控制记录与恢复审计，把新 generation 写到 Redis，再读回 generation/run_id 确认未在写入期间换进程。
4. 最后提交 PG。Redis 写入已成功而 PG 提交失败时，双方保持不一致；旧认证继续被拒绝，后续恢复重新生成代次，不能把 Redis 写成功解释为事务已提交。

BLOCKED 的密码操作已经递增 epoch，恢复过程保留其 fenced epoch，使 UNKNOWN 操作仍可按证据恢复。相关授权族依然撤销。新身份没有旧凭证，不需要随已有身份增加 epoch。密码恢复和安全恢复使用一致的身份加锁顺序，网络邮件与目录写入不在该恢复事务中执行。

## 部署约束与故障处理

| 配置 | 要求 |
|---|---|
| `UNIPASS_SESSION_NAMESPACE` | 默认 `unipass:session`；同一部署各实例一致 |
| `UNIPASS_REDIS_GENERATION_KEY` | 默认 `unipass:security:generation`；同一 PG 身份库只能对应同一运行域 |
| Redis ACL | 除会话/限速读写及索引订阅命令外，允许 `INFO server`；不需要应用执行 CONFIG |
| Redis 运行形态 | 当前针对单一 Redis 主进程；读副本、多主、Cluster 未验证 |
| PG 与 Redis | 必须作为同一认证域运维，不能让两个独立 Redis 的实例竞争同一 PG 控制行 |

Redis 清库、marker 被删/修改、主进程重启都会造成旧凭证失效并要求重新登录。该策略为保守安全恢复，普通持久化重启也会触发。不要手工把 PG 控制记录改成 Redis 值来解除故障；先修复依赖权限与连接，观察 `auth_runtime_recovery` 中的新记录，再以重新登录验证恢复。应用日志只记录通用恢复失败，不输出连接凭证。

PG/Redis 之间没有分布式事务。若同一进程内 marker 被删除又原样恢复，且期间没有任何请求或扫描观察到差异，当前机制无法证明这段瞬时变化发生过。依赖不可用时拒绝请求；已在 PG 完成的密码、禁用与授权族吊销不会因 Redis 备份恢复而撤销。生产需验证 ACL、持久化恢复、主备切换、并发请求及独立资源端的状态检查。

## RS256 密钥交接

外置 PKCS12 由启动时加载；`UNIPASS_SIGNING_ALIAS` 指向唯一当前私钥，其余 RSA 条目只进入 JWK 公钥集合。每个 RSA 公钥至少 2048 位，明确标记 RS256/signature；当前 alias 缺失或弱 RSA 配置会导致启动失败。JWKS 只输出公钥。没有在线上传私钥或热更新接口。

正常轮换先制作同时包含旧公钥与新密钥的受保护证书库，保留不同且稳定的 alias/kid：

1. 所有节点先发布重叠公钥，仍使用旧 alias 签名；确认各 RP 可获取新 kid。
2. 在保留相同公钥集合的情况下切换当前 alias，分批重启；新签名使用新 kid，旧 JWT 在有效期内继续验签。
3. 等待旧签名令牌最长有效期、允许时钟偏差和 RP 的 JWKS 缓存窗口，并检查 RP 退出用 ID token hint 的保留策略后，才移除旧公钥。

证书库加载后不会自动刷新，所有变更必须重启实例。私钥泄漏不适用常规重叠等待，需要紧急退役、撤销授权族及重新认证；当前未提供一键应急管理接口。MFA 加密 key 与 JWT 签名 key 分开管理，本文不实现 MFA 密文换 key。

## 本地证据

2026-10-18 21:26:20（Asia/Shanghai）执行 `scripts/verify-all.ps1 -RedisExecutable <本机 Redis 8.4.2>` 成功，用时约 88 秒：共 **82 项**，失败/错误/跳过均为 0。环境为 JDK 17.0.12、Maven 3.9.11、真实 PostgreSQL 17.6、独立 Redis 8.4.2；完整报告位于各模块 target 下。

新增六个 HTTP/PG/Redis 集成用例覆盖 marker 缺失、真实 FLUSHDB、真实进程重启后恢复旧 marker、并发恢复只增加一次 epoch、Redis 写入后 PG 延迟约束在提交时故障、密码 BLOCKED fence 保留。Redis 测试只操作用例自行启动的随机端口进程，不连接开发或生产服务。

新增两个密钥配置用例由 keytool 生成临时 RSA 证书库：验证旧/新 JWT 在重叠期均可验签、仅当前私钥可签名、公钥集合没有私钥、退役后拒绝旧签名，以及缺 alias/1024 位弱 key 启动失败。这是本地 loader/Nimbus 验证，不是独立 RP 经 HTTP 缓存 JWKS 或多实例滚动发布的证据。

测试不覆盖 Sentinel/Cluster、多机断网、生产备份、独立 SDK 与五秒吊销时延。P2 与 T2 保持未整体验收。

依据：[Redis INFO](https://redis.io/docs/latest/commands/info/)、[Spring Authorization Server JWK 配置](https://docs.spring.io/spring-authorization-server/reference/configuration-model.html)。

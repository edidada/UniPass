# 第二阶段 OIDC 运行与验证

2026-10-18。本文记录 `iam-server` 的实际实现；M2 整体仍未验收。MFA 增量见 [挑战与验证](14-MFA挑战与验证.md)，SAML IdP、跨端 SDK 与真实目录联调仍待完成。

## 实现与约束

Spring Boot 3.5.16 BOM 管理 Spring Authorization Server 1.5.8、Security 6.5.11、Session 3.5.7。标准授权码、JWT、OIDC、userinfo、撤销和 RP 退出由框架处理。所有客户端要求精确注册回调、非空 state 和 S256 PKCE；无 implicit/password grant。普通 SPA 不发 refresh token，原生公共客户端明确注册后可轮换 refresh token，机密客户端使用 basic。客户端注册通过离线操作员 CLI 执行，不开放未授权管理接口。

授权码 60 秒、access token 1 小时、refresh token 最长距初次认证 30 天。令牌值在 PostgreSQL 仅保存 SHA-256 摘要；令牌索引保留历史摘要来定位旧 refresh token 的令牌族。令牌事务先锁身份再锁授权记录，缓冲 HTTP 响应至提交成功；并发换码仅一次成功，旧 refresh 再次使用撤销整族，错误客户端不能借他人的 refresh 吊销其族。当前未提供历史授权数据清理任务，容量治理仍待实现。

RS256 密钥由外置 PKCS12 加载，当前 alias 提供私钥签名，其他 RSA alias 只提供公钥；JWKS 不输出私钥，RSA 最少 2048 位。`unipass_family` 是持久授权族标识；OIDC `sid` 保留框架生成的会话摘要，不能拿族 ID 覆盖。本地重叠签名与退役已测试，多实例/RP 缓存轮换证据待补，见 [故障恢复与签名轮换](16-Redis故障恢复与签名轮换.md)。

Redis 保存 IAM 主机下的 HttpOnly/Secure/Lax Cookie 会话；闲置 8 小时、认证起绝对 24 小时。PG 保存账号 gate 和 epoch，每次浏览器/API 请求检查账号及 PG/Redis 运行代次，查询失败拒绝放行。密码变更、禁用及认证后全局退出使旧 epoch 失效。Redis marker 丢失或进程变化后恢复会撤销授权族，并增加 ACTIVE/OPEN 身份 epoch；旧 JWT 与刷新令牌不能因 Redis 恢复继续使用。整库丢失与进程重启已本地演练，主备和生产恢复待验收。

认证后的 `/logout` 和 RP `/oauth/logout` 执行全局退出，递增身份 epoch 并撤销该用户的授权族；未登录时经框架校验的 ID-token hint 仅撤销对应族。退出重定向必须精确注册，不能任意跳转。该实现保证 UniPass 状态拒绝旧凭证，尚不代表外部 RP 的本地页面会话或飞书会话已清理。

密码到期标志阻止授权与换令牌，但保留已登录的改密和 CSRF 接口。本人改密状态查询允许原会话在初始认证后 5 分钟内读取自己的当前 fence 操作；其他请求拒绝旧 epoch。邮件重置与管理员恢复入口已独立接入，详见 [运行记录](15-密码重置验证与管理员恢复.md)，其能力与权限不能用普通会话替代。

登录失败计数保存在 Redis：账号 5 次失败锁 30 分钟；同 IP 一分钟 20 次失败锁 10 分钟；Redis 不可用拒绝认证。IP 取直连地址，不信任转发请求头。TOTP MFA 已接入授权和本人改密，图形验证码与风控管理尚待实现，不能把计数器等同于完整风控验收。

## 配置与启动

先按 [第一阶段运行说明](11-第一阶段运行与验证.md) 导入身份。所有凭证通过受保护的环境或企业 secret 注入，不提交 `.env`、私钥、证书库或生产配置。构建为 `mvn package -DskipTests`，生成可执行 `iam-server/target/iam-server-0.1.0-SNAPSHOT-exec.jar`；普通 JAR 保持为模块依赖。

| 环境变量 | 含义 |
|---|---|
| `UNIPASS_DB_URL` / `UNIPASS_DB_USER` / `UNIPASS_DB_PASSWORD` | PG JDBC URL、用户及密码；生产 URL 使用 TLS verify-full |
| `UNIPASS_REDIS_HOST` / `UNIPASS_REDIS_PORT` / `UNIPASS_REDIS_PASSWORD` | Redis 地址、端口及认证；密码必填 |
| `UNIPASS_REDIS_TLS` | 生产启用 TLS；默认 false 便于独立本地测试 |
| `UNIPASS_SESSION_NAMESPACE` / `UNIPASS_REDIS_GENERATION_KEY` | 默认会话 namespace 与安全 marker key；同一部署所有实例一致，ACL 还须允许 INFO server |
| `UNIPASS_ISSUER` | 外部固定 HTTPS issuer；不能含凭证、query、fragment |
| `UNIPASS_SIGNING_STORE` / `UNIPASS_SIGNING_PASSWORD` / `UNIPASS_SIGNING_ALIAS` | 外置 PKCS12 文件、密码与当前 RSA alias |
| `UNIPASS_MFA_KEY` | 必填，Base64 编码的随机 32 字节 MFA 加密 key，见 MFA 运行记录 |
| `UNIPASS_PORT` | 默认 8080；TLS 接入与可信代理边界由部署配置负责 |
| `UNIPASS_DIRECTORY_TYPE` | `AD` 或 `OPENLDAP` |
| `UNIPASS_LDAP_URL` / `UNIPASS_LDAP_BASE_DN` | LDAPS 地址及搜索根 |
| `UNIPASS_LDAP_READ_DN` / `UNIPASS_LDAP_READ_PASSWORD` | 最小只读账号 |
| `UNIPASS_LDAP_WRITE_DN` / `UNIPASS_LDAP_WRITE_PASSWORD` | 可选的最小写账号 |
| `UNIPASS_LDAP_WRITABLE_CONFIRMED` | 真实写权限核验后设 true；默认 false |
| `UNIPASS_PASSWORD_HISTORY_VERIFIED` / `UNIPASS_RESET_HISTORY_VERIFIED` | 分别核验目录用户改密与重置历史策略后设 true；默认拒绝相应写入 |

目录 TLS 信任通过 JVM trustStore 配置，保持证书链与主机名验证。迁移由启动时 Flyway 执行 V1–V6；迁移账号与运行账号拆分仍属部署任务。生产不内置测试账号、默认客户端或自动生成的签名私钥。

```powershell
java -jar iam-server/target/iam-server-0.1.0-SNAPSHOT-exec.jar
```

仅本机开发可加 `--unipass.local-http=true --server.address=127.0.0.1`，且 issuer 必须为 loopback HTTP；该模式才允许非 Secure Cookie，禁止对外绑定。代码默认不信任 `Forwarded`/`X-Forwarded-*`，不要仅传这些头来改变安全边界。

## 注册客户端

准备 [客户端配置示例](../examples/oidc-client.json)。机密客户端 secret 由密码学随机源生成 32–64 个可打印 ASCII 字符，经受保护环境注入 `UNIPASS_CLIENT_SECRET`；持久化为 bcrypt，不在 CLI 输出。公共 native/SPA 不设置 secret。重复 client_id 拒绝，不隐式覆盖。

```powershell
java '-Dloader.main=com.unipass.server.ClientAdminCli' -cp iam-server/target/iam-server-0.1.0-SNAPSHOT-exec.jar org.springframework.boot.loader.launch.PropertiesLauncher migrate
java '-Dloader.main=com.unipass.server.ClientAdminCli' -cp iam-server/target/iam-server-0.1.0-SNAPSHOT-exec.jar org.springframework.boot.loader.launch.PropertiesLauncher register examples/oidc-client.json
```

CLI 只需要数据库配置，不启动 Web/Redis/目录。生产 callback 必须 HTTPS；native 允许 reverse-domain 私有 scheme。显式设置 `UNIPASS_ALLOW_LOCAL_CALLBACKS=true` 才允许精确注册 HTTP loopback，端口仍严格匹配。原生生产优先使用已认领的 HTTPS app links。

## 协议与业务接口

发现地址 `/.well-known/openid-configuration` 公布固定 issuer 和端点。其余路径：`/oauth/authorize`、`/oauth/token`、`/oauth/jwks`、`/oauth/userinfo`、`/oauth/revoke`、`/oauth/introspect`、`/oauth/logout`。自动注册端点未启用。

| 业务接口 | 边界 |
|---|---|
| `GET /api/session/me` | Redis 浏览器会话 + PG 状态检查；返回 UUID sub/epoch |
| `GET /api/session/csrf` | 浏览器会话；返回 CSRF header 名和 token |
| `POST /api/password/change` | 浏览器会话、CSRF、Idempotency-Key；密码 char[] 不进入日志 |
| `GET /api/password/operations/{id}` | 本人操作；保留受限恢复读取能力 |
| `GET /api/resource/me` | Bearer access JWT、`at+jwt` 类型、`unipass-api` audience、`api.read` scope、PG 状态；ID token 不得用于 API |

独立资源服务必须实现相同的 epoch/gate/族状态检查，不能仅验签并宣称即时吊销。当前示例 API 与 IAM 同进程，独立 RP/BFF 接入和五秒端到端时延报告仍待补。

## 验证入口与未完成事项

```powershell
pwsh -NoProfile -File scripts/verify-all.ps1 -RedisExecutable '完整路径/redis-server.exe'
```

需要 JDK 17、Maven 3.9、可执行 Redis；PG 17.6 由测试库启动，Redis 由测试在随机 loopback 端口独立启动、设置随机密码且关闭持久化，退出回收自有进程。LDAP 网关测试使用本地 TLS 服务器；OIDC HTTP 用例中的目录为测试适配器，因此不能作为真实企业目录认证验收。报告保存在各模块 `target/surefire-reports`、`target/failsafe-reports`。

尚需：短信/飞书验证适配、MFA 受控恢复/轮换、SAML IdP 能力验证、独立 RP/BFF 和移动端、多实例/RP 缓存签名轮换、Redis 主备恢复、生产 LDAP/AD 联调、容量压测与五秒吊销证据、授权数据清理、集中指标和安全扫描。T2/T3 与 P2 均保持未整体验收。

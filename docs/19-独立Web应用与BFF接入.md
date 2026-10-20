# 独立 Web 应用与 BFF 接入

2026-10-20。`iam-web` 是 JDK 17 / Spring Boot 3.5.16 的独立进程示例，可部署为 CRM、HR 等不同客户端。授权码、nonce/state、JWT 和 OIDC 退出由 Spring Security 6.5.11 处理。这个增量覆盖 T2/T7 接入基础，不代表 IAM 门户、全部管理页面、后端退出通知或真实跨站浏览器兼容已完成。

## 进程与信任边界

IAM 保存目录、身份、epoch、gate 和授权族；每个 RP 保存自己的加密 Redis 浏览器会话。RP 不读取 IAM PG，也不直接验证目录密码。浏览器持有 RP 的 HttpOnly Cookie，通过重定向在 IAM 主机复用 SSO；token 保留在 BFF。不同 RP 使用独立 client_id、secret、cookie、Redis namespace 和 AES key。

每个应用包含一个 `/api/resource/data` 示例资源端点，部署在自己的 RP 进程，使用 Bearer access JWT。先经 JWKS 验签及 issuer、期限、`at+jwt`、本应用 audience/client_id、`unipass-api` audience 检查，再用机密客户端身份向 IAM `/oauth/introspect` 查询 live 状态。IAM 复核身份 epoch/gate、Redis 安全代次与族状态；状态不可查询则拒绝请求。此示例不缓存 introspection 结果，也不接受另一个 RP 或 ID token 的凭证。

`/bff/profile`、`/bff/data` 每次加载会话后同样校验 access token live 状态；BFF data 再以服务端 token 调用配置 origin 下的资源 API。浏览器只得到 sub、应用标识和业务结果，没有 token JSON。一个 RP 不能使用自己的凭证查询另一个客户端的令牌，此处资源服务按客户端独立，不应据此推断已实现通用多客户端 API 权限模型。

## 授权、会话与刷新

浏览器访问 `/oauth2/authorization/unipass`，服务端保存授权上下文并强制 S256 PKCE。固定回调为配置的 origin 加 `/login/oauth2/code/unipass`，不使用客户端传来的任意跳转地址，也不信任 Forwarded/X-Forwarded-*。回调 state 一次消费，nonce、ID token issuer/audience/签名经框架校验，成功后固定回到应用首页。

RP Cookie 名为 `UNIPASS_RP_<id>`，path `/`，host-only、HttpOnly、Secure、Lax；默认闲置三十分钟，BFF 另外检查首次 ID token 签发起二十四小时上限。Redis 会话属性（安全上下文、授权请求、authorized client）整体以 AES-256-GCM 加密；随机 nonce，AAD 为 RP namespace。密钥必须在同一 RP 多实例间共享并安全持久保存，不能每次启动生成；不同 RP 应使用不同 key。AES key 在线轮换与历史 envelope 迁移仍未实现。Redis 管理员不能在没有 key 的情况下构造可解密的会话属性；部署仍须限制 Redis 网络与 ACL。

access token 临近到期三十秒时由框架刷新；返回 ID token 重新验证并更新会话，subject/epoch 必须与原主体一致。新的 access/refresh 只保存在服务端。刷新失败或结果未知时销毁本地会话，要求重新登录，不继续重试旧 refresh token。

并发保护分两层：

1. 在 Spring Session 加载前，用 cookie 摘要取得 Redis 请求租约，持有到更新会话落库后释放，竞争请求返回 409 和 Retry-After。所有实例必须共用同一 RP Redis/namespace；默认租约六十秒，释放使用 owner 比较。
2. 真正调用 token 端点前，用 refresh token 的 SHA-256 摘要创建一次尝试标记，保留三十一天，长于 IAM 初次认证起三十天的 refresh 期限。即便暂停请求超过租约或会话旧快照被恢复，也不能再次发出同一个 refresh 请求。只有新 refresh token 才能建立新的标记。

请求锁失效不构成新的授权依据；最终 epoch/族判断仍在 IAM。RP Redis 整库恢复、故障切换丢写和多实例长暂停尚需演练；不能从单机用例推断这些场景已满足可用性目标。RP 与 IAM 分离部署时必须保留 IAM 的永久吊销状态，不得把恢复 RP 会话视作恢复有效授权。

## CSRF、页面与退出

静态首页使用外置 JS，CSP 限制 self、禁止嵌入及任意 base；不读取或持久化 token，数据通过 textContent 展示。所有写请求要求配置 origin 精确匹配与有效 CSRF token，没有 CORS 放开规则。`GET /csrf` 返回当前 RP 会话的 header 名/token；不能拿 IAM 的 CSRF token 代替 RP token。

`POST /logout` 经 Origin/CSRF 校验，清本地 Cookie 和会话，再由框架生成 IAM RP-initiated logout URL；携带标准 id_token_hint，post_logout_redirect_uri 固定为注册的应用首页。IAM 有认证会话时执行全局 epoch 失效，另一个 RP 下一次请求因 live 校验被拒绝。没有 IAM 认证会话时，IAM 按已验证 hint 撤销该授权族，不能把它称为全局退出。IAM 后端退出通知与 logout_token/jti 防重放接收器尚未实现。

当前页面仅提供登录、读取示例数据及退出。IAM MFA 页面、密码到期、自助重置、因素恢复、会话列表、Vue/TypeScript 门户与无障碍/兼容报告继续按 T7 实现；没有删减原任务范围。

## 配置与运行

应用接口另见 [RP/BFF OpenAPI](web-openapi.json)，不与 IAM 的业务路径混用。

先通过 IAM 的 ClientAdminCli 注册 CONFIDENTIAL 客户端，scope 为 `openid, profile, api.read`，精确注册回调与退出地址。client_id 使用 3–60 位字母、数字、下划线或连字符；客户端 secret 随机 32–64 个可打印 ASCII 字符。每个实例提供下列受保护配置：

配置模板：[CRM](../examples/web-crm-client.json)、[HR](../examples/web-hrm-client.json)。替换为真实 HTTPS origin 后，通过 [客户端注册命令](13-第二阶段OIDC运行与验证.md) 逐个注册；`UNIPASS_CLIENT_SECRET` 与对应 RP 的 `UNIPASS_RP_CLIENT_SECRET` 必须一致，不能把生产 secret 加进 JSON。Introspection 的 Basic 客户端凭证按 [RFC 6749 §2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1) 做 form 编码，回归使用含 `+%:` 的随机 secret 检验互通。

| 环境变量 | 含义 |
|---|---|
| `UNIPASS_RP_ID` | 如 crm 或 hrm；同时派生 cookie 与 Redis namespace |
| `UNIPASS_RP_ISSUER` | 固定 IAM HTTPS origin，不带 path/query/fragment |
| `UNIPASS_RP_ORIGIN` | 本应用 HTTPS origin，不带 path；默认不信任代理头 |
| `UNIPASS_RP_CLIENT_SECRET` | 对应 IAM 注册的机密凭证 |
| `UNIPASS_RP_SESSION_KEY` | Base64 随机 32 字节 AES key；保存到 secret 管理 |
| `UNIPASS_RP_REDIS_HOST/PORT/PASSWORD` | 会话 Redis；默认地址 127.0.0.1:6379，密码必填 |
| `UNIPASS_RP_REDIS_TLS` | 生产启用 TLS，默认 false 仅便于本地测试 |
| `UNIPASS_RP_PORT` | 默认 8081，两个 RP 使用各自端口 |

构建 `mvn -B -ntp package -DskipTests`，启动 `java -jar iam-web/target/iam-web-0.1.0-SNAPSHOT-exec.jar`。应用无需 IAM 数据库配置。TLS 入口及证书应由部署层明确配置，JVM TLS 不允许跳过证书/主机名校验。

仅本地开发可以传 `--unipass.rp.local-http=true --server.address=127.0.0.1`；issuer/origin 也必须 loopback HTTP 或 HTTPS。该模式才允许非 Secure Cookie，不能对外绑定。示例 IAM endpoint 路径明确配置而非运行时自动发现；生产 issuer 的固定路径应与 IAM OIDC discovery 核对，不能把任意外部 discovery 地址变成 SSRF 输入。

网络使用 JDK HTTP client，禁止自动跟随后端重定向，连接两秒、读取三秒。DNS、线程排队和完整业务链路的硬截止时间未测定，不能直接将单次读超时当作全链路 SLA。

## 自动验证与后续证据

`scripts/verify-all.ps1 -RedisExecutable <本机 Redis 路径>` 纳入本模块。`IndependentRpIT` 启动实际打包的 IAM、CRM、HRM 三个独立 JVM、随机端口 PostgreSQL/Redis 与测试证书 LDAPS SDK 服务；IAM 使用正常目录网关，不注入 fake directory bean。测试代理仅转发到本机 IAM 并注入 introspection 故障或刷新响应丢失；只回收自有进程。

覆盖：一次密码登录的两个 RP SSO；PKCE/nonce/state；回调伪造、跨应用和重放；ID token 与错误应用凭证拒绝；会话密文无原 token；实时状态故障拒绝；并发刷新仅一次；已提交刷新丢响应后不重放；恢复旧会话快照后的刷新拒绝；真实 LDAPS 改密后两个 RP/API 拒绝；Origin/CSRF 与 RP 退出。另有加密 envelope 篡改/跨应用/错误 key 和配置约束单测。

测试使用 Java HTTP cookie jar，各应用在 localhost 不同端口，没有模拟真实站点的浏览器 SameSite 行为。真实 HTTPS 跨主机浏览器、MFA 接入页、OIDC back-channel logout、多实例、故障切换与生产目录仍待验收。改密到两个 RP/API 拒绝的本地观察保存在 `iam-web/target/independent-rp/revocation-observations.md`；少量串行样本不是 P99、峰值或五秒 SLA 报告。

参考：[Spring OAuth2 Client](https://docs.spring.io/spring-security/reference/6.5/servlet/oauth2/client/core.html)、[JWT 配合 introspection](https://docs.spring.io/spring-security/reference/6.5/servlet/oauth2/resource-server/opaque-token.html)。

2026-10-20 22:05:56（Asia/Shanghai），JDK 17.0.12 / Maven 3.9.11 的全工程验证成功，约 145 秒，五个模块共 **102 项**，失败/错误/跳过均为 0。其中新模块 2 项单测、8 项独立进程集成测试；本次使用含 `+%:` 的客户端 secret。证据来自各模块 target 报告和实际可执行包，未以此声明真实浏览器或生产 SLA 通过。

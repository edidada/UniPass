# OIDC 后端退出通知

2026-10-20。此增量实现 T2/T7 的 IAM 持久通知与独立 RP 接收，配合原有实时 epoch/gate/授权族检查。采用 Nimbus JWT 编解码及验签，业务代码校验 logout token 上下文。协议参考 [OpenID Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)。SAML、飞书/移动会话、IAM 门户及生产时延验收继续按原计划完成。

## 注册与范围

机密 Web 客户端可以在离线注册 JSON 中增加 `backchannel_logout_uri`，见 [CRM](../examples/web-crm-client.json) 和 [HR](../examples/web-hrm-client.json)。地址必须与某个已登记 callback 的 scheme/authority 完全一致，固定路径 `/logout/backchannel`，不带 query、fragment 或 userinfo，生产必须 HTTPS。本机 HTTP 只在显式允许 loopback 注册时可用。NATIVE/SPA 不允许登记；未登记的客户端仍依靠实时状态拒绝，不能宣称收到主动通知。现有 CLI 拒绝重复 client_id，本增量没有增加覆盖注册接口。

IAM discovery 公布 `backchannel_logout_supported=true`、`backchannel_logout_session_supported=true`。UniPass 接入配置要求 `sid`；不提供仅 `sub` 的整用户会话接收模式，也不启用动态注册。RP 的 `sid` 来自框架 ID token，刷新后要求保持相同 sid/sub/epoch；不会用自定义授权族标识冒充 sid。

## 事务与投递

V8 新增 `oidc_rp_session`，在首次保存含 ID token 的授权时记录授权 ID、用户、客户端、登记 URI、sid 和可信密码认证时间，随授权删除级联清理。表中没有 access/refresh/logout token 原文。

`oidc_logout_task` 是持久投递账本，按 authorization_id 唯一。PG 触发器在授权首次变为 revoked 时入队，事务回滚会同时撤销入队。身份 epoch/status 变化或 gate 从 OPEN 变为 BLOCKED 时撤销该用户授权，因此现有改密、因素变更、离职禁用、全局退出和 Redis 安全代次恢复路径均能入队。重复 fence 不重复创建同一授权任务；单族撤销仅通知对应客户端/sid。身份任务使用独立 JDBC 入口时仍受同一数据库约束。

任务状态：`PENDING → RUNNING → SENT`；失败重新进入 PENDING，最多五次后 DEAD。后台默认每秒领取一条，通过 `FOR UPDATE SKIP LOCKED` 与三十秒 owner 租约支持竞争领取。网络调用期间不持有 PG 行锁，完成时比较 lease_token，旧 worker 不能覆盖已换 owner 的结果。第五次运行中租约过期会转 DEAD，不伪报成功。

每次尝试重新签发 RS256 JWT：当前签名 kid，`typ=logout+jwt`，固定 issuer、目标 client audience、UUID sub、原 sid、新 UUID jti、iat、两分钟 exp，以及唯一的 backchannel-logout 空对象事件；没有 nonce。HTTP POST form 中只发送 `logout_token`，连接两秒、总请求三秒、不跟随后端重定向。只有 HTTP 200 记 SENT；异常、超时和其他状态重试，退避为 `2^attempts + [0,2]` 秒。任务不保存 JWT，日志不包含凭证或远端响应。

DEAD 表示主动清理尚未确认，不能据此放行旧凭证。运维可按 state/attempts/next_attempt_at/lease_until 检查积压与故障，不应将 target_uri 改为任意地址。死信管理界面、独立告警与保留清理策略仍属 T8/T11；当前不会自动无限重试。默认单 worker 的吞吐与五秒总体目标必须另做容量测试。

## RP 接收与竞态

`POST /logout/backchannel` 只接受 form body 中一个 logout_token，不接受 query。该端点由签名 JWT 认证，不依赖浏览器 Cookie、Origin 或 CSRF；其他浏览器写接口保留原有 Origin/CSRF。成功为空 200，非法或重放为空 400，Redis/JWKS 等依赖不可用为空 503，响应禁止缓存。接口契约见 [RP OpenAPI](web-openapi.json)。

RP 只使用固定 IAM issuer 的 JWKS 验签，并校验 issuer、RS256、type、自己的 audience、非空 jti/sid、可选 sub、唯一空对象事件与无 nonce。iat 最多允许未来三十秒或过去三分钟；exp 必须尚未到期、晚于 iat 且不超过 iat 加三分钟。不能把普通 ID/access token 当退出通知。

登录成功时，Redis Lua 原子登记 sid → session_id/sub，并拒绝已吊销 sid。收到有效通知后，另一段 Lua 原子完成：检查 jti 未消费、匹配已登记 sub、记录 jti 防重放、记录 sid 吊销、删除该 sid 的全部本地 session key 和索引。jti 标记保存四分钟，覆盖接收窗口；sid 索引及吊销标记保存二十五小时，长于 RP 二十四小时绝对会话期限。只存摘要化 sid/jti key，不持久化原通知。

同一个 JWT 并发接收只允许一个 200，其余 400。发送端每次重试使用新 jti，因此第一次已删除会话而响应丢失时，后续尝试仍可确认同一 sid 已退出。通知早于登录回调完成时，吊销标记阻止后续绑定；并发请求晚提交或旧会话快照恢复时，BFF 先检查 sid 标记，再检查 IAM live 状态。整库恢复可能同时丢失 RP 标记，IAM 的永久授权撤销仍是放行依据，不能仅凭本地 Redis 恢复有效认证。

单个授权族撤销不会递增整用户 epoch。为避免同一 IAM 登录再次给该 RP 签发已退出的 sid，授权入口查询该用户/客户端/可信密码认证时间对应的通知账本；存在通知时清理当前 IAM 登录，进入密码重新认证并产生新 sid。其他客户端既有授权保持 live，不被单族撤销扩散。通知即便处于 PENDING/DEAD 也触发此限制，迟到重试只能清理原 sid。账本暂不自动清理，未来保留策略必须覆盖 IAM 登录绝对期限与通知窗口，不能提前删除仍用于重新认证判断的记录。

## 升级与验证

V8 在安装触发器后，使 ACTIVE/OPEN 身份 epoch 递增并撤销已有授权，要求重新登录建立新 sid 映射；密码 BLOCKED 操作的 fenced epoch 不修改。已有 RP 会话通过 live 状态拒绝，不能声称迁移为它们补齐了历史通知。部署前应明确一次重登影响；迁移回退、主备恢复和滚动版本兼容尚需 T11 演练。

`IndependentRpIT` 使用实际 IAM/CRM/HRM 三个 JVM、正常 LDAPS 网关和自有真实 PG/Redis。新增覆盖：无浏览器请求时删除两个 RP 会话、恢复快照拒绝、同 sid 晚绑定拒绝；错误签名/issuer/audience/events/nonce/sub/时间和 ID token 拒绝；并发 jti 仅一次；网络失败后重试、200 响应体不结束时有界失败、过期末次租约 DEAD、旧 owner 回写隔离和重试新 jti；事务回滚不发布；单族退出后重新密码登录、新 sid 不受旧通知重试影响且另一个 RP 继续可用。测试中的投递 worker 由父测试进程运行真实生产实现，调度器关闭以精确控制故障，不等价于生产调度性能验收。

`BackchannelMigrationIT` 在真实 PG 先安装 V7、写入 OPEN/BLOCKED 身份及旧授权，再升级 V8，验证旧认证撤销、BLOCKED epoch 保留、gate fence 入队、重复 fence 不重复任务，以及删除授权后投递账本保留。

全量命令为 `scripts/verify-all.ps1 -RedisExecutable <Redis 路径>`，报告位于各模块 target 目录；Gradle 分支使用等价集成任务。真实 HTTPS 跨主机浏览器、RP 多实例/Redis 主备、JWKS 滚动轮换、规模与 P99/五秒目标仍待验收。

2026-10-20 22:41:58（Asia/Shanghai），JDK 17.0.12 / Maven 3.9.11 最终源码全量验证成功，约 176 秒，五模块 **111 项**，失败/错误/跳过均为 0。包含客户端注册 3、V7→V8 升级 1、原 OIDC 集成 42、独立 RP 集成 15；覆盖缺少 aud/sid/jti 和单族退出后的重新认证/迟到通知。功能提交 `64eebe5`；未将此前较早结果作为新增检查的证据。

2026-10-20 22:42:58（Asia/Shanghai），Gradle Wrapper 8.14.3 / JDK 17 的 `clean build --offline` 成功，用时 203 秒，37 个任务全部执行，**111 项**测试失败/错误/跳过均为 0。构建分支 `build/gradle-jdk17` 的功能合并提交 `35c1442`，复用本机依赖缓存，不借用 Maven 产物。IAM 的 80 个、RP 的 67 个 BOOT-INF/lib 文件名称与版本清单分别与 Maven 完全一致；两分支模块源码一致。

文档相对链接及两份 OpenAPI 的本地引用已检查；IAM 业务路径 24 个，RP 路径增为 9 个。当前没有 Git remote，`gh run list --limit 1` 返回无法确定仓库，因此本次未推送且远程 Actions 未验证。两种本地成功不替代远程运行、生产联调或 P2–P5 全部验收。

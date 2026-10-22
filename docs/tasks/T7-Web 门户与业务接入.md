# T7 Web 门户与业务接入详细设计

| 项目 | 内容 |
|---|---|
| 编号 | UniPass-LLD-T7 |
| 版本 / 日期 | V1.3 / 2026-10-23 |
| 状态 | 独立 RP/BFF、后端退出通知、登录会话管理后端及本次 IAM 门户 Maven 增量已编码；远程 CI 未运行，浏览器/HTTPS/真实租户证据仍缺，尚未整体验收 |
| 负责人角色 | 前端 / 后端 |
| 依赖与开工条件 | T2、T3；选择两个独立 RP 验证 SSO。 |

## 1. 目标与边界

承接 [PM 任务规划](../05-PM开发子任务规划与里程碑.md) 的 T7。公共技术决策见 [技术选型](../08-技术选型与决策记录.md)，跨文档口径见 [设计基线](../09-设计基线与待确认事项.md)。本文的完成标准必须以交付证据验证，不能以文档完成代替实现完成。

## 2. 处理流程与实现约束

1. 首期 Web RP 推荐 BFF：服务端保存 token，浏览器只持 HttpOnly 会话 Cookie。SPA 如单独评审使用公共客户端，必须 PKCE 且不在 localStorage 保存长期凭证。
2. 门户页覆盖登录、MFA、到期改密、自助重置、会话管理和异常恢复；授权上下文使用服务端 ID，不信任前端传入的跳转地址。
3. Cookie 使用 Secure、HttpOnly、SameSite=Lax 且限 IAM 主机；所有写接口校验 CSRF token 与 Origin，CORS 只开放登记来源。浏览器不安全请求要求唯一且与 IAM issuer 完全一致的 Origin；`/oauth/token`、introspect、revoke 等客户端协议端点保持无浏览器 Origin 兼容。
4. 改密 202 展示处理中并按 operation_id 查询，不自动重新提交密码；成功后清会话回到重新认证页。未知响应后只保留只读查询：`/api/password/requests/{key}/operation`（改密）与 `/api/password/reset/requests/{key}/operation`（重置），请求 UUID 带轮次上限轮询，密码永不重放。
5. RP 处理后端登出通知时验证签名、issuer、audience、事件声明和 jti 防重放；本地 session 必须同时受 epoch 检查约束。
6. 页面统一处理账号不存在、口令错误和重置申请结果，避免枚举；密码输入禁止进入分析埋点、录屏与错误采集。邮件凭证在首条请求与首次渲染前剥离 fragment，仅在用户显式点击验证后消费一次；凭据先于 await/pagehide 清除。

## 3. 数据与契约

BFF 会话绑定 sid、sub、auth_epoch；回调 state 在服务端一次性消费；会话列表只展示脱敏设备、最近活动和可吊销标识。门户续跳只存在服务端会话内的 `Pending(id,target,owner,expiresAt)`（随机 UUID、10 分钟过期、所有者绑定）；不存在 SavedRequest 或任意 return_to/target 参数。只有已通过 `/oauth/authorize` 参数校验的目标可以跨会话失效保留，且只携带目标本身，不携带认证态或 MFA 证据。

字段与接口以 [公共详细设计](../04-详细设计文档.md) 为起点；新增表和字段必须配数据库迁移及回退兼容说明。内部 ID 采用不可变 UUID，时间统一 UTC，日志回传 trace_id；业务错误使用公共错误信封，协议错误遵循对应协议。本次新增 `/api/session/me` 扩展视图、`/api/password/requests/{key}/operation`、`/api/password/reset/requests/{key}/operation` 与 `/portal/continue`，契约见 [OpenAPI 3.1](../openapi.json)（现为 34 路径）。

## 4. 异常处理与运维

依赖调用设置连接与总超时，不无限重试；写入结果不明时保留 operation_id 与可恢复状态。关键指标按任务、结果和依赖统计，禁止以用户 ID 作为高基数指标标签。认证、授权和状态校验故障均拒绝放行；管理员操作和人工修复必须留审计。

## 5. 验证与完成标准

两个 RP 跨域 SSO、浏览器返回刷新、CSRF、开放重定向、重置 token 重放、会话吊销、无障碍键盘操作和错误文案。

交付物：门户、Web 示例与接入清单、浏览器兼容报告；对应 A1、A5-4、A6。

开发自测、QA 验证和责任人评审分别记录 commit、执行时间、环境与证据位置；未执行填“未执行”，不得预填通过。

实施记录：[独立 Web/BFF 接入](../19-独立Web应用与BFF接入.md)。当前 `iam-web` 可分别作为 CRM/HRM 独立 JVM 运行，使用自己的加密 Redis 会话、S256 PKCE、一次性 state、Origin/CSRF 和 access token live introspection；资源端再次验签/type/audience/scope。刷新在 Session 加载前串行化，并以长期摘要标记阻止旧 refresh 重试；丢响应销毁本地会话。V8 [后端退出通知](../21-OIDC后端退出通知.md) 增加事务入队、有限重试、jti 防重放与 sid 原子清理。这些增量不替代 Vue/TypeScript IAM 门户、MFA/密码页、会话管理与真实浏览器验收。

## 6. V13 IAM 门户增量（2026-10-23，远程 CI 未验证）

新增第六个模块 `iam-portal`：Vue 3.5.44 + TypeScript 6 + Vite 8 构建 `iam-portal/target/classes/META-INF/resources/portal`（首页与散列资源，`base=/portal/`），无第三方运行时依赖之外仅 Vue；Node 24.22.1/npm 11.19.1 由 frontend-maven-plugin 2.0.2 固定，`.npmrc` 指向官方 registry 并禁用继承代理。工具链命令（typecheck/test/build）只在 Maven reactor 或对应 Gradle 分支（及其 CI）中执行，本地不得运行。`iam-server` 以普通模块依赖打包资源，门户 jar 走 classpath `META-INF/resources` 供服务端按需 serve。

技术选型理由：Vue 3 + TypeScript 的静态类型与 OpenAPI 契约（Identity/MfaStatus/CsrfProof）同步演进，字段漂移在构建期即被 vue-tsc 拦截；门户采用页导向的固定服务端路由——`/login`、`/reset` 与 `/portal/*` 八条外壳路径由服务端返回同一 `index.html`，不接受调用方携带的任意 return_url，续跳目标只能来自服务端 `PortalContinuations` 校验记录（600 秒、所有者绑定、一次性消费），从机制上排除开放重定向；构建产物打进 `iam-portal` jar 的 `META-INF/resources`，由 Spring Boot classpath 直接 serve，单交付物、不要求 CDN 或反代假设、资源路径固定可测；Node 与 npm 版本由 Maven（frontend-maven-plugin）与 Gradle（node-gradle）以及 `package.json` 的 `engines` 双重锁定并 `engine-strict` 校验，两端工具链一致且可复现。`/api/session/csrf` 为已认证会话内端点，不用于匿名外壳取证。

后端同源与续跳策略：`BrowserOriginPolicy` 在浏览器链全体不安全请求上要求唯一、与 issuer 完全一致的 Origin（缺省/`null`/外来/重复一律 403，变更前生效）；协议链仅对 `/oauth/authorize` 与 `/oauth/logout` 启用，保持 token/introspection/revoke 兼容。`PortalContinuations` 只存放通过校验的授权请求：随机 continuation UUID + 600 秒 + 所有者绑定，登录成功、续跳与跨 SID 轮换均只搬运目标；改密围栏导致的会话作废保留目标到新匿名会话，不保留认证或 MFA 证据。`PortalPages` 对 8 条外壳路径返回 no-store、Referrer-Policy same-origin 的同一资源 `index.html`（无数据、无 CDN），浏览器链 CSP `default-src 'none'`/`script-src 'self'`/`style-src 'self'`/`connect-src 'self'`/`img-src 'self' data:`/`base-uri 'none'`/`form-action 'self'`/`frame-ancestors 'none'`；未认证浏览器访问受保护 API 统一得到 JSON 401，CSRF 取证走公共端点 `/api/public/csrf`。`PasswordController.me` 扩展 identity 视图；改密/重置均提供按 `Idempotency-Key` 的只读恢复路径（用途为密码操作结果确认，与 `/portal/continue` 的续跳记录是两个独立机制；登录、最近口令、登录状态及 epoch/世代核验均实时检查；未验证邮箱凭据、撤销后 401、他人 404）。

回归测试（新增，仅 CI 执行）：`PortalContinuationsTest`（4 项）、`OidcFlowIT` 新增 7 项（外壳/CSP/资源包、Origin 前置拒绝、MFA 续跳与 SID 轮换、改密码后匿名续跳、跨身份接替拒绝、恢复请求只读归属、旧 202 路径改造）；`BrowserOriginPolicyTest`（4 项）；独立 RP 套件改为 `/api/public/csrf` 取证并带 Origin。门户前端 vitest：`portal.test.ts`（10 项，覆盖 202 轮询不重放、丢响应按键恢复、刷新只读续查、上限后手工查询、输入清除与不暴露错误细节）与 `api.test.ts`（5 项：CSRF 头/幂等传播、operation_id 提取、错误文案不外泄、目标路径前置守卫、UUID 校验），JUnit 报告 Maven 写 `iam-portal/target/frontend-test-results.xml`、Gradle 重定向到 `iam-portal/build/frontend-test-results.xml`（两侧工作流均归档）。以上均为静态代码盘点，非运行证据；远程运行结果以 Codex 推送后的 Actions 记录为准。

仍未完成：真实 HTTPS 跨主机两 RP 浏览器验收、键盘/读屏无障碍与错误文案人工评审、多浏览器兼容报告、飞书真实租户端到端、T8 管理控制台、T9–T11 集成/安全/发布范围。

登录列表与独立吊销后端增量见 [会话设计与验证](../26-登录会话管理与独立吊销.md)：V12 稳定登录 ID、归属分页、近期口令/MFA、CSRF/Origin、全授权族吊销、刷新/改密竞态及升级围栏。Vue/TypeScript 门户、前端会话管理和浏览器兼容报告仍未完成；接口增量不代表 T7 整体验收。

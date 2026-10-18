# MFA 挑战与验证

2026-10-18。T2 增加 TOTP 二次验证；T3 的短信/邮箱/飞书重置验证与 T8 的管理员操作边界仍未完成。本功能不替代密码恢复所需的可信因素验证。

## 因素生命周期

采用 [java-otp 1.0.0](https://github.com/jchambers/java-otp/releases/tag/java-otp-1.0.0)（MIT）实现 RFC 6238 算法，参数为 6 位、30 秒、HMAC-SHA1；IAM 自己负责挑战归属、有效期、尝试次数和消费事务，未自行实现 OTP 算法。密钥为独立随机 160 位值，以 Base32/otpauth URI 在注册响应中交付一次。

注册要求当前密码认证距今不超过 5 分钟。pending secret 5 分钟内必须以有效 TOTP 确认；已启用的因素不能被注册接口覆盖。确认与用户 `auth_epoch++` 在同一 PG 事务，旧会话及令牌失效，必须重新密码登录。启用时的 TOTP 时间步已消费，不能在紧接着的 MFA 再使用同一步，需要等待下一步或输入尚未消费的有效时间步。

服务启动新增必填 `UNIPASS_MFA_KEY`：Base64 编码的 32 字节随机 AES key，由 secret 管理注入，多实例保持一致。示例只生成值，不输出密钥：

```powershell
$mfaKeyBytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($mfaKeyBytes)
$env:UNIPASS_MFA_KEY = [Convert]::ToBase64String($mfaKeyBytes)
[Array]::Clear($mfaKeyBytes, 0, $mfaKeyBytes.Length)
```

真实部署必须将生成结果安全保存到企业 secret 管理，不要每次进程启动重新生成。数据库仅保存带随机 nonce 的 AES-256-GCM envelope；AAD 绑定用户不可变 UUID，密文被篡改或挪给其他用户会拒绝解密。响应与 DTO 的字符串表示脱敏，OTP/密钥不进入审计。

当前 envelope 为 v1、单外置 key，尚未实现多 key 在线重加密与轮换工具。丢失 key 会导致原因素不可用；密钥备份恢复、硬件认证器、恢复码以及受控因素撤销仍是后续交付，不能靠删除因素记录代替安全恢复。

## 授权与挑战

已启用 TOTP 的用户，以及具有 `ROLE_ADMIN*` 角色的主体，在授权前需要最近 5 分钟内 MFA。无因素的管理员必须先注册；不会因没有因素而跳过 MFA。密码到期检查仍优先提示改密，已启用因素的用户可经独立 step-up 后改密。

`/oauth/authorize` 参数先完成客户端、精确回调、state 和 S256 校验；当前会话缺少近期 MFA 时返回 401 `mfa_required` 和服务器生成的 context UUID。挑战绑定用户、epoch、会话 ID 摘要、context 及 5 分钟过期时间；context 只接受当前会话持有值，不接收前端任意跳转 URL。

验证先锁身份，再锁因素与挑战，成功原子记录消费时间和 `last_used_step`。只接受当前时间步及正负一步漂移；同一用户已消费的时间步不能在其他挑战或会话重放。一个会话创建新挑战会作废该会话此前未消费挑战。错误验证码累计到因素：5 次锁 30 分钟，新建挑战或重新登录不能清零；拒绝结果在事务提交后返回，避免回滚失败计数。

验证成功重新生成会话 ID，将 `mfaAt` 写入 Redis 安全上下文；会话 MFA 可在 5 分钟内复用于后续授权和受保护操作。新发 JWT `amr` 为 `pwd,otp`；刷新沿用该授权最初的认证证据，仍检查 epoch/gate。启用因素后先前未做 MFA 的授权由于 epoch 改变失效。

## HTTP 契约

以下均为 IAM 浏览器会话接口；所有 POST 要求来自 `GET /api/session/csrf` 的 CSRF header。挑战成功不直接发 token，App 仍走浏览器授权码/PKCE。

| 方法与路径 | 请求 / 返回 |
|---|---|
| `GET /api/mfa` | 返回 enrolled、required、recent；不返回因素密钥 |
| `POST /api/mfa/enrollment` | 空 JSON；返回 secret、otpauthUri、expiresAt，只有本次响应可读 |
| `POST /api/mfa/enrollment/confirm` | `{ "code": "六位数字" }`；成功返回 reauthentication_required=true |
| `POST /api/mfa/context` | 空 JSON；为独立 step-up 创建服务器 context |
| `POST /api/mfa/challenges` | `{ "context": "UUID" }`；返回 challenge UUID |
| `POST /api/mfa/verify` | `{ "context": "UUID", "challenge": "UUID", "code": "六位数字" }`；返回 verified=true |

授权页收到 MFA_REQUIRED 后保留原始 RP 授权参数，完成挑战再重试原授权；门户页面尚待 T7 实现。业务拒绝统一返回 REQUEST_REJECTED 与 trace_id，非法/过期/重放验证返回 400，因素已启用或尚未注册时返回 409。此阶段未提供匿名 MFA 接口。

## 迁移与验证

服务 Flyway 升级到 V4。因素与挑战均外键关联身份，事务锁顺序与 token/password 保持身份在前；移除 V4 表会丢失因素和消费证据，不是可接受的回退操作。旧版本不理解 MFA，启用 MFA 后不得直接回退并继续签发无 MFA 令牌。首次切换还需清理旧版本序列化会话并要求重新登录；新 principal 固定 serialVersionUID，跨版本兼容仍须执行回归。

自动测试使用真实 PG/Redis，覆盖注册后 epoch 失效、HTTP CSRF、授权挑战、错误 context、跨会话、过期、时间步重放、跨挑战失败锁定、并发恰一次消费、amr 与 refresh 持久化，以及 envelope 篡改和用户归属。测试 OTP 由标准库生成；真实认证器扫码、时钟偏差运维、多实例切换和生产 secret 恢复尚未验收。

# MFA 加密主密钥轮换

2026-10-21。T2/T3 增量：在保留 TOTP 秘密、消费时间步、失败计数、因素状态和 epoch 的前提下，迁移活动及待确认因素的加密主密钥。用户更换认证器仍走 [因素生命周期](18-MFA因素轮换与受控恢复.md)，两种轮换分别审计。本功能不包含 RP Redis 会话 AES key、签名私钥、KMS 接口或历史备份重加密。

## 格式与密钥配置

V1 为 `version=1 | 12字节nonce | GCM ciphertext+tag`，AAD 为原来的 `unipass:totp:v1:<用户UUID>`；key id 固定视为 `legacy`。旧密文保持可读，不自动猜测或轮流试 key。

V2 为 `version=2 | 1字节key-id长度 | ASCII key-id | 12字节nonce | ciphertext+tag`，AES-256-GCM，128 位 tag，AAD 为 `unipass:totp:v2:<key-id>:<用户UUID>`。改 key id、搬到另一用户、改 payload 或使用错误 key 均不能通过验证。key id 必须为 1–48 位字母、数字、下划线或连字符，首字符为字母或数字；`legacy` 保留给 V1。

| 配置 | 作用 |
|---|---|
| `UNIPASS_MFA_KEY` | 原 Base64 随机 32 字节 key，只解读/写入 V1；仍有 legacy 引用时不能移除 |
| `UNIPASS_MFA_KEYS_JSON` | 受保护 JSON 对象，key id → Base64 随机 32 字节 key；最多 16 个命名 key，禁止重复字段、保留 id、相同材料不同 id |

示意结构为 `{"totp-2026q4":"<由secret管理注入的Base64值>"}`，占位内容不可直接运行。不要把生产 JSON 放入 Git、命令行参数、工单或日志。各节点安装同一可读 key 集合；数据库只保存 id、SHA-256 材料指纹、状态和操作证据引用，未保存密钥材料。

V9 新增 `mfa_encryption_key`、单行 `mfa_encryption_control`、`mfa_key_audit`。首次控制行未初始化时，在事务内登记配置 key：有 legacy 则继续写 V1；没有 legacy 时只允许唯一一个命名 key 作为初始写入 key。已有因素引用的 key 必须可用，并在提交初始指纹之前验证全部已有密文的 owner/AAD/tag；错误材料或坏密文使登记、writer 与审计一起回滚，不会固化错误指纹。后续启动不自动引入配置里的新 key，且会检查所有 AVAILABLE key 的材料指纹及现有引用；缺失、材料漂移或引用已退役 key 会拒绝启动。

## 写入与并发约束

当前写入 key 以 PG 控制行为准，环境变量不决定激活状态。加密、解密及重包裹参与外层 MFA 事务并持有控制行共享锁；切换和退役取得排他锁。新 key 未在节点安装时，节点不能退回旧 key 写入。

V9 触发器检查两个因素表新增/改变的密文头，拒绝与当前 writer 不一致的写入。旧节点、旧快照或旧 pending 密文不能在切换后重新写回旧 key。触发器仅检查格式和路由；GCM 身份验证仍由服务完成。终态 pending 的 NULL 清理继续允许，普通计数更新不改变密文。

确认旧 pending 时，验证原秘密后使用当前 writer 重新加密，再提交活动因素，不直接复制旧 envelope。主密钥操作不修改 auth_epoch、不清除 MFA 限制、不重新注册因素，也不重置时间步或失败计数；真正因素确认仍按原流程 fence 并要求重新认证。

分批重加密先按 UUID 顺序锁定身份，`SKIP LOCKED` 跳过忙用户，再锁因素并共享锁定当前 writer；不先持控制行锁等待身份。每批 1–100 个用户，同一用户的活动和 pending 一起处理；只改 `secret_cipher` 并在同事务记录更新数量。异常或提交失败回滚整批。已提交批次不依赖进程内游标，重复运行只查仍引用旧 key 的记录；有忙用户时一次返回 0 不代表整体完成。

## 操作员 CLI 与发布顺序

使用已打包服务，不启动 Web、Redis 或 LDAP：

```powershell
java '-Dloader.main=com.test.examples.unipass.server.MfaKeyAdminCli' -cp iam-server/target/iam-server-0.1.0-SNAPSHOT-exec.jar org.springframework.boot.loader.launch.PropertiesLauncher status
```

统一需要 `UNIPASS_DB_URL/USER/PASSWORD` 与当前 key 配置。变更命令还要求 `UNIPASS_OPERATOR_REF`、`UNIPASS_EVIDENCE_REF`，为 3–200/500 位审计引用，允许字母、数字及 `_.:@/-`。这是受信的离线数据库操作员边界，不新增 HTTP 管理入口，也不会自动验证工单的业务真实性。

| 命令参数 | 行为 |
|---|---|
| `migrate` | 显式执行 Flyway，不需要加载密钥 |
| `status` | 只输出当前 writer、id、材料指纹、状态及数据库引用数 |
| `introduce <id>` | 登记本机已安装 key，AVAILABLE；相同材料重复操作返回 changed=false |
| `activate <id>` | 串行切换 writer；不改因素，当前已激活则 changed=false |
| `rekey <1..100>` | 提交一个可重入批次，输出 changed_rows；统计的是因素记录数 |
| `verify` | 流式读取全部非空因素密文，验证已登记材料、owner/AAD 与 tag，仅输出 verified_rows |
| `retire <id>` | 拒绝当前 writer 或仍有引用的 key；完整验密通过后标记 RETIRED，重复退役返回 changed=false |

发布步骤：

1. 保留原 legacy 材料，完成 V9 迁移并升级全部 MFA 写入节点，继续使用 legacy writer。首次初始化之前的新密文写入会被拒绝，不应在迁移间隙重放秘密提交。
2. 生成并安全持久保存新 key，先安装到全部节点的 key ring，并滚动重启使服务加载，再由 CLI introduce。没有环境变量热重载机制；核对 AVAILABLE 指纹与节点配置，没有逐节点验证证据时不能宣称整个集群已准备好。
3. activate 新 id。已持共享锁的 MFA 写事务先完成；其后新秘密只能使用新 writer。遗漏升级/配置的节点会拒绝需要该 key 的操作，不能降级写旧格式。
4. 反复 rekey，查看 status，直到所有非当前 key 的引用数为 0；忙用户稍后重试。取消、过期等正常流程可减少 pending 引用，不替代活动因素迁移。
5. verify，再 retire 旧 id。退役在控制行排他锁下再次检查引用并流式验密，失败不改退役状态；执行期间 MFA 加解密可能等待。事务/数据库调用有超时，规模与持锁时延需 T9 实测，不从小规模通过推断生产无感。
6. 所有节点重启并移除已退役材料。Java 运行对象可能仍持旧 SecretKeySpec，数据库退役不等于已经擦除进程内存或企业备份。

同 id 禁止换材料，已退役 id 禁止再引入/激活。需要在退役前回切 writer 时，旧 id 必须仍 AVAILABLE、各节点同时具备新旧材料，再按同样流程分批回迁；V1-only 程序不能直接回退读取 V2。备份恢复必须保留其对应 key 版本和控制状态，不能把旧库快照直接恢复到已移除旧 key 的实例。企业 KMS、备份恢复、全节点滚动与灾备演练仍属 T11，未在本次本地测试中签收。

## 验证范围

`MfaSecretCipherTest` 覆盖 V1 兼容、V2 owner/key-id AAD、tag 篡改、未知 key 和格式/配置拒绝。`MfaKeyRotationIT` 在真实 PG 中先建 V8 并写入活动与 pending，再升级 V9，覆盖首次错误材料不固化指纹、状态和计数保留、旧节点写入拒绝、旧材料退役/缺失/漂移、坏密文批次回滚、跳锁后续跑、双 worker、切换等待在途写入、提交时故障回滚，以及实际可执行 JAR 的完整 CLI 流程且不输出 key。OIDC HTTP 增量覆盖切换期间现有授权继续有效、旧 pending 按新 writer 提交、新因素可验证；因素确认仍撤销旧授权。

统一验证命令沿用 `scripts/verify-all.ps1 -RedisExecutable <Redis路径>`，Gradle 分支运行等价集成测试。P2–P5 的其余实现与外部验收继续保留。

2026-10-21 07:55:07（Asia/Shanghai），JDK 17.0.12 / Maven 3.9.11 最终源码全量脚本成功，约 227 秒，五模块 **122 项**测试，失败/错误/跳过均为 0。MFA envelope 单测由 1 增为 3，新 PG 密钥轮换集成 8，OIDC HTTP 由 42 增为 43，独立 RP 15 项保持通过。功能提交 `6486859`，首次材料校验补强 `e5d1a4a`；本次执行包含实际服务 JAR 的密钥 CLI，不以补强之前的 121 项证明新增检查。

2026-10-21 07:56:39（Asia/Shanghai），`build/gradle-jdk17` 合并至 `f84e2df` 后完成 Gradle Wrapper 8.14.3 / JDK 17 的 `clean build --offline`，约 244 秒，37 个任务全部执行，**122 项**测试失败/错误/跳过均为 0。五模块源码与 Maven 主线一致，IAM/RP 的运行库名称与版本分别为相同的 80/67 项。仓库未配置 remote，`gh run list --limit 1` 无法定位仓库，远程 Actions 未验证。

# 角色口径与 USER_OPERATOR 预留

> 本文记录 T8 管理权限的实际部署口径，以及"预留但不授予能力"的 `ROLE_USER_OPERATOR`。状态为**编码增量**，仅由远程 CI 验证。

## 1. 实际角色矩阵

| 角色 | 角色管理 | 审计读取/导出 | 应用/客户端管理 | 说明 |
|---|---|---|---|---|
| `ROLE_SYSTEM_ADMIN` | 是 | 是 | 是 | 首个席位由离线 `AdminRoleCli` 建立；不能撤销自己的最后一个 SYSTEM_ADMIN |
| `ROLE_ADMIN_APP` | 否 | 否 | 是 | 应用登记/编辑/停用/删除/轮换/窗口/回调历史 |
| `ROLE_ADMIN_AUDIT` | 否 | 是 | 否 | 只读审计列表/导出/归档校验 |
| `ROLE_USER_OPERATOR` | 否 | 否 | 否 | **预留**：可被授予，但本增量不授予任何控制台能力 |
| 密码/MFA 恢复角色 | 否 | 否 | 否 | 与上述管理权限完全独立，不因管理角色被授予而自动获得，反之亦然 |

- 所有检查都读取 `iam_user_role` 的**实时**行，不信任登录会话里冻结的 roles；应用管理写路径在事务内锁后复核。
- 只有 `ASSIGNABLE` 集合中的角色可被授予/撤销；`ROLE_USER_OPERATOR` 已纳入该集合，但不在 `ClientAdminService`/`AdminConsoleService` 的任何授权集合中。

## 2. 与任务书命名的差异（显式决定）

任务书使用 `ROLE_APP_ADMIN` / `ROLE_AUDITOR`；当前部署使用 `ROLE_ADMIN_APP` / `ROLE_ADMIN_AUDIT`。本增量**不**同时注册两套别名：

- 双名会让"授予一个角色却静默获得另一个名字的能力"变得难以审计，违背"角色不得静默授予另一角色"。
- 改名需要数据迁移、门户/CLI/文档同步与重新验证；在未完成前，以本文和 docs/29 的实际名称为准。
- 如后续决定改名，应新增迁移把现有行重命名并保留审计可追溯，而不是并存。

## 3. USER_OPERATOR 的边界

- 可被 SYSTEM_ADMIN 通过控制台或离线 CLI 授予/撤销；授予本身是显式的、可审计的。
- 不满足 `requireConsole`（需要 SYSTEM_ADMIN）、`requireAuditReader`（AUDIT/SYSTEM_ADMIN）、`requireAppAdmin`（ADMIN_APP/SYSTEM_ADMIN）中的任何一个。
- 不触发任何"用户操作"接口，因为本增量没有交付用户操作面；保留该角色是为了后续用户运营能力有稳定的授权载体。
- 负向测试：持有 `ROLE_USER_OPERATOR` 的账户访问角色管理、审计、应用管理均 403。

## 4. 测试

- `AdminConsoleIT.reservedUserOperatorIsAssignableButGrantsNoConsoleCapability`：授予成功、角色行存在、`requireConsole`/`requireAuditReader` 均 403。
- `ClientManagementHttpIT`：`ROLE_USER_OPERATOR` 对应用写 403（既有用例）；控制台角色页可授予该角色（前端列表已加入）。
- 未本地运行；以远程 Maven JDK 17 CI 为准。

## 5. 未做

- 真正的用户运营操作面（查询/禁用/会话管理）及其细粒度权限。
- 角色重命名迁移与双名兼容策略。
- 字段级审计脱敏（见 docs/32 N3）。

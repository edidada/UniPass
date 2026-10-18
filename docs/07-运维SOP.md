# UniPass 企业统一登录平台 — 运维 SOP

> 修订提示（2026-10-18）：本文为初版方案。实施前须结合 [设计基线与待确认事项](09-设计基线与待确认事项.md)、[技术选型](08-技术选型与决策记录.md) 和 [分任务详细设计](README.md)；冲突以修订基线为准，示例未经过部署验证。

| 项目 | 内容 |
|------|------|
| 文档编号 | UniPass-OPS-001 |
| 文档版本 | V1.0 |
| 编制日期 | 2026-10-18 |
| 生效条件 | 验收文档（QA-001）签字通过后由运维团队正式接管并签署确认单 |

**修订记录**

| 版本 | 日期 | 修订人 | 说明 |
|------|------|--------|------|
| V1.0 | 2026-10-18 | 运维组 | 首版，巡检/告警/故障预案/变更/备份演练/联系人 |

---

## 1. 职责边界

运维负责：节点与服务进程、目录可用性、Redis/PG/LB、证书与密钥有效期、监控告警响应、同步队列健康、变更执行与回滚、故障处置与升级。

不负责（需升级至对应 Owner）：业务应用自身的接入配置问题（应用 Owner）、飞书开放平台策略变更（飞书管理员）、AD 域控底层故障（域管理员）、代码缺陷修复（后端）。

值班方式：7×8 常规值守 + 7×24 电话轮值（P1 场景）；每日 09:00 前完成日常巡检并登记。

---

## 2. 日常巡检

### 2.1 每日巡检（09:00 前完成）

| 检查项 | 命令/方法 | 正常标准 |
|--------|----------|---------|
| IAM 节点健康 | `curl -s https://iam.corp/actuator/health` | `{"status":"UP"}` |
| LDAP 复制状态 | `ldapsearch -H ldaps://ldap-master -D "cn=admin" -w *** -b "cn=config" olcSyncrepl` | 从节点 `lag` < 5 秒 |
| 认证成功率 | 查询 Prometheus `rate(iam_auth_total{result="fail"}[5m])` | 失败率 < 0.5% |
| 飞书同步队列积压 | `select count(*) from sync_task where status='pending'` | < 10 |
| 磁盘使用率 | `df -h` 于应用节点 | < 75% |

补充每日项：

| 检查项 | 方法 | 标准 |
|--------|------|------|
| `DEAD` 任务 | `select count(*) from sync_task where status='dead'` | 0；>0 须当日处置并记录原因 |
| JVM | `GET /actuator/metrics/jvm.memory.used`、GC 暂停 P99 | 老年代 < 75%，GC 暂停 < 200 ms |
| Redis | `redis-cli -s info` → `connected_clients`、`used_memory_ratio`、Sentinel `master_failover_state` | normal，内存 < 70% |
| PG 主从复制延迟 | `SELECT now()-pg_last_xact_replay_timestamp()` 于从库 | < 10 s |
| 证书剩余有效期 | `echo \| openssl s_client -connect pass.corp.example.com:443 2>/dev/null \| openssl x509 -noout -enddate` | > 30 天 |
| 改密事件量 | `audit_log` 按日聚合 `PASSWORD_CHANGE` | 与历史均值偏离 < 50%（异常波动可能是撞库或策略变更） |
| 登录失败 Top IP/账号 | 审计查询 | 无异常集中；异常则核查是否撞库 |
| 错误日志 | 节点 `grep -E "ERROR\|FATAL"` 最近 24 h | 无新增未知类型 |

巡检结果写入《巡检登记表》（含时间、执行人、异常项与处理动作），连续 3 天同一项异常须升级为变更需求。

### 2.2 周期任务

| 周期 | 事项 |
|------|------|
| 每周 | 备份恢复抽检（恢复一份备份到隔离环境并跑冒烟 S1–S3）；慢查询与容量趋势；飞书 API 配额与错误码分布 |
| 每月 | 离职账号与 HR 名单对账；权限最小化复查（管理员名单）；日志归档；限流阈值与真实峰值复核 |
| 每季 | 密钥轮换演练；故障演练（§5 场景至少 2 项）；容量规划评审；SOP 有效性回顾 |
| 每年 | 等保复评配合；灾难恢复（DR）切换演练；全量回归验收项 A1–A8 |

---

## 3. 监控与告警

| 指标 | 警告 | 严重（P1 呼叫） |
|------|------|----------------|
| 认证失败率（5 min） | > 2% | > 5% 持续 3 min |
| `/oauth/token` P99 | > 500 ms | > 1.5 s 持续 5 min |
| IAM 节点存活数 | < 2 | = 0 |
| LDAP bind 错误率 | > 1% | > 10% 或熔断打开 |
| `sync_task` pending | > 50 | > 500 或最老任务 > 30 min |
| `sync_task` dead | ≥ 1 | ≥ 20 |
| Redis 主从切换 | 发生即通知 | 10 min 内 2 次 |
| PG 复制延迟 | > 30 s | > 120 s |
| 磁盘 | > 80% | > 90% |
| 证书 | < 30 天 | < 7 天 |
| 单 IP 登录失败 | > 50/min | > 200/min（疑似撞库，联动安全） |

告警必须带 `trace_id`/节点/指标当前值与 SOP 场景编号，值班据此直接进入对应处置流程。

---

## 4. 故障处理预案

### 场景 A：LDAP 主节点宕机

1. 确认从节点已提升为主（或手动切换）。
2. 修改 IAM 配置中 LDAP URL 指向新主。
3. 滚动重启 IAM 节点。
4. 恢复原主节点后，重新加入复制拓扑。

执行细节与判定：

- 先区分"目录进程故障"与"网络分区"：`ldaps://` 端口 telnet 通但 bind 报错 → 服务侧问题；不通 → 网络/主机。
- 手动提升（OpenLDAP mirrormode 可双向写，无须改配置；非 mirrormode 需重建 syncrepl 指向）。
- 切换期间**改密接口必须拒绝**（宁失败不静默错误），登录可降级读从节点。
- 原主回归后先以只读加入，确认复制收敛（`contextcsn`/AD USN 一致）再放开写。
- 事后核对：切换窗口内的改密请求是否落地（查 `audit_log` 与目录 `pwdLastSet`/`modifyTimestamp`）。

### 场景 B：飞书密码同步失败

1. 检查 `sync_task` 表中 `status=failed` 的记录。
2. 查看飞书 API 返回码：若为 `99991663`（token 过期），刷新 `tenant_access_token` 后重试。
3. 若为权限不足，检查飞书应用权限是否被回收。
4. 对失败任务执行重试：`POST /admin/sync/retry/{taskId}`。

扩展判断表：

| 飞书返回 | 含义 | 处置 |
|---------|------|------|
| `99991663`/`99991661` | tenant/app_access_token 失效 | 清 Redis 缓存 key `unipass:feishu:tenant_token` 后重试 |
| `99991672`/权限类 | 应用权限被回收或未申请 | 飞书管理员重新授权；期间确认降级路径（`SUCCESS_DEGRADED`）是否生效 |
| `100`/`230001` 用户不存在 | 映射缺失或该员工非本企业成员 | 修 `iam_user_external_binding`，重跑绑定同步 |
| `99991400` 频控 | 超出调用配额 | 降低消费并发，错峰重放 |
| 5xx / 超时 | 飞书侧抖动 | 交由自动重试；连续 3 次进 `DEAD` 后人工处理 |
| 网络不通 | 出站白名单/DNS/代理 | 基础设施排查，同时确认降级不阻断改密 |

**注意**：本场景任何情况下都不应阻塞员工改密。若发现改密接口因飞书而失败，属于实现缺陷，按 P1 上报开发。

### 场景 C：Windows 域用户无法登录且 IAM 密码正确

1. 在域控上运行 `dcdiag` 检查 AD 健康。
2. 确认 IAM 到 AD 的 LDAP 绑定账号未过期。
3. 检查 AD FS 信赖方信任证书是否过期（默认 1 年）。

扩展排查顺序：

1. 判断范围：个别人 / 某台机器 / 全员。全员 → 域控或复制问题；单机 → 机器信任关系（`Test-ComputerSecureChannel`，必要时重新加域）；个人 → 账号状态与锁定。
2. 时钟偏差（> 5 分钟 Kerberos 直接失败）：`w32tm /query /status`。
3. IAM 侧确认：目录中该账号 `userAccountControl` 是否含锁定位、密码是否真正写入（`pwdLastSet` 时间）。
4. AD FS 路径失败时另查：登录 IAM 是否正常、SAML 断言是否被 AD FS 接受（信赖方日志）、声明规则映射。
5. 恢复后必做：用该员工账号跑一次 A5 端到端检查，确认 Web/App 与 Windows 凭证一致。

### 场景 D：改密后旧会话未失效（安全类，最高优先级）

1. 立即确认影响范围：检查 `pwd_ver` 校验是否在网关生效（用改密前签发的 token 复现）。
2. 应急止血：`DELETE /admin/sessions/{userId}` 强制下线受影响账号；若为普遍失效机制问题，对全量在线会话执行吊销（会造成全员重登，需公告）。
3. 根因定位方向：Redis 吊销是否执行成功、`password_changed_at` 是否更新、校验代码分支是否被绕过、缓存击穿后目录读到的旧值。
4. 定性为 P1，通知安全与架构，出具事件报告；期间提高登录失败与令牌异常监控灵敏度。

### 场景 E：LB / Nginx 故障或 VIP 漂移

1. 确认 VIP 在活跃节点（`ip addr` / VRRP 状态）。
2. 检查 upstream 健康检查是否误摘（`max_fails` 抖动）；必要时手工置为 down/up 恢复部分流量。
3. 单节点承载期间关注限流与 P99，必要时临时下调非核心接口（如审计导出）QPS。
4. TLS 握手失败排查证书链与 SNI；`X-Forwarded-Proto` 缺失会导致回调地址降级为 http，属配置故障需即时修正。

### 场景 F：Redis 会话集群异常

1. Sentinel 未自动切换 → 手动 `redis-cli -p 26379 sentinel failover unipass-session`。
2. 数据全丢场景：所有在线用户需重新登录。这是可接受结果，**严禁**为"减少投诉"而临时关闭会话校验。
3. 恢复后确认 `unipass:token:refresh:*` 与 DB `iam_session` 一致性，孤儿 refresh 记录清理。
4. 检查是否内存打满触发 `allkeys-lru` 过度淘汰 → 扩容或缩短会话 TTL（走变更）。

### 场景 G：疑似撞库 / 密码喷洒攻击

1. 观察特征：同 IP 对多账号失败、失败率突增而成功率不降。
2. 处置：确认 L3/L4 限流生效（临时下调该 IP 段阈值）；必要时在 LB 层封禁；对已命中弱口令账号强制改密并下线。
3. 上报安全，保留 `audit_log` 证据（导出时间范围、IP 列表、账号列表）。
4. 事后：核查是否发生账号接管，审计异常登录 IP/设备。

### 场景 H：服务节点内存泄漏 / 频繁 Full GC

1. 摘流该节点（LB 置 down），保留现场。
2. `jcmd <pid> GC.heap_info`、`jstack`、必要时 `jmap -histo:live`；确认是否令牌/会话对象堆积。
3. 重启恢复服务，事后提交 heap dump 给开发定位。
4. 若两节点同时异常，按场景 D 的安全优先原则处理，禁止降级放行。

---

## 5. 变更管理

- 任何 IAM 配置变更（客户端密钥、回调地址、密码策略）须通过变更单审批。
- 变更窗口：非业务高峰（建议 20:00–22:00）。
- 变更前：备份 `application.yml`、LDAP `cn=config`、数据库 `iam_user` 表。
- 回滚条件：认证失败率 > 5% 持续 3 分钟，立即回滚配置并重启节点。

变更流程补充：

| 阶段 | 动作 | 硬性要求 |
|------|------|---------|
| 申请 | 变更单写明动机、影响面、步骤、验证方法、回滚方案 | 无回滚方案不批 |
| 审批 | 运维 Owner + 架构（涉及策略/协议/密钥时 + 安全） | 密码策略与密钥类必须双签 |
| 预演 | 在预生产执行一遍完整步骤 | 保留执行记录 |
| 执行 | 蓝绿/单节点灰度先行；每次仅一项变更 | 禁止合并多项未验证变更 |
| 验证 | 冒烟 S1–S5 + 变更后 30 分钟指标观察 | 指标不达标即回滚 |
| 收尾 | 更新配置基线文档与 CMDB，关闭变更单 | 基线未更新视为变更未完成 |

高风险变更清单（须演练 + 双人执行）：JWT 签名密钥轮换、密码策略调整、目录 Base DN/复制拓扑变更、AD FS 证书更换、会话 TTL 调整、飞书应用凭证更换。

**密钥轮换标准动作**：JWKS 同时保留新旧 `kid` → 新令牌用新 `kid` 签发 → 观察 ≥ 24 h（旧令牌自然过期）→ 从 JWKS 摘除旧 `kid` → 关闭旧密钥引用。中途任何 RP 报 `invalid signature` 均须检查其 JWKS 缓存刷新周期。

---

## 6. 备份与恢复

| 对象 | 频率 | 保留 | 恢复验证 |
|------|------|------|---------|
| PostgreSQL | 每日全量 + WAL 归档 | 30 天 | 每周抽检 1 份 |
| LDAP 数据（slapadd 导出 LDIF / AD 系统状态） | 每日 | 14 天 | 每月 |
| `application.yml` 与 Nginx/AD FS 配置 | 每次变更前后 | 版本化留存 | 随变更 |
| 审计日志 | 实时双写 + 每日归档 | 在线 6 个月，归档 ≥ 12 个月 | 每季 |
| 飞书绑定映射表 | 每日 | 30 天 | 随 PG |

RPO ≤ 5 分钟，RTO ≤ 30 分钟（应用层重建 + 数据回放）。恢复后必须先跑冒烟 S1–S7 再对外发布。

---

## 7. 应急联系与升级路径

| 角色 | 职责 | 联系方式 |
|------|------|---------|
| IAM 运维负责人 | 服务恢复 | 值班手机 |
| 飞书管理员 | 飞书侧权限/接口问题 | 飞书内部群 |
| Windows 域管理员 | AD/域控故障 | 分机 |

| 角色 | 职责 | 联系方式 |
|------|------|---------|
| 后端值班（IAM） | 代码缺陷、协议问题 | 值班群 |
| 安全工程师 | 撞库、令牌异常、事件定性 | 电话 |
| 基础设施/网络 | LB、DNS、证书、公网白名单 | 工单 + 电话 |
| HR 系统 Owner | 员工号数据异常、离职同步不一致 | 邮箱 |

**升级路径**：一线值班（10 分钟内响应）→ 运维负责人（P1 立即）→ 架构 + 开发负责人 + 安全（30 分钟未止血）→ IT 负责人（60 分钟未止血或影响全员登录）。

**公告模板**（影响登录时必须发布）：故障现象与开始时间 / 影响范围（哪些端）/ 当前处置动作与临时规避方式（如"请使用域账号直接在 Windows 登录"）/ 下次更新时间。全员强制重登前必须提前公告。

---

## 8. 附录：命令速查

```bash
# 健康与令牌
curl -s https://iam.corp/actuator/health
curl -s https://iam.corp/.well-known/openid-configuration | python -m json.tool

# 同步队列
psql -d unipass -c "select status,target_system,count(*) from sync_task where created_at>now()-interval '1 day' group by 1,2 order by 3 desc;"
psql -d unipass -c "select id,user_id,target_system,retry_count,left(last_error,120) from sync_task where status in ('failed','dead') order by created_at desc limit 20;"

# 手动重试
curl -s -X POST https://iam.corp/admin/sync/retry/10086 -H "Authorization: Bearer ${ADMIN_TOKEN}"

# 强制下线
curl -s -X DELETE https://iam.corp/admin/sessions/u-10086 -H "Authorization: Bearer ${ADMIN_TOKEN}"

# 会话吊销核查（Redis）
redis-cli -p 6379 --scan --pattern 'unipass:token:refresh:u-10086*' | head
redis-cli -p 6379 smembers unipass:user_sessions:10086

# 目录
ldapsearch -H ldaps://ldap-master:636 -x -D "cn=iam-bind,ou=service,dc=corp,dc=example,dc=com" -W -b "ou=users,dc=corp,dc=example,dc=com" "(employeeNumber=E10086)" modifyTimestamp pwdLastSet
# Windows 侧（域控/客户机）
dcdiag /v
repadmin /showrepl
w32tm /query /status
Test-ComputerSecureChannel -Verbose

# 审计
psql -d unipass -c "select action,result,count(*) from audit_log where created_at>now()-interval '1 hour' group by 1,2 order by 3 desc;"
psql -d unipass -c "select created_at,action,result,ip from audit_log where user_id=10086 order by created_at desc limit 20;"

# 证书与密钥
echo | openssl s_client -connect pass.corp.example.com:443 2>/dev/null | openssl x509 -noout -dates -subject
curl -s https://iam.corp/.well-known/jwks.json | python -m json.tool | grep -E '"kid"'
```

**日志定位口径**：以 `trace_id` 串联 `unipass-iam` → `sync_task` → Connector 出站日志；查不到 `trace_id` 时用「账号 + ±60 秒时间窗」在审计表反查。禁止在排查过程中把用户口令粘贴进工单或群聊。

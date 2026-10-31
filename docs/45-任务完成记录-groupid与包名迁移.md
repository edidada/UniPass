# 任务完成记录：groupId、包名与启动验证

> 记录 2026-10-31 的 Maven groupId 调整、Java 包名迁移、CI 启动验证与 GitHub 账户切换。

## 1. Maven groupId

全部 Maven `pom.xml`（root、各模块 parent、模块间依赖）中的：

```xml
<groupId>com.unipass</groupId>
```

已改为：

```xml
<groupId>com.test.examples</groupId>
```

共 12 处，已确认无 `com.unipass` groupId 残留。

## 2. Java 包名

Java 源码包名与目录已统一迁移为：

```text
com.test.examples.unipass.*
```

迁移范围包括各模块 `src/main/java`、`src/test/java` 目录、`package`/`import`、测试中的 `-Dloader.main`、Spring Boot `mainClass` 与脚本中的类名。Java 包名与 Maven groupId 不要求逐字相同：groupId 为 `com.test.examples`，Java 包为 `com.test.examples.unipass`。

## 3. 启动报错与 GitHub Actions 验证

本地 `iam-web` 的直接报错是缺少 `UNIPASS_RP_ID`；完整原因与 IDEA/Maven 配置见 [本地 iam-web 启动与 RP 配置](44-本地iam-web启动与RP配置.md)。

按“不在本地启动、不装 Docker”的要求，改为在 GitHub Actions 中启动：

- workflow 新增 `Start iam-web and verify health`
- 使用 runner 的 Redis 6380 + 独立密码
- 注入完整 `UNIPASS_RP_*` 环境变量
- 启动 `iam-web-0.1.0-SNAPSHOT-exec.jar`
- 轮询 `http://127.0.0.1:8081/health`

结果：

| 项 | 结果 |
|---|---|
| 运行 | `41183342890`（`edidada/UniPass`） |
| 结论 | success |
| 测试 | 248 项，0 失败/错误/跳过 |
| 启动步骤 | success，约 4 秒 |
| 健康检查 | `{"status":"UP"}` |

## 4. GitHub 账户与远端

- `gh` 活动账户：`edidada`
- `origin`：`ssh://git@github.com/edidada/UniPass.git`
- 推送：`766212d..fef157f main -> main`（非 force）
- 本机 `github.com:443` 不通，使用 SSH 推送；同一 `edidada/UniPass` 仓库
- 其他 remote（gitee/wiseism/wdidada126）未删除，但不再作为 `origin`

## 5. 备注

- 不提交任何真实 secret；CI 使用 test-only 值。
- `application.yml` 保持 fail-closed，不为 `UNIPASS_RP_*` 增加开发默认值。
- 包名迁移后旧命令中的旧包类名需要同步更新；本文与 docs/44 已按新包名记录。

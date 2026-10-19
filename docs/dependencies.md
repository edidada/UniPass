# 分阶段依赖基线

2026-10-18 锁定；具体来源为 Maven Central 与各依赖 POM，未声明为最新版本。生产部署前仍需安全扫描与支持周期复核。

| 依赖 | 版本 | 用途 | 许可证 |
|---|---|---|---|
| Java | 编译 release 17，本机 Oracle JDK 17.0.12 | 当前本地构建；生产建议 JDK 21，尚未验证 | 按选用 JDK 发行版确认 |
| Maven | 本机 3.9.11 | 多模块构建 | Apache-2.0 |
| UnboundID LDAP SDK | 7.0.3 | LDAPS、AD/OpenLDAP 适配与测试服务器 | POM 包含 Apache-2.0 可选许可 |
| PostgreSQL JDBC | 42.7.8 | 业务数据库访问 | BSD-2-Clause |
| Flyway core / database-postgresql | 11.13.2 | 版本化数据库迁移 | Apache-2.0 |
| Commons CSV | 1.14.1 | RFC 4180 CSV 解析 | Apache-2.0 |
| JUnit BOM | 5.13.4 | 单元与集成测试 | EPL-2.0 |
| Zonky Embedded PostgreSQL | 2.2.2 | 测试时启动本机隔离 PG 进程 | Apache-2.0 |
| Embedded PG binaries BOM | 17.6.0 | 测试数据库 PostgreSQL 17.6 | PostgreSQL 及分发组件许可证 |
| compiler / surefire / failsafe / shade 插件 | 3.14.1 / 3.5.4 / 3.5.4 / 3.6.1 | 编译、测试、打包 | Apache-2.0 |

上述为 P1/P2 领域库的显式基线。JDK 17 是兼容构建下限，未修改生产 JDK 21 建议。

## P2 服务运行时

`iam-server` 导入 Spring Boot **3.5.16** 官方 BOM；其传递依赖会覆盖领域库的间接运行时版本。2026-10-18 已从实际打包的 `BOOT-INF/lib` 核对：

| 组件 | 服务运行时版本 | 用途 |
|---|---|---|
| Spring Authorization Server | 1.5.8 | OAuth/OIDC 协议 |
| Spring Security | 6.5.11 | 认证、过滤器与 JWT |
| Spring Session core/data-redis | 3.5.7 | Redis 会话 |
| UnboundID LDAP SDK | 7.0.4 | 领域网关在服务中的运行版本 |
| Flyway core/database-postgresql | 11.7.2 | V1–V6 服务迁移 |
| PostgreSQL JDBC | 42.7.11 | PG 连接 |
| Jackson databind/core | 2.21.4 | JSON 及框架授权持久化 |
| Tomcat embedded | 10.1.55 | HTTP 容器 |
| java-otp | 1.0.0 | TOTP，MIT 许可；显式锁定版本 |
| Angus Jakarta Mail default provider | 2.0.5 | SMTP；EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0，来自实际 POM |

Spring 组件、Flyway、Jackson、Tomcat 为 Apache-2.0；JDBC 与 LDAP 许可见上表。服务可执行包 classifier 为 `exec`，测试库不打包；领域库与服务 BOM 运行时均由各自集成测试覆盖。支持截止日期、安全扫描、生产镜像摘要仍未取证，不把当前能构建解释为已通过生产安全审查。

运行库采用 POM 显式版本，测试库不进入可执行 JAR。传递依赖以 Maven 解析为准；实施升级时执行 `mvn dependency:tree` 并归档扫描结果。当前尚未执行漏洞扫描、生产镜像构建或支持周期审核，没有生产镜像摘要。

官方资料：[LDAP SDK 连接与 TLS](https://docs.ldap.com/ldap-sdk/docs/getting-started/connections.html)、[Zonky PostgreSQL 测试库](https://github.com/zonkyio/embedded-postgres)、[Maven Surefire](https://maven.apache.org/components/surefire-archives/surefire-3.5.4/maven-surefire-plugin/usage.html)。

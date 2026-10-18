# 第一阶段依赖基线

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

当前阶段未使用 Spring，不提前冻结 T2 的 Spring 协议栈。LDAP 网关通过接口隔离，T2 可在 Spring 运行时直接复用。JDK 17 是兼容构建下限，未修改生产 JDK 21 建议。

运行库采用 POM 显式版本，测试库不进入可执行 JAR。传递依赖以 Maven 解析为准；实施升级时执行 `mvn dependency:tree` 并归档扫描结果。当前尚未执行漏洞扫描、生产镜像构建或支持周期审核，没有生产镜像摘要。

官方资料：[LDAP SDK 连接与 TLS](https://docs.ldap.com/ldap-sdk/docs/getting-started/connections.html)、[Zonky PostgreSQL 测试库](https://github.com/zonkyio/embedded-postgres)、[Maven Surefire](https://maven.apache.org/components/surefire-archives/surefire-3.5.4/maven-surefire-plugin/usage.html)。

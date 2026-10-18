# UniPass

企业统一登录平台，覆盖统一身份目录、Web/App OIDC 登录、Windows 域集成、飞书应用接入及会话撤销。

按阶段实施中。第一阶段提供目录网关、HR 预览导入、离职禁用和操作员 CLI；第二阶段已加入可恢复改密与重置领域核心，OIDC/HTTP 认证边界仍待完成。真实企业目录尚未验收。

```powershell
pwsh -NoProfile -File scripts/verify-stage1.ps1
```

需要 JDK 17+、Maven 3.9+。该命令运行 LDAPS 与真实 PostgreSQL 17.6 测试并打包，不依赖 Docker。

[运行说明](docs/11-第一阶段运行与验证.md) · [改密核心](docs/12-第二阶段密码核心与恢复.md) · [阶段进度](docs/10-阶段实施进度.md) · [文档索引](docs/README.md) · [设计基线](docs/09-设计基线与待确认事项.md)

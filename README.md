# UniPass

企业统一登录平台，覆盖统一身份目录、Web/App OIDC 登录、Windows 域集成、飞书应用接入及会话撤销。

按阶段实施中。第一阶段提供目录网关、HR 预览导入、离职禁用和操作员 CLI；第二阶段已加入密码恢复核心、OIDC/PKCE、Redis 会话、刷新轮换、TOTP MFA、本人改密、邮件重置验证及管理员恢复。后续各端接入与真实企业环境验收仍在推进。

```powershell
pwsh -NoProfile -File scripts/verify-stage1.ps1
```

需要 JDK 17+、Maven 3.9+。该命令运行 LDAPS 与真实 PostgreSQL 17.6 测试并打包，不依赖 Docker。

OIDC 全量回归另需本机 Redis：`pwsh -NoProfile -File scripts/verify-all.ps1 -RedisExecutable 'redis-server 完整路径'`。

[运行说明](docs/11-第一阶段运行与验证.md) · [改密核心](docs/12-第二阶段密码核心与恢复.md) · [OIDC 服务](docs/13-第二阶段OIDC运行与验证.md) · [阶段进度](docs/10-阶段实施进度.md) · [文档索引](docs/README.md)

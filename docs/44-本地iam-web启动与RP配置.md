# 本地 iam-web 启动与 RP 配置

> 本文记录在 IDEA / Maven 下启动 `iam-web`（独立 RP）所需的配置，以及常见 `UNIPASS_RP_*` 占位符报错的原因。`iam-web` 采用 fail-closed：身份、密钥、Redis 密码均无默认值，必须显式提供。

## 1. 直接原因

`RpSettings` 构造器读取：

```java
id = env.getRequiredProperty("unipass.rp.id");
```

对应 `iam-web/src/main/resources/application.yml`：

```yaml
unipass:
  rp:
    id: ${UNIPASS_RP_ID}
```

IDEA 的 `WebApplication` 运行配置没有设置 `UNIPASS_RP_ID`，因此启动报：

```text
Could not resolve placeholder 'UNIPASS_RP_ID' in value "${UNIPASS_RP_ID}"
```

这不是代码缺陷，而是 RP 配置缺失时故意拒绝启动。

## 2. 必需配置

| 环境变量 | 要求 |
|---|---|
| `UNIPASS_RP_ID` | 3–60 字符，`[A-Za-z0-9_-]`，如 `crm` |
| `UNIPASS_RP_ISSUER` | IAM 的 origin，不带 path/query/fragment，如 `http://localhost:8080` |
| `UNIPASS_RP_ORIGIN` | 本应用 origin，如 `http://localhost:8081` |
| `UNIPASS_RP_CLIENT_SECRET` | 32–64 个可打印 ASCII，必须与 IAM 注册的客户端 secret 一致 |
| `UNIPASS_RP_SESSION_KEY` | Base64 编码的 **32 字节** AES key |
| `UNIPASS_RP_REDIS_PASSWORD` | 必填；`application.yml` 没有默认值 |
| `UNIPASS_RP_REDIS_HOST` | 默认 `127.0.0.1` |
| `UNIPASS_RP_REDIS_PORT` | 默认 `6379` |
| `UNIPASS_RP_PORT` | 默认 `8081` |

`local-http=true` 时还要求绑定 loopback 地址；建议显式传：

```text
--server.address=127.0.0.1 --unipass.rp.local-http=true
```

否则会报：

```text
Local RP requires a loopback bind address
```

## 3. IDEA 运行配置

Run/Debug Configurations → `WebApplication`：

**Program arguments：**

```text
--server.address=127.0.0.1 --unipass.rp.local-http=true
```

**Environment variables：**

```text
UNIPASS_RP_ID=crm
UNIPASS_RP_ISSUER=http://localhost:8080
UNIPASS_RP_ORIGIN=http://localhost:8081
UNIPASS_RP_CLIENT_SECRET=你的32到64位可打印secret
UNIPASS_RP_SESSION_KEY=Base64编码的32字节key
UNIPASS_RP_REDIS_HOST=127.0.0.1
UNIPASS_RP_REDIS_PORT=6379
UNIPASS_RP_REDIS_PASSWORD=你的本地Redis密码
UNIPASS_RP_PORT=8081
```

生成 32 字节 session key：

```powershell
$b = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
[Convert]::ToBase64String($b)
```

## 4. 外部依赖

1. **Redis 必须带密码启动**，例如：

   ```powershell
   docker run --rm -p 6379:6379 redis:7-alpine redis-server --requirepass dev-only-redis
   ```

   然后设置 `UNIPASS_RP_REDIS_PASSWORD=dev-only-redis`。

2. **IAM server 必须已启动在 `UNIPASS_RP_ISSUER` 上**，本地 HTTP 模式需允许 loopback：
   `--unipass.local-http=true --server.address=127.0.0.1`。

3. **IAM 中已注册对应客户端**：
   - `client_id = crm`
   - `client_secret = UNIPASS_RP_CLIENT_SECRET`
   - redirect URI 精确为 `http://localhost:8081/login/oauth2/code/unipass`
   - post logout 建议 `http://localhost:8081/`
   - backchannel `http://localhost:8081/logout/backchannel`
   - scopes `openid profile api.read`

   注册方式见 [第二阶段 OIDC 运行与验证](13-第二阶段OIDC运行与验证.md) 或 `ClientAdminCli`。

4. `UNIPASS_RP_ISSUER` / `UNIPASS_RP_ORIGIN` 不能带路径，例如不能写 `http://localhost:8081/portal`。

## 5. Maven 启动

```powershell
$env:UNIPASS_RP_ID='crm'
$env:UNIPASS_RP_ISSUER='http://localhost:8080'
$env:UNIPASS_RP_ORIGIN='http://localhost:8081'
$env:UNIPASS_RP_CLIENT_SECRET='dev-only-rp-secret-0123456789abcdef'
$env:UNIPASS_RP_SESSION_KEY='<base64-32-bytes>'
$env:UNIPASS_RP_REDIS_PASSWORD='dev-only-redis'
mvn -pl iam-web -am -DskipTests install
mvn -pl iam-web spring-boot:run "-Dspring-boot.run.arguments=--server.address=127.0.0.1 --unipass.rp.local-http=true"
```

启动成功后访问 `http://localhost:8081/health` 应返回 200。

## 6. 说明

- `lettuce-timer` 线程泄漏警告是启动失败后的副作用，不是根因。
- 不建议在 `application.yml` 中写开发默认 secret，会破坏 fail-closed；请用 IDEA 环境变量、EnvFile 插件或不入库的本地 profile。
- 只补 `UNIPASS_RP_ID` 后，后续还会依次要求 issuer/origin/secret/session-key/Redis 密码；按上表一次配齐。

# UniPass IAM — k3s 部署说明（R630 lab）

> 首装于 2026-11-01。遵循 `r630-proxmox8/cicd/runbook-onboard-new-java-app.md` 的流程。
> 本目录进入 git 的只有**无明文的清单**；所有口令在安装时以 Secret 形式注入集群。

## 依赖拓扑

```
unipass ns                          middleware ns（共享，复用不新建）
  unipass-iam (git-<sha>)            ├─ redis      6379  ← 会话/业务缓存（UNIPASS_REDIS_*）
  ldap (osixia/openldap, TLS 636)    └─ postgres   5432  ← 业务库（cicd/middleware/postgres.yaml 推入）
  svc unipass-iam NodePort 30083 + traefik IngressRoute https://unipass.lab
```

- Redis 用 `middleware/redis`（现有实例，密码来自 `middleware/redis-secret`）。因为
  `secretKeyRef` 不能跨命名空间，把密码复制到 `unipass/unipass-redis`。
- PostgreSQL 是共享中间件（`middleware/postgres`，postgres:17，镜像 `base/postgres:17`），
  应用库 `unipass`、账号 `unipass`。
- LDAP 是 UniPass 私有依赖（登录/改密/禁用必须目录），按 namespace 规划裁决放 `unipass` ns：
  osixia/openldap:1.5.0（镜像 `base/openldap:1.5.0`），自建 CA 签发的 ldaps 证书
  （`DirectoryConfig` 强制 `ldaps://`，SAN=DNS：ldap.unipass.svc.cluster.local）。
- issuer 必须是 https（`SecurityConfiguration` 只放行 https 或"local-http+回环"，NodePort http 不满足后者），
  所以经 traefik（k3s 自带，443 在所有节点）以 `https://unipass.lab` 暴露，TLS 用 traefik 默认证书。

## Secret 清单（安装时创建，不在 git）

| Secret | ns | key | 来源 |
|---|---|---|---|
| `postgres-secret` | middleware | postgres-password | 新随机（与 unipass-db 同值） |
| `unipass-db` | unipass | db-password | 同上（跨 ns 复制） |
| `unipass-redis` | unipass | redis-password | 从 `middleware/redis-secret` 复制 |
| `ldap-admin` | unipass | admin-password | 新随机（LDAP cn=admin 读写，OSIXIA bootstrap 同源） |
| `ldap-tls-ish` | unipass | ca.crt / ldap.crt / ldap.key | 自建 CA + 叶子（SAN=ldap.unipass.svc.cluster.local） |
| `unipass-signing` | unipass | signing.p12 + store-password + apptruststore.jks | keytool 生成 RSA2048（alias=current，3650d）；truststore 导入上述 CA（JKS，口令 changeit） |
| `unipass-mfa` | unipass | mfa-key | openssl rand -base64 32 |
| `galaxy-registry` | unipass | dockerconfigjson | master `/root/registry-credentials.txt` 的 PULL 账号 |

## 首装步骤

```bash
# 0) ns + 拉取凭据（runbook B §1）
ssh k3s-master
k3s kubectl create ns unipass
source /root/registry-credentials.txt
k3s kubectl -n unipass create secret docker-registry galaxy-registry \
  --docker-server=registry.galaxy.local:30500 \
  --docker-username=$REGISTRY_PULL_USER --docker-password=$REGISTRY_PULL_PASS \
  --dry-run=client -o yaml | k3s kubectl apply -f -
k3s kubectl -n unipass patch serviceaccount default \
  -p '{"imagePullSecrets":[{"name":"galaxy-registry"}]}'

# 1) 镜像入库（master podman，国内源拉取后推私有仓库）
podman pull docker.m.daocloud.io/library/postgres:17 && \
podman tag  docker.m.daocloud.io/library/postgres:17 registry.galaxy.local:30500/base/postgres:17 && \
podman push --remove-signature registry.galaxy.local:30500/base/postgres:17
# openldap 同理：docker.m.daocloud.io/osixia/openldap:1.5.0 → base/openldap:1.5.0

# 2) 应用镜像（win11 构建，tag=git-<短sha>）
mvn -B -pl iam-server -am package -DskipTests
TAG=git-$(git rev-parse --short HEAD)   # 镜像 tag 就是这个短 sha
# Dockerfile 见本目录；构建上下文只放 Dockerfile + <模块>*-exec.jar（fat jar）
docker build -t registry.galaxy.local:30500/unipass/iam-server:$TAG \
  --build-arg JAR_FILE=build/app.jar <临时上下文>
docker push registry.galaxy.local:30500/unipass/iam-server:$TAG

# 3) 清单：postgres（middleware）→ ldap → 最後 unipass-iam，逐个 rollout status 等绿
k3s kubectl apply -f middleware/postgres.yaml
k3s kubectl apply -f unipass/ldap.yaml
k3s kubectl apply -f unipass/k8s.yaml     # 部署前先把 image tag 换成 $TAG

# 4) 种子（改首发热装；命令式种子详见本次 runbook 报告）：
#    - LDAP 用户：kubectl exec deploy/ldap -- ldapadd ...（slappasswd 生成 {SSHA}，employeeNumber=E001）
#    - DB 行：kubectl exec deploy/postgres -- psql ...（iam_user.directory_id 取 entryUUID）
#    - 管理角色：kubectl exec deploy/unipass-iam -- \
#        java -cp /app/app.jar com.test.examples.unipass.server.AdminRoleCli grant E001 ROLE_ADMIN_APP
```

## 关键校验点（原理见报告）

- 镜像必须 `-exec.jar`（thin jar 会 `no main manifest attribute` 起 CrashLoop）。
- 探针用公开 `/portal/`（应用没有 actuator 端点，runbook 的 `/actuator/health/...` 在本项目不可用）。
- 改动 `UNIPASS_*` 后要 `rollout restart` 才生效；NodePort 冲突先查
  `k3s kubectl get svc -A | grep nodePort`。

## 现场已知坑（首次实施实测，见 smoke 报告 2026-11-01）

1. issuer 只能 https（非回环 http 会被 `SecurityConfiguration` 拒绝启动）。
2. 目录 URL 必须 `ldaps://`；证书 SAN=DNS：ldap.unipass.svc.cluster.local；应用 JVM 信任
   自建 CA（`unipass-signing/apptruststore.jks` + `JAVA_OPTS`）。
3. osixia/openldap：默认双向 TLS（`LDAP_TLS_VERIFY_CLIENT=never`）、ConfigMap 只读 chown 崩
   （initContainer 拷入 emptyDir）、k8s `LDAP_*` 环境变量冲突（`enableServiceLinks: false`）、
   收尾删挂载目录（`LDAP_REMOVE_CONFIG_AFTER_SETUP=false`）。
4. ldap Service 必须同时暴露 389+636（只写 389 时 636 无 kube-proxy 规则）。
5. 登录错口令累计触发 30min/10min 锁（redis `unipass:login:*`）；改密 60s per-user 守卫
   （`password_request_guard`）、MFA 失败 ≥5 次锁 30min（`mfa_totp.locked_until`）。
6. 改密前置：recent password + recent MFA + `UNIPASS_PASSWORD_HISTORY_VERIFIED=true`；
   请求体字段名 `old_password/new_password/confirm_password`。
7. 管理台写接口一律要 `Idempotency-Key`；MFA 每次 enroll 换新基座 secret（只读一次）。

## 回滚

- 应用：`k3s kubectl -n unipass rollout undo deploy/unipass-iam`（或 `set image ... $old_tag`）。
- 种子数据回滚：`psql ... "DELETE FROM iam_user_role WHERE user_id=?; DELETE FROM iam_user WHERE employee_no='E001';"`。
- LDAP 数据摧毁重来：删 `deploy/ldap` + `ldap-data`/`ldap-config` PVC 后重 apply（bootstrap 会重建）。

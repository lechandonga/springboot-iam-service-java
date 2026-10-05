# Spring Boot 本地 IAM 服务

在纯 Spring Boot（Web + Test）基础上实现的本地身份认证与访问控制：加盐不可逆口令、
失败锁定（并发安全）、短效访问令牌 + 一次性刷新令牌（重放即吊销会话链）、
角色 + 账号属性联合的最小权限授权（默认拒绝、DENY 优先）、只增不改的完整审计。

- 设计与错误码说明：[`docs/IAM.md`](docs/IAM.md)
- 场景测试：[`src/test/java/com/github/lechandonga/springbootiamservicejava/tests/iam`](src/test/java/com/github/lechandonga/springbootiamservicejava/tests/iam)

## 快速开始

```bash
mvn test                      # 跑全部场景测试，日志含【业务场景】【用例】【结果】
mvn spring-boot:run           # 启动（默认 8080）
```

种子账号：`admin/admin-pass-123`（管理员）、`alice/editor`、`bob/viewer`、
`carol`（试用期 editor）、`dave`（禁用）。

```bash
curl -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin-pass-123"}'
```

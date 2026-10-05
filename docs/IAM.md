# 本地身份认证与访问控制（IAM）说明

本服务在纯本地完成账号、角色、策略、会话的全部管理，不依赖任何外部身份服务，
仅使用 Spring Boot Web 与 JDK 内置加密能力（PBKDF2 / HMAC-SHA256 / SHA-256）。

## 1. 凭证模型

- 口令绝不以明文存储或记录。落库格式为 `迭代次数:salt(Base64URL):hash(Base64URL)`。
- 哈希算法为 **PBKDF2WithHmacSHA256**：每账号独立 16 字节随机盐、210,000 次迭代、
  256 位输出；相同口令在不同账号上的存储值不同，可抵御彩虹表与批量预计算。
- 校验使用常量时间比较（`MessageDigest.isEqual`），格式损坏、非法 Base64、空值
  一律安全返回“不匹配”，不向调用方抛底层异常。
- 登录失败处理（`iam.max-login-failures`，默认 5 次；锁定时长 `iam.lock-duration`，默认 15 分钟）：
  - 失败计数在**每账号锁对象内串行**完成，20 个并发错误登录也只会产生精确的
    `阈值-1` 次 BAD_CREDENTIALS，之后一律 ACCOUNT_LOCKED，无法并发绕过。
  - 达到阈值时账号写入 `lockedUntil`；锁定窗口内即使口令正确也返回 ACCOUNT_LOCKED。
  - 锁定窗口过期后计数自动清零，重新给予尝试预算。
  - 管理员重新启用账号（`enabled=true`）会显式清除锁定状态。
- 失败原因严格区分：未知用户名/口令错误 = `BAD_CREDENTIALS`；锁定 = `ACCOUNT_LOCKED`；
  禁用 = `ACCOUNT_DISABLED`。未知用户名与错误口令返回完全一致的结果，避免账号枚举。

## 2. 令牌与会话模型

- 登录成功后创建一条**会话链（SessionChain）**，返回：
  - 短效**访问令牌**（默认 10 分钟，`iam.access-token-ttl`）
  - **一次性刷新令牌**（默认 12 小时，`iam.refresh-token-ttl`）
- 令牌形态为 `base64url(JSON载荷).base64url(HMAC-SHA256签名)`，载荷含
  `typ / sub(账号) / cid(会话链ID) / jti / iat / exp`，签名密钥来自
  `iam.token-signing-secret`（生产环境务必更换）。
- 校验顺序：结构 → 签名（常量时间）→ 必填字段 → 类型 → 过期。每一步对应不同错误码，
  篡改载荷或签名段都会得到 `BAD_SIGNATURE`。
- 服务端只保存刷新令牌的 SHA-256 指纹，不保存令牌原文。
- **刷新轮换（refresh rotation）**：每次刷新签发新的访问令牌与新的刷新令牌，
  旧刷新令牌记入该会话链的“已消费”集合，立即作废。
- **盗用检测**：已消费的旧刷新令牌再次出现（签名合法但不是当前令牌）时，
  立即吊销整条会话链（`revoked`），本次返回 `REFRESH_REPLAY`；此后该链上
  已签发的全部访问/刷新令牌均失效（访问请求返回 `TOKEN_REVOKED`）。
- 登出、管理员禁用账号、管理员重置口令都会立即吊销对应会话链。

## 3. 授权规则

- **默认拒绝、最小权限**：没有任何策略匹配即为 DENY（`policy=default-deny`）。
- 策略按 `priority` 升序求值，第一条匹配的策略决定 ALLOW / DENY，显式 DENY
  可以压过通配 ALLOW。
- 主体（subject）支持三种写法，可同时表达角色与账号属性约束：
  - `role:admin` —— 账号当前角色
  - `attr:department=engineering` —— 账号当前属性（键值精确匹配）
  - `user:alice` —— 指定账号
  - `*` —— 任意已认证主体
- resource / action 支持尾部 `*` 通配（如 `document*`、`admin:*`、`*`）。
- **状态即时生效**：授权与认证过滤器每次请求都实时读取账号的启用状态、角色与
  属性，并检查会话链吊销位。因此已签发的令牌无需等待过期：角色被撤销立即失权，
  账号被禁用立即被拒（`ACCOUNT_DISABLED`）。
- 受保护资源由 `AuthenticationFilter` 统一鉴权，授权判定由 `AuthorizationService`
  统一完成；`/api/admin/**` 本身也走同一套引擎（资源名 `admin:account`、
  `admin:policy`、`admin:session`、`admin:audit`），不是硬编码开放。

## 4. 审计规则

- 每次登录成功/失败、账号锁定、刷新轮换、刷新重放、登出、放行、拒绝、
  管理员操作都写一条审计记录。
- 记录字段：`sequence`（进程内严格连续、无重复的全局序号）、`timestamp`、
  `eventType`、`subject`（谁）、`sessionChainId`、`resource`、`action`（对什么）、
  `result`（ALLOW/DENY/SUCCESS/FAILURE）、`decisionDetail`（依据哪条策略及原因），
  可完整还原“谁在何时对什么操作依据哪条策略得到什么结果”。
- 序列号分配与写盘在同一同步临界区，100 并发授权请求产生恰好 100 条记录、
  序号连续、无丢失无重复。
- 记录**只增不改**：系统不提供任何更新/删除审计的接口；内存快照不可变，
  同时以 JSON-lines 形式追加到 `iam.audit-log-file`（默认 `target/audit/audit.log`），
  文件只以 APPEND 方式打开。
- 审计查询本身也是受保护操作（`admin:audit/read`，默认仅 `role:admin`）。

## 5. 错误码

| code | HTTP | 含义 |
| --- | --- | --- |
| BAD_CREDENTIALS | 401 | 用户名不存在或口令错误（两者响应一致，防枚举） |
| ACCOUNT_LOCKED | 403 | 连续失败达到阈值，账号处于锁定窗口 |
| ACCOUNT_DISABLED | 403 | 账号被禁用（登录时与携带令牌时同一码） |
| MISSING_TOKEN | 401 | 未提供 Authorization: Bearer 令牌 |
| MALFORMED_TOKEN | 401 | 令牌结构/内容格式不合法 |
| BAD_SIGNATURE | 401 | 签名不合法或载荷被篡改 |
| TOKEN_EXPIRED | 401 | 令牌已过期 |
| TOKEN_REVOKED | 401 | 会话链已吊销（登出/禁用/重置口令/重放连带） |
| TOKEN_TYPE_MISMATCH | 401 | 访问/刷新令牌类型用错场合 |
| REFRESH_REPLAY | 403 | 一次性刷新令牌被重复使用，整条会话链已吊销 |
| ACCESS_DENIED | 403 | 已认证但无权限（默认拒绝或命中 DENY） |
| VALIDATION_ERROR | 400 | 请求体字段缺失或取值非法 |
| NOT_FOUND | 404 | 目标账号/策略不存在 |
| CONFLICT | 409 | 资源已存在 |
| INTERNAL_ERROR | 500 | 未预期内部错误（细节只写服务端日志，不外泄） |

## 6. HTTP 接口

公开：
- `POST /api/auth/login` `{username,password}`
- `POST /api/auth/refresh` `{refreshToken}`

需访问令牌：
- `POST /api/auth/logout`
- `POST /api/resource/access` `{resource,action}` —— 返回 `{allowed,detail,...}`
- `POST /api/resource/documents/read`、`POST /api/resource/documents/write` —— 受保护操作示例
- `/api/admin/accounts`（POST 创建 / GET 列表）、`/api/admin/accounts/{u}/enabled|roles|attributes|password`（PUT）
- `/api/admin/sessions/{username}`（GET 会话链状态）
- `/api/admin/policies`（GET/POST）、`/api/admin/policies/{id}`（DELETE）
- `/api/admin/audit`（GET 审计记录，仅管理员）

首次启动自动播种（仅当存储为空）：
- 账号 `admin/admin123`（role=admin）、`alice/alice123`（engineering/viewer）、`bob/bob123`（marketing/editor）
- 策略：admin 通配管理与文档；engineering 可读文档；editor 可写文档。

## 7. 本地验证方法

前置：JDK 21+、Maven 3.9+（本仓库在 JDK 25 上验证通过）。

```bash
mvn test
```

测试日志中可直接看到业务场景覆盖，关键行形如：

```
[IAM-场景] ========== 认证与锁定主流程 ==========
[IAM-用例]    连续失败达到阈值后账号锁定 (阈值=5) => PASS | ...
[IAM-场景] ========== 并发登录锁定 ==========
[IAM-用例]    并发结束后账号处于锁定状态 => PASS | BAD_CREDENTIALS=5, ACCOUNT_LOCKED=15
[IAM-场景] ========== 令牌轮换、重放吊销与失效原因区分 ==========
[IAM-场景] ========== 授权判定与权限/状态即时生效 ==========
[IAM-场景] ========== 审计完整性与并发写入 ==========
[IAM-用例]    审计不丢不重且序列号严格连续 => PASS | 该主体 AUTHZ=100; 全表序号连续
```

覆盖的关键场景对应测试类：

| 场景 | 测试类 |
| --- | --- |
| 口令加盐哈希算法 | `PasswordServiceTest` |
| 认证成功/失败/锁定/禁用区分 | `AuthLockFlowTest` |
| 并发登录不可绕过阈值 | `ConcurrentLoginTest`（20 线程并发错口令 + 8 线程并发正确口令） |
| 令牌轮换、重放吊销链、过期/吊销/坏签名/篡改/类型不符 | `TokenRotationTest` |
| 默认拒绝、角色+属性联合判定、撤权/禁用即时生效、DENY 优先 | `AuthorizationLiveChangeTest` |
| 审计可还原性、100 并发无丢无重序号连续、只增不改、落盘 JSON-lines | `AuditIntegrityTest` |

手工验证（启动后端口固定可用 `mvn spring-boot:run`，默认 `server.port=0` 随机端口，
需要固定端口可在命令行追加 `-Dspring-boot.run.arguments=--server.port=8080`）：

```bash
curl -s localhost:8080/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}'
```

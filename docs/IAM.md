# 本地身份认证与访问控制（IAM）说明

本模块在 Spring Boot 工程内提供完整的本地 IAM 能力：账号、角色、策略、会话全部在进程内存中管理，
不依赖任何外部身份服务或数据库，只使用 Spring Boot Web/Test 常规开源依赖，可本地重复验证。

## 1. 凭证模型

- 账号（`Account`）含：用户名、口令哈希、随机盐、角色集合、账号属性集合、启用状态、
  失败计数、锁定截止时间、**安全版本号 `securityVersion`**。
- 口令使用 `PBKDF2WithHmacSHA256`（迭代 120000 次、16 字节随机盐、256 位输出），存储格式
  `pbkdf2$iterations$saltB64$hashB64`，不可逆；登录用恒定时间比较。
- 登录失败计数在**账号对象监视器锁内**串行更新：并发错误登录最多计入阈值次数，
  达到 `iam.max-failed-attempts`（默认 5）即锁定 `iam.lock-duration`（默认 5 分钟）。
  锁定窗口内即使口令正确也返回 `ACCOUNT_LOCKED`；锁过期后自动解锁清零。
- 账号不存在时也执行一次哑哈希比较，降低用户名枚举的时间侧信道；错误码与坏口令一致。
- 失败原因区分：`INVALID_CREDENTIALS`（401）、`ACCOUNT_LOCKED`（423）、`ACCOUNT_DISABLED`（403）。

## 2. 令牌与会话模型

- 登录成功后创建 `Session`（会话链），签发：
  - **访问令牌（短效，默认 15 分钟）**：自包含签名令牌，
    格式 `base64url(payloadJson).base64url(HmacSHA256(payloadJson, 密钥))`。
    payload 含 `sub`（用户）、`sid`（会话 id）、`jti`（签发唯一 id）、`ver`（账号安全版本）、
    `iat`、`exp`。通过 `Authorization: Bearer <token>` 提交。
  - **刷新令牌（一次性，默认 14 天）**：48 字节高熵随机串，仅在签发响应中出现明文；
    服务端只存其 SHA-256 哈希与有效期，挂在会话链上。
- 刷新（`POST /api/auth/refresh`）：旧刷新令牌在**记录级锁内**标记已用，签发新访问令牌 +
  新刷新令牌，会话 id 不变（同一会话链）。
- **重放检测**：已使用的刷新令牌再次出现即判定为盗用，立即吊销同一会话（`Session.revoke`），
  会话链上所有访问令牌与刷新令牌全部失效。
- 访问令牌每次请求都回源校验实时状态：
  - HMAC 签名、过期时间、payload 结构；
  - 会话未吊销；账号仍存在且启用；
  - 令牌中的 `ver` 必须等于账号当前 `securityVersion`——禁用、角色/属性调整、改口令都会
    让版本号 +1，已签发令牌立即失效。
- 拒绝原因可区分：`TOKEN_MISSING` / `TOKEN_MALFORMED` / `TOKEN_BAD_SIGNATURE` /
  `TOKEN_TAMPERED`（payload 可解析但与签名不符）/ `TOKEN_EXPIRED` / `TOKEN_REVOKED`。

## 3. 授权规则

- **默认拒绝（default deny）**：没有任何匹配的放行策略即拒绝。
- 策略（`Policy`）字段：`id`、`action`（支持末尾 `*` 通配）、生效角色集合、
  必需账号属性集合、`effect`（ALLOW/DENY）。
- 命中条件（同时满足）：
  1. action 匹配（精确或通配）；
  2. 账号拥有策略角色集合中的**任一**角色（角色集合为空表示不限制角色）；
  3. 账号拥有全部必需属性。
- 判定顺序：策略按登记顺序评估；命中的 **DENY 优先**（即使后面有 ALLOW）；
  否则第一个命中的 ALLOW 放行；否则默认拒绝。
- 种子策略示例：`iam.admin.*` 仅 admin、`document.read` 需 viewer/editor/admin、
  `document.write` 需 editor、`document.publish` 需 editor 且带 `department:content` 属性、
  带 `probation` 属性写文档显式 DENY。

## 4. 审计规则

- 所有认证结果（登录成功/各类失败、刷新轮换/重放/过期、登出）与所有授权判定
  （放行和拒绝）都写入只增审计 `AuditLog`。
- 记录字段：严格递增 `sequence`、`timestamp`、`principal`、`sessionId`、`action`、
  `result`（SUCCESS/FAILURE/ALLOW/DENY）、`matchedPolicyId`、`reason`、`detail`
  （判定时账号的角色/属性快照等），可还原“谁在何时对什么操作依据哪条策略得到什么结果”。
- 追加在单一锁内分配序列号并入列表：并发写入不丢记录、不重号；不提供任何修改/删除入口；
  读取返回不可变快照。审计读取本身（`iam.admin.audit.read`）也会产生审计记录。

## 5. 错误码含义

| 错误码 | HTTP | 含义 |
| --- | --- | --- |
| `INVALID_CREDENTIALS` | 401 | 用户名/口令错误（含账号不存在） |
| `ACCOUNT_LOCKED` | 423 | 连续失败达阈值被临时锁定 |
| `ACCOUNT_DISABLED` | 403 | 账号被禁用（登录或使用令牌时） |
| `TOKEN_MISSING` | 401 | 缺少 Authorization Bearer 令牌 |
| `TOKEN_MALFORMED` | 401 | 令牌结构/编码不合法 |
| `TOKEN_BAD_SIGNATURE` | 401 | 签名无法通过（伪造） |
| `TOKEN_TAMPERED` | 401 | 内容被篡改（payload 与签名不符） |
| `TOKEN_EXPIRED` | 401 | 访问/刷新令牌已过期 |
| `TOKEN_REVOKED` | 401 | 令牌已吊销（登出、重放盗链、安全版本变更） |
| `ACCESS_DENIED` | 403 | 默认拒绝或命中 DENY 策略 |
| `ACCOUNT_NOT_FOUND` / `POLICY_NOT_FOUND` | 404 | 管理目标不存在 |
| `USERNAME_TAKEN` | 409 | 用户名/策略 id 冲突 |
| `BAD_REQUEST` | 400 | 请求参数不合法 |
| `INTERNAL_ERROR` | 500 | 内部错误；底层异常只写服务端日志，不透出接口 |

## 6. HTTP 接口

- `POST /api/auth/login` `{username,password}` → accessToken/refreshToken/expiresIn/sessionId
- `POST /api/auth/refresh` `{refreshToken}` → 新的一对令牌（旧刷新令牌作废）
- `POST /api/auth/logout`（Bearer）→ 吊销当前会话链
- `GET  /api/protected/profile`（Bearer）→ 当前身份与角色/属性
- `POST /api/protected/check`（Bearer）`{action}` → 最小权限判定结果
- `POST /api/admin/accounts`、`POST /api/admin/accounts/{name}`（enabled/roles/attributes/password）、
  `POST /api/admin/accounts/{name}/unlock`、`POST /api/admin/policies`、`GET /api/admin/audit`
  （均需 admin 且操作本身被审计）

种子账号：`admin/admin-pass-123`、`alice(editor)/alice-pass-123`、`bob(viewer)/bob-pass-123`、
`carol(editor+probation)/carol-pass-123`、`dave(已禁用)/dave-pass-123`。

## 7. 本地验证方法

```bash
# 运行全部测试（含场景化中文日志：业务场景 / 用例 / 预期 / 结果）
mvn test

# 只看 IAM 场景日志
mvn test -Dtest='*Tests' 2>&1 | grep IAM-SCENARIO

# 启动应用（8080 被占用时换端口）
mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=8099
```

测试覆盖六大关键场景（`src/test/.../tests/iam`）：

1. `AuthenticationLockTests`：坏口令/不存在/锁定/禁用错误原因区分、阈值锁定、管理员解锁；
2. `ConcurrentLoginTests`：20 个并发错误登录恰好 5 次计入、锁定后 8 个并发正确口令全部拒绝；
3. `TokenRotationTests`：轮换一次性、重放吊销整条会话链、过期/坏签名/篡改/畸形区分；
4. `AuthorizationTests`：默认拒绝、角色+属性联合判定、显式 DENY 优先、审计还原依据；
5. `ImmediateEffectTests`：角色/属性调整、禁用、改口令后旧会话立即失效，重新登录按新状态；
6. `AuditIntegrityTests`：50 并发判定精确新增 50 条审计、序列号连续唯一、字段完整、只增不改。

测试环境通过 `@TestPropertySource` 把令牌 TTL 缩短（访问 10s、刷新 3s），
以便确定性验证过期场景；失败阈值与生产一致为 5。

## 8. 关键配置（`application.properties`）

```properties
iam.max-failed-attempts=5
iam.lock-duration=300s
iam.access-token-ttl=900s
iam.refresh-token-ttl=1209600s
iam.token-signing-key=change-me-local-dev-hmac-sha256-secret-key-0123456789abcdef
```

生产部署时请通过环境变量覆盖签名密钥。当前实现为内存存储，面向本地演示与可重复验证；
持久化时可在保持现有并发与只增语义的前提下替换 `*Repository` / `AuditLog` 实现。

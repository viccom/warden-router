# CloudStudio 发布网关行为与适配记录（WorkBuddy 沙箱）

> 2026-10-16 · 本文记录**平台网关会破坏哪些请求语义**、我们如何在
> warden-route 内适配，以及每项结论的**实测证据**与**提交索引**。
> 面向：在本环境部署对外服务的开发者、维护路由/认证逻辑的后续人。
> 姊妹文档：沙箱知识库 `docs/agent/knowledge/sandbox-networking.md`
> （工作区侧）与 `warden-public-auth-case.md`（warden 401 完整复盘）。

## 0. 为什么需要这份文档

沙箱内的服务要对外提供，必须经过平台网关。该网关**不是透明 TCP 代理**：
它会终止 TLS、解析 HTTP、并**改写部分请求头与响应头**。任何"依赖原始请求
语义"的程序（Host 同源校验、Authorization 认证、Location 跳转、Cookie
作用域）都会在此静默失效——症状往往表现为 401/403，而**本地一切正常**，
极易误判成业务代码 bug。

本文的价值：把"网关会做什么"从**反复踩坑**变成**已知清单**，并给出
逐项的适配实现（均为按路由 opt-in，默认零影响）。

## 1. 链路拓扑

```
浏览器 ──HTTPS──▶ CloudStudio Gateway（云侧终止 TLS，改写头）
                      │  明文 HTTP（平台内部网络）
                      ▼
              warden-route :9000（本程序，127.0.0.1）
                      │
                      ▼
              各上游服务（127.0.0.1:PORT）
```

两种对外通道（并存）：

| 通道 | 域名 | 鉴权载体 | 备注 |
|---|---|---|---|
| artifact release | `https://<appName>.app.workbuddy.host/` | 免 Cookie（链接即入口） | 当前交付主通道；`appName = "a" + md5(runtimeId)[:16]` |
| webview 网关 | `https://webview.e2b.<region>.sandbox.cloudstudio.club/` | `x-cs-sandbox-id` + `x-cs-sandbox-port` 两个 Cookie | 备选；区域段随集群变化 |

> 两条通道**行为不同**（见 2.2），出问题时先用三层对照定位在哪条链路上。

## 2. 网关行为清单（均为实测实锤）

### 2.1 改写 Host 头（且 `X-Forwarded-Host` 一并改写）

- **实测**：浏览器访问 `<appName>.app.workbuddy.host`，到达本程序时
  `Host` = `9000-<space-key>.e2b.<region>.sandbox.cloudstudio.club`
  （内部寻址形态）；`X-Forwarded-Host` 同样被改写，**无任何头携带浏览器原值**。
- **影响**：上游做"Origin 与 Host 一致性"校验的（kula `origin_validation`、
  gorilla `Upgrader.CheckOrigin` 类）必然 403——WS 握手被拒，表现为
  "页面能开、终端/监控连不上"。
- **证据**：route-go 入站头诊断日志 + kula 侧 `Origin (X) does not match Host (Y)`。

### 2.2 替换 `Authorization` 请求头为平台 JWT

- **实测**：客户端发 `Authorization: Bearer <真实 token>`（35 字符），
  到达本程序时变成 `Bearer eyJhbGciOiJIUzI1N…`（**386 字符平台 JWT**，
  `iss=cloudstudio.net`，HS256）。
- **影响**：凡"token 存前端、每请求走 Authorization 头"的服务，公网必 401；
  且**用户输入的任何 token 都到不了上游**（在网关处即被替换），
  UI 层无法自愈。
- **证据**：同一 token 三层对照——本地经 router 到达 35 字符原值 → 上游 200；
  公网到达 386 字符 JWT → 上游 401。
- **注意**：**webview 通道不替换该头**（实测 `+token → 200 / 无 token → 401`），
  这是排查时的重要对照组。

### 2.3 WebSocket 必须走 HTTP/1.1

- **实测**：在 HTTP/2 连接上发 `Upgrade` 头，网关直接 400。
- **影响**：命令行/脚本客户端（curl、部分 SDK）默认协商 h2 时握手失败；
  浏览器 `WebSocket API` 按规范走 h1，不受影响。
- **处置**：命令行复现必须加 `--http1.1`。

### 2.4 `Set-Cookie` 的处理

- **实测**：早期观察网关会把 `Set-Cookie` 的 `Path` 统一改写为 `/`；
  2026-10-16 复测中 `Path=/warden/` 被原样保留（**行为不稳定/随版本变化**）。
- **影响**：多应用 Cookie 作用域设计不能依赖网关行为——本程序的策略是
  **自己明确声明 Path**，不假设网关会改（见 3.4）。

## 3. 适配实现（均在 warden-route，按路由 opt-in）

设计原则一句话：**不猜、不绕过，而是把被网关破坏的请求语义"修复"回上游预期的样子**。

### 3.1 host_fix（治 Host 改写）— `public_host`

`routes.toml` 为路由声明对外域名：

```toml
public_host = "ad8584f64ca039337.app.workbuddy.host"   # 例：/monitor/ 条目
```

入站 Host 匹配网关形态正则
`^[0-9]+-[0-9a-f]{16,}\.e2b\.[a-z0-9-]+\.sandbox\.cloudstudio\.club$`
时才改写为该对外域名（== 浏览器 Origin），上游同源校验自然通过；
**无需**上游 `allowed_origins` 白名单（治标方案，保留作为备查）。
实现：`hostfix.go`；提交 `3fe162e`。

### 3.2 auth_bridge 登录流（治 Authorization 替换；适用于**有登录 API**的服务）

vnts2 / OpenList 这类「登录 API 返回 token → 前端存 localStorage → 每请求
带 Bearer」的服务：

1. **响应侧**：登录响应（POST + 200 + JSON 含 `data.token`/`token`）→ 提取
   token 种 HttpOnly Cookie（Path 限定路由前缀）。
2. **请求侧**：请求携带桥接 Cookie → 用其值恢复 `Authorization` 头
   （**无条件覆盖**：公网到达的已是平台 JWT，"有头就跳过"会把假 token 放行）。

```toml
auth_bridge = true                 # 或由下面任一键隐式启用
auth_bridge_scheme = "Bearer"      # 或 ""（原样 token，如 OpenList）
auth_bridge_cookie = "_wrauth-openlist"   # 多路由必须不同名（网关可能把 Path 统一成 /）
```

实现：`authbridge.go`；测试 `authbridge_test.go`。

### 3.3 auth_bridge 静态注入 + 门控（适用于**无登录 API**的服务，如 warden）

warden 的 token 是静态预共享密钥（无登录 API 可桥接），前端只发
Authorization 头 → 登录流方案不适用。改为**门控换 Cookie + 静态注入**：

```toml
auth_bridge_scheme = "Bearer"
auth_bridge_token = "<上游静态 token>"
auth_bridge_gate = "/warden/.gate"            # 门控入口（可省略，见下）
auth_bridge_gate_key = "<门控密钥>"            # 与 token 同值即可（一个密钥走天下）
```

- **门控**：访问 `/warden/.gate` → 密钥输入页（表单 **POST**，密钥不进
  URL/历史/Referer/访问日志；访问日志另对门控 query 脱敏）→ 校验通过
  （常量时间比较）种 24h HttpOnly Cookie（值 = `HMAC(gate_key)` 标记，
  防伪造）、302/303 回前缀。错误密钥 403 + 重试框；**持有效 Cookie 免输**。
- **注入**：请求带有效门控 Cookie → 用 `auth_bridge_token` 覆盖
  `Authorization` 头。
- **安全不变量**（配置校验强制）：`token ⟺ gate_key` 双向绑定——token 无 key
  可被伪造 Cookie 触发（事实上的无条件注入）；`gate` 可选（**消费型路由**：
  UI 与 API 路径分裂时，API 侧只消费 Cookie，不再开第二个入口）。
- **证据/复盘**：`warden-public-auth-case.md`；提交 `fba377e`/`5b9b51c`/`0592851`。

### 3.4 门控 Cookie `Path` 固定为 `/`（为什么）

上游 UI 的 **API 常用根绝对路径**（`/api/v1/...`，假设自己部署在域名根下），
与 UI 自身所在前缀（`/warden/`）是**两条不同路由**。若 Cookie 只种在
`/warden/` 内，浏览器对 `/api/v1/...` 请求**根本不发 Cookie**——症状是
"Cookie 种上了但 UI 仍 401"（实测）。结论：

- 门控 Cookie `Path` **固定 `/`**（全局作用域无副作用：Cookie 名独立 +
  值是 HMAC 标记，其他路由收到不认）；
- 且 `token+gate_key` **必须在 API 路径路由上重复配置**（见
  `/api/v1/` 条目，消费型）。

### 3.5 决策记录：门控 Cookie **不加** `Secure`

- 发布域名只有 HTTPS 入口，浏览器侧本就安全；
- 本程序在网关后方收到的是**明文 HTTP**（TLS 在网关终止），无法可靠判断
  原始 scheme（`X-Forwarded-Proto` 不可依赖）；
- 误判（在 http 上下文发出 `Secure` Cookie）会让本地调试静默失效——
  风险大于收益。
- 结论：保持 `HttpOnly; SameSite=Lax; Path=/`，不设 `Secure`。

## 4. 设计原则（迁移到新场景时照此办理）

1. **只修语义，不改协议**：所有适配都是"把网关改坏的头/路径恢复成上游预期"，
   绝不引入新的自定义协议。
2. **按路由 opt-in，默认零影响**：未配置的路由行为与无网关时完全一致。
3. **配置校验挡误用**：危险组合（token 无 key、gate 出前缀）在加载期拒绝，
   不留给运行时。
4. **静默失效变显式**：门控被更长前缀遮蔽等场景启动告警（`GateShadowWarnings`）。
5. **凭据不入日志**：门控路径 query 脱敏；`/_routes` 回显字段抹为 `***`。

## 5. 排障范式：三层对照 + 真浏览器

**任何"公网不对、本地正常"的问题，先做三层对照**：

```
① 本地直连上游（如 curl 127.0.0.1:PORT）
② 本地经 router（curl 127.0.0.1:9000/<prefix>/）
③ 公网经网关（curl https://<appName>.app.workbuddy.host/<prefix>/）
```

- ① ② 正常、③ 异常 → **网关行为**问题，查本文第 2 节清单。
- **本地模拟严禁构造 `Host` 头**（否则分不清"网关改写"与"自己造的"）。
- **最终判定用真浏览器**（playwright）：Cookie 发送规则、SameSite、Path
  匹配只有真浏览器能验证；curl 全绿 ≠ 浏览器可用（曾因此漏判一轮）。

## 6. 已知限制与观察项

| 项 | 说明 | 状态 |
|---|---|---|
| 门控被更长前缀遮蔽 | Lookup 最长前缀优先，gate 可能被抢走（fail-closed，不产生注入） | 启动/重载告警 |
| 门控失败无限速 | 密钥空间 16+ 位随机，穷举不可行 | 观察 |
| `POST /_routes` 回显提交者凭据 | 请求者已知该值，无泄露面 | 观察 |
| Cookie 无 `Secure` | 见 3.5 决策记录 | 有意为之 |
| 网关行为随版本变化 | 如 Set-Cookie Path 改写行为前后不一致 | 复测为准 |

## 7. 提交索引（时间线）

| 提交 | 内容 |
|---|---|
| `3fe162e` | host_fix：`public_host` 对外 Host 修复（治 kula WS 403） |
| `fba377e` | auth_bridge 静态注入模式（治 warden 公网 401） |
| `5b9b51c` | 门控 Cookie `Path=/` + `/api/v1/` 重复配置（治"Cookie 种上仍 401"） |
| `0592851` | 门控密钥输入页 + GateKey 与 token 统一 |
| `0644598` | 导航卡片直达门控路径 |
| `8aba069` | 审查加固：密钥不进 URL/日志、免输兑现、`/_routes` 抹除、消费型路由语义、Lookup 复用 |
| 本次 | `validGatePath` 禁 `?/#`、POST 超限 413、门控遮蔽告警、fileRoutes 依赖注入（修 data race） |

## 8. 配置键速查（routes.toml）

```toml
[[route]]
prefix  = "/warden/"          # 挂载路径（须以 / 开头结尾）
host    = "127.0.0.1"
port    = 8789
mode    = "strip"             # strip=剥前缀 | keep=保留
hidden  = true                # 不进导航宫格（可选）
public_host = "…"             # host_fix：对外域名（可选）
response_header_timeout = "10s"  # 每路由响应头超时（可选）

# 认证适配（可选；任一键即隐式启用）
auth_bridge        = true
auth_bridge_scheme = "Bearer"       # 或 ""
auth_bridge_cookie = "_wrauth-gate" # 多路由勿同名
auth_bridge_token  = "…"            # 静态注入值（与 gate_key 成对）
auth_bridge_gate   = "/warden/.gate" # 门控入口（可省略=消费型）
auth_bridge_gate_key = "…"          # 门控密钥（[A-Za-z0-9_-]{16,128}）
```

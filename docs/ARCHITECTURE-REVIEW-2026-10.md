# warden-router 架构与兼容性审查（2026-10）

- **审查对象**：github.com/viccom/warden-router @ `60b0c5d`（main，17 commits，无 tag）
- **审查方式**：静态代码审查——全量非测试源码（约 4,000 行 Go）精读 + warden 仓库（`viccom/warden` @ `e3d99c7`）交叉比对。**未运行**测试套件与运行时验证（见 §6 边界声明）。
- **审查维度**：架构设计 / 规范化 / 路径分流兼容性，附与 warden 集成的可行性判断。
- **严重度分级**：P0 = 安全/暴露面问题，应尽快处理；P1 = 正确性/能力缺口，影响真实场景；P2 = 规范性/可维护性，择机处理。
- **结论速览**：工程质量高于"临时沙箱工具"定位（并发模型、TDD 纪律、实测驱动的适配文档均扎实）；但当前形态是"缝合了平台网关漏洞的转发器"，距"可迁移的路径分流网关"还差三件事：暴露面治理、行业标准头、配置契约规范化。

---

## 0. 总评

**值得保留的底子**（后续改进不应破坏这些设计）：

| 设计 | 出处 | 价值 |
|---|---|---|
| 三层路由 static > dynamic > discovered | routes.go:317-343 | 职责清晰：部署者意图 > 在线操作 > 自动发现 |
| 单漏斗原则 | main.go:115-198, rewrite.go:22-39 | 响应改写只在 `ModifyResponse`、指标只在中间件，多点改写类 bug 在结构上不可能 |
| 落盘并发模型 | routes.go:470-505 | `persistMu` 内重取最新快照 + `fsync` + `rename`，杜绝丢更新与半截文件 |
| Route 插入后不可变约定 | routes.go:20-21 | 读侧免锁拷贝，copy-on-write 门槛预先立好 |
| warden 失联降级 | discovery.go:59-71 | 静态/动态路由照常服务，发现停摆只打日志 |
| 拨测只打内网 | nav.go:94-102 | 防止路由器变成对公网的周期性灯塔 |
| 凭据卫生 | api.go:107-115, 134-153; logging.go:97-102 | 常量时间比较、token/gate_key 不回显不进日志 |

**定性**：代码里约六成是通用路径分流能力（三层路由、strip/keep、Set-Cookie/Location 重写），约四成是平台特定 workaround（auth_bridge、hostfix、CloudStudio/Trae 网关适配）。这个比例是"是否值得集成回 warden"的关键输入（§4）。

---

## 1. 架构设计

### 1.1 【P0·安全】发现层无视 warden 的暴露门控

**证据**：`discovery.go:24-32` 的 `wardenSvc` 只解析 `name/display_name/description/ui_url/health.status`；warden 的 `/api/v1/services` 实际返回 `proxy`（允许经反代暴露）与 `subdomain` 字段（warden `src/supervisor/mod.rs:523-526` 的 `ServiceStatus` 序列化），但 `discover()` 不读。

**影响**：一个 `proxy = false`（明确不公开）的服务，只要 `ui_url` 恰好带路径前缀（如 `http://127.0.0.1:8790/internal/`），就会被自动挂到公网单域名下。暴露决策权在 warden 配置里，执行却被 router 的约定旁路。

**建议**：`wardenSvc` 增加 `Proxy bool`，`discover()` 仅对 `proxy == true` 的服务建路由。行级改动。**注意兼容期**：现网若有服务依赖"ui_url 带前缀即挂载"而未开 `proxy`，此改动会摘掉它的公网入口——上线前先对 warden 服务表做一次盘点（`/_health` 的 discovered 计数前后对照即可发现）。

### 1.2 【P1·正确性】发现层不消费健康状态，死亡语义与 warden 反代不对齐

**证据**：`discovery.go:83-105`——`health.status` 只进 `svcs`（导航卡片用），路由创建与否不看法度。warden 自己的反代对停止的服务返回**带状态信息的 503**、缺 ui_url 返回 502（warden `src/proxy/forward.rs:178-192`）；router 则照常转发，由 `ErrorHandler` 返回泛化 502（main.go:183-197）。

**影响**：同一服务经两个入口死掉，运维看到两种症状与两种状态码，排障心智分裂；导航卡片显示 unhealthy 但路由仍吸流量。

**建议**：二选一或并行——(a) 发现层跳过非 `running` 状态的服务（route 消失，404 + 导航卡片灰显）；(b) Lookup 后查 `services` 健康表，非 running 返回 503 + 状态 JSON（对齐 warden 语义）。(b) 信息量更大。

### 1.3 【P1·可运维性】token 生命周期：`sync.Once` 只在启动时读一次

**证据**：`main.go:55-82`——`resolveTokens()` 虽被 `discover()` 每周期调用（discovery.go:49），但函数体整体包在 `tokenOnce.Do` 里，实际只在首次执行。warden 轮换 `.api-token` 后：发现循环永远 401，静默停摆；`/_health` 无任何"发现已过期"信号（endpoints.go:18-24 只报 counts/admin_auth），仍显示 `status: ok`。

**建议**：(a) `/_health` 增加 `last_discovery_ok` 时间戳与 `last_discovery_error`；(b) 401 时重读 token 文件（带 mtime 缓存，开销可忽略）。(a) 必做，(b) 强烈建议。

### 1.4 【P2·可维护性】全局单例群

**证据**：`table`（main.go:92）、`persistPath`（main.go:52）、`sharedTransport`（main.go:103）、`probeHealth`（nav.go:38-41）、`cachedAtok/cachedWtok`（main.go:56-59）均为包级全局；测试依赖 `swapTable`/`swapProbe` 替换钩子。routesfile.go:371-380 已示范正确方向（`fileRoutes` 依赖注入，注释标明系 2026-10-16 审查所改）。

**建议**：引入 `App` 聚合结构持有全部状态，main 只做装配；这是未来任何形态集成（并入 warden 或独立演化）的前置条件。不急于一次做完，新增代码先行即可。

### 1.5 【P2·可运维性】跨层前缀冲突静默吞没

**证据**：`Upsert`（routes.go:277-285）只做 `validRoute`，不检查与 static/discovered 层的同前缀冲突；Lookup 优先级 static > dynamic > discovered（routes.go:336-342）静默取高者。经 `/_routes` API 添加一条与 static 同前缀的动态路由：返回 200，**永不生效**，无任何警告。`GateShadowWarnings()`（routes.go:383-427）已为门控路径实现了"被更长前缀遮蔽"检测——同一机制应推广。

**建议**：重载期（routes.toml reload、discover、Upsert 三处）跑一次通用的跨层同前缀冲突检测，告警进日志与 `/_health`。

---

## 2. 规范化

### 2.1 【P2】一个东西五个名字

| 名字 | 用在哪 |
|---|---|
| `warden-router` | 仓库名 |
| `warden-route` | go.mod module 名、README 标题、代码注释自称 |
| `web-gateway` | warden 服务名（README 部署节、config.go:18-19 的 `Name` 字段） |
| `warden-route-go` | 构建产物名（README 构建命令） |
| `router-go` | 部署目录 `/workspace/router-go/`（main.go:45-47 flag 默认值） |

**建议**：定 `warden-route` 为正名（module 名已是它），其余在 README 声明为历史别名；服务名 `web-gateway` 与功能完全脱节，是最误导的一个，趁早改名（warden services.toml 同步改，记得 README 提醒过的 restart API）。

### 2.2 【P2】配置面四分五裂且无版本化

现状五处配置来源：9 个启动 flag（main.go:40-48）、代码内静态路由（config.go，**硬编码沙箱端口** 8789/8800/27960/27970）、routes.toml（每路由 17 键，routesfile.go:110-267）、dynamic-routes.json（`Version:1` 字段存在但无迁移语义，routes.go:454-457）、以及藏在 warden services.toml `ui_url` 路径里的隐式挂载约定。

**建议**：(a) routes.toml 加 `version` 字段，起步即可，无迁移负担；(b) 增加 `warden-route validate` 子命令（只解析不监听），CI 与部署前各跑一次；(c) 长期把 config.go 的沙箱端口迁入 routes.toml，代码静态层留空或仅留自检用途。**收益最大的一项**是把"挂载前缀"从 ui_url 路径戏法升为 warden 服务配置的显式字段（见 §4）。

### 2.3 【P2】鉴权体系三套并存，缺权威对照

三套凭据：warden API Bearer（默认读 `.api-token`）、`/_routes` 管理 Bearer（**默认同一份** `.api-token`，main.go:71-77）、每路由 gate_key（HMAC cookie）。一份密钥两用，泄漏即双失守。

**建议**：admin token 支持独立文件（flag 已支持 `-admin-token`，补一个文件读取即可对齐 warden-token 的三级回退）；README 增加一张"凭据 × 用途 × 轮换方式 × 轮换后需重启什么"对照表（当前 token 轮换需重启 router，正因 §1.3）。

### 2.4 【P2】零 tag、零 CHANGELOG

17 个提交线性堆在 main，无任何版本标记。提交信息质量很高（带实测证据索引），配 tag 序列成本极低。对"沙箱重建后从持久包补装"的部署模式（README 记载的 go 工具链即此模式）有实际用途：产物可按 tag 归档。

**建议**：从下一个功能提交起打 `v0.x` tag；不必追溯历史。

### 2.5 【P2】API 错误无机器可读码

`/_routes` 错误一律 `{"error": "中文文本"}`（api.go:34-104），自动化调用方只能字符串匹配。加 `code` 字段（如 `invalid_prefix`/`unauthorized`）即可。

---

## 3. 路径分流兼容性

### 3.1 兼容性分级（现状应写成显式契约）

| 级别 | 上游形态 | 现状支持 | 典型例子 |
|---|---|---|---|
| T1 | 自带 base_path | ModeKeep 完美 | ttyd `-b`、kula `base_path` |
| T2 | 相对路径 / 尊重 X-Forwarded-* | ModeStrip + 响应重写基本可用 | 多数现代前端 |
| T3 | 根绝对路径硬编码（`/api/`、`/static/`） | **只能手工加伴随透传路由** | warden UI（`/api/v1/` 透传，config.go:18-19） |

T3 的伴随路由模式不可扩展：每个应用可能需要 N 条，且**两个应用争夺同一根路径（如都占用 `/api/`）时无解**——单域名根命名空间只有一个。这张表应进 README，让部署者挂载前先给上游定级。

### 3.2 【P1·性价比最高】未设置 `X-Forwarded-Prefix`

**证据**：全仓库无该头（已 grep 确认）；Rewrite 只调 `SetXForwarded()`（XFF/XFH/XFP）并在 main.go:160-178 条件覆盖 XFH/XFP。

**影响**：`X-Forwarded-Prefix` 是事实行业标准（Django `FORCE_SCRIPT_NAME` 生态、Grafana `root_url`、Spring 等前缀感知框架/中间件消费它自动生成正确绝对 URL）。不设置时，这批本可开箱即用的 T2/T3 上游被迫退回伴随路由模式。

**建议**：strip 模式下 `pr.Out.Header.Set("X-Forwarded-Prefix", strings.TrimSuffix(rt.Prefix, "/"))`，行级改动，默认开启（上游不认识此头则无影响，零风险）。

### 3.3 【P1】上游 scheme 写死 `http`

**证据**：main.go:129-131——`target := &url.URL{Scheme: "http", ...}`；`Route` 结构（routes.go:52-87）无 scheme/TLS 字段。

**影响**：https 上游**无法表达**。沙箱内全是 localhost http 所以未暴露；但这是"沙箱专用"写进核心逻辑的典型，也堵死了"router 独立部署在别的环境"的路。

**建议**：`Route` 加 `scheme` 键（缺省 http，保持现状），routes.toml / 在线 API 同步。小时级。

### 3.4 【P1·安全】gate cookie 的 HMAC 未绑定路由前缀

**证据**：`gateCookieValue = HMAC-SHA256(GateKey, "warden-route:static-gate:" + cookieName)`（authbridge.go:129-134）——输入不含路由前缀；而静态模式默认 cookie 名统一为 `_wrauth-gate`（authbridge.go:122）且显式用 `Path="/"` 种 cookie（authbridge.go:236-244，为兼容"UI 在子路径、API 在根路径"的 warden 形态，注释如实记录了该妥协）。

**影响**：两个路由若共享同一 GateKey（同一运维者的自然做法）且都未显式配 `auth_bridge_cookie`，默认 cookie 名相同 → HMAC 值相同 → 在路由 A 通过门控拿到的 cookie **在路由 B 直接通行**。cookie 名绑定防 tossing 的设计意图，被"默认名全局唯一"的前提架空了。

**建议**：HMAC 输入加入 `rt.Prefix`（`"warden-route:static-gate:" + prefix + ":" + name`）。行级改动；副作用是已发 cookie 全部失效（用户重过一次门控，可接受）。

### 3.5 【P2·原理性边界，应显式文档化】客户端 JS 种的 cookie 管不了

代理只重写 `Set-Cookie` **响应头**（rewrite.go:47-92，且仅 strip 模式）；`document.cookie` 写的 cookie 绕过代理直接落根路径。auth_bridge 的门控自己也被迫 `Path="/"`（§3.4）。这是代理层的原理边界，不是 bug，但下一个部署者会重新踩一遍。

**建议**：README 兼容性分级表（§3.1）旁注明此限制与 auth_bridge 的适用条件。

### 3.6 【P2】重定向保真的盲区

**证据**：`pointsToUpstream`（rewrite.go:139-148）只认"host 名相同且端口相同/缺省"。三个漏网场景：(a) 上游重定向到自己的 https 形态（`https://host/...` 端口 443 ≠ 上游端口）→ 判为外部 → 浏览器被导向不存在的地址；(b) 同集群另一 host 的 SSO 跳转 → 原样放行 → 跳出挂载点；(c) 伴随路由场景下重定向到本该由别的路由接管的路径。

**建议**：每路由可配 `internal_redirect_hosts` 白名单（含自身 https 形态的默认项），命中即相对化拉回。天级。

### 3.7 【P2】内容重写缺位（T3 的根治手段）

对根绝对路径硬编码的 T3 应用，业内通行做法是可选的 HTML 子串替换（nginx `sub_filter` 类）：每路由 opt-in + MIME 白名单（`text/html`）+ 大小上限 + `sub_filter_once` 语义。有了它，大部分 T3 应用可脱离伴随路由模式。天级，注意与流式响应的缓冲取舍（需在 ModifyResponse 读全 body，仅限开启路由）。

### 3.8 已知且接受的风险（记录在案，无需动作）

- `/_metrics` 无鉴权暴露路由前缀列表（README 明示为有意设计；前缀非秘密，接受）。
- WS/长连接无读超时（timeout.go 注释：任何读超时都会误杀终端会话；每路由 `response_header_timeout` 已提供"等响应头"段的约束，语义正确）。

---

## 4. 与 warden 的关系及集成可行性

**现状契约（全部单向，router 认识 warden，warden 不认识 router）**：

| 契约 | 位置 | 脆弱性 |
|---|---|---|
| `/api/v1/services` JSON 字段名 | discovery.go:24-36 | warden 改序列化即断，无版本协商 |
| `.api-token` 文件路径与语义 | main.go:68, 76 | 一份密钥两用；轮换需重启（§1.3） |
| warden API 端口 8789、沙箱端口拓扑 | main.go:41, config.go:18-35 | 部署特定值进代码 |
| **ui_url 路径的双语义** | router 视为公网挂载前缀并剥离（discovery.go:96-104）；warden 反代视为**上游前缀并前置**（forward.rs:511-529 `build_upstream_uri`） | **同一字段值、两个消费者、语义相反**。当前沙箱未同时启用两者所以未引爆；任何"两者并行"的部署必有一边转错 |

**集成判断**：不合并是对的，但理由要说准——通用能力（六成）适合进 warden proxy 模块；平台 workaround（四成：auth_bridge、hostfix、CloudStudio/Trae 适配）会污染通用监护器。正确的集成路径不是搬代码，而是先做契约规范化：warden 服务配置显式 `mount_prefix` 字段（消灭 ui_url 戏法）、发现层尊重 `proxy` 门控（§1.1）、admin 凭据独立（§2.3）。届时 router 成为"warden 配置的纯消费者"，合并与否退化为组织选择。

---

## 5. 改进优先级汇总

| # | 事项 | 级别 | 量级 | 出处 |
|---|---|---|---|---|
| 1 | 发现层尊重 `proxy` 门控（上线前盘点现有 discovered） | P0·安全 | 行级 | §1.1 |
| 2 | gate cookie HMAC 绑定前缀 | P1·安全 | 行级 | §3.4 |
| 3 | `X-Forwarded-Prefix` 默认设置 | P1 | 行级 | §3.2 |
| 4 | 上游 `scheme` 可配 | P1 | 小时级 | §3.3 |
| 5 | 发现层健康语义对齐 warden（503 + 状态） | P1 | 小时级 | §1.2 |
| 6 | `/_health` 加发现新鲜度 + 401 重读 token | P1 | 小时级 | §1.3 |
| 7 | 跨层同前缀冲突告警 | P2 | 小时级 | §1.5 |
| 8 | routes.toml `version` + `validate` 子命令 | P2 | 小时级 | §2.2 |
| 9 | 重定向内部 host 白名单 | P2 | 天级 | §3.6 |
| 10 | T3 内容重写（sub_filter 类） | P2 | 天级 | §3.7 |
| 11 | 命名统一 / tag 序列 / API 错误码 / 凭据对照表 | P2 | 各小时级 | §2 |

**只做三件事的话**：#1 + #3 + #2（两行级 + 一行级，覆盖暴露面、行业标准、跨路由通行三个要害）。

---

## 6. 审查边界声明（可信度）

- 本审查为**静态审查**：基于 `60b0c5d` 全量非测试源码精读与 warden `e3d99c7` 交叉比对；**未运行** `go test`/`go vet`（本机无 Go ≥1.27 工具链），未做任何运行时复现。涉及"实测"字样的行为描述（如网关改写 Host、替换 Authorization）均转引自仓库内 `docs/cloudstudio-gateway.md` 及代码注释的记载，非本次独立验证。
- 测试文件（约 3,000 行，`*_test.go` × 10）未逐行精读，仅经 defects_test.go 的存在确认了缺陷测试纪律；测试覆盖率结论不在本报告主张范围内。
- 行号引用以 `60b0c5d` 为准，后续提交会漂移，按符号名检索为准。
- 审查人：AI 编码代理（GLM），受 warden 仓库维护者委托，2026-10-16。

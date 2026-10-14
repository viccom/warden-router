# router-go 透明代理能力增强 — TDD 实施方案

> 批次一/二来自《router-go 透明代理能力研究报告》。本文是实施的**测试先行**
> 计划：每个能力先列出必失败测试（RED），再给实现要点（GREEN），最后负向验证。
> 遵循 `golang-testing` 的 RED-GREEN-REFACTOR 循环与 `golang-code-style`。

## 0. 总体约束（实施中不可违背）

1. **零第三方依赖**：只用标准库（与项目现状一致）。TOML 用严格子集手写解析器。
2. **WS 安全默认**：任何超时/改写默认关闭，显式开启才生效；`ModifyResponse`
   对 101 升级响应本就不触发（ReverseProxy 语义），WS 路径零影响。
3. **只改 ModeStrip 的响应**：ModeKeep 路由（kula/ttyd 类）路径原样，一律不碰。
4. **单一 funnel**：响应改写只在 `sharedProxy.ModifyResponse`；访问日志与指标
   只在中间件；不分散多处。
5. 每个能力完成时：`gofmt -l` 空、`go vet` 干净、`go test -race -count=5` 全绿、
   负向验证（注入缺陷→对应测试转红）。

## 1. 批次一：响应重写 + 访问日志

### 1.1 Set-Cookie Path 重写

**测试先行（`rewrite_test.go`，经真实代理集成断言，仿 D10 的真 TCP 模式）**：

| # | 用例 | 期望 |
|---|---|---|
| C1 | `Set-Cookie: s=1; Path=/; HttpOnly`，strip 路由 `/app/` | `Path=/app/`，其余属性原样 |
| C2 | `Path=/login` | `Path=/app/login` |
| C3 | `Path=/app/x`（已含前缀） | 不变 |
| C4 | 无 Path 属性 | 追加 `Path=/app/` |
| C5 | 多个 Set-Cookie 头 | 逐条重写 |
| C6 | `path=` 小写属性名 | 正确识别（大小写不敏感） |
| C7 | `Expires=...; SameSite=Lax` 等属性 | 原样保留 |
| C8 | ModeKeep 路由 | 完全不变 |
| C9 | 非 cookie 响应 | 无副作用 |

**实现要点**：`ModifyResponse` hook 内 `rewriteSetCookie(resp, rt)`：
`resp.Header["Set-Cookie"]` 逐条按 `;` 切段，找 `path=` 属性；值不以
`rt.Prefix` 开头则替换为 `rt.Prefix + strings.TrimPrefix(v, "/")`（Prefix 以
`/` 结尾，拼接通顺）；无 path 段则追加。**不动** name=value 首段与其它属性。

### 1.2 Location 重定向重写

**测试先行**：

| # | 用例 | 期望 |
|---|---|---|
| L1 | `302 Location: /login` | `/app/login` |
| L2 | `Location: ../x`（相对） | 解析后前插前缀 |
| L3 | `Location: http://127.0.0.1:9200/login`（指回上游自己） | `/app/login`（去掉 scheme/host） |
| L4 | `Location: https://example.com/x`（外部） | 不变 |
| L5 | `Location: /app/y`（已含前缀） | 不变 |
| L6 | ModeKeep 路由 | 不变 |
| L7 | 201 Created 带 Location | 同样重写（按头处理，与状态码无关） |
| L8 | 畸形 Location | 原样返回，不 panic |

**实现要点**：`rewriteLocation(resp, rt)`：解析 Location；绝对 URL 仅当 host
指回上游自己（host 名匹配、端口缺省或匹配）才改写并**相对化**（清空
scheme/host，否则把浏览器导向 127.0.0.1 死地）；相对 URL 先对**出站请求
URL**（`resp.Request.URL`，即上游视角的剥离后路径）做 `ResolveReference`
再前插前缀。

### 1.3 访问日志

**测试先行（`logging_test.go`）**：

| # | 用例 | 期望 |
|---|---|---|
| A1 | `Write` 前无 `WriteHeader` | statusRecorder 记 200 |
| A2 | 显式 `WriteHeader(404)` | 记 404 |
| A3 | 字节数累计 | 正确 |
| A4 | 下游是 Hijacker（WS 场景） | Hijack 透传成功，WS 101 不破 |
| A5 | 下游是 Flusher | Flush 透传（SSE 不卡） |
| A6 | `Unwrap()` 存在 | `http.ResponseController` 可穿透 |
| A7 | 集成：经 loggingMiddleware 请求代理路由 | 日志行含 method/path/status/耗时/route 前缀 |
| A8 | 集成：WS 握手经 middleware | 仍 101（D10 链路套 middleware 复跑） |

**实现要点**：`loggingMiddleware(next)` 包 mux（与 recoverMiddleware 同层）。
route 标签由中间件自己 `table.Lookup(r.URL.Path)` 取得（未命中记 `-`）。
多一次 Lookup 约 1-2µs，可忽略。日志单行经 `log.Printf`（stdout→warden 日志）。
statusRecorder 必须实现 `Hijack/Flush/Unwrap`——**漏 Hijack 是全项目最贵
的坑**（WS 直接死），A4/A8 专守。

## 2. 批次二：指标 + 每路由超时 + 声明式路由

### 2.1 /_metrics（Prometheus 文本格式，零依赖手写渲染）

**测试先行（`metrics_test.go`）**：

| # | 用例 | 期望 |
|---|---|---|
| M1 | 发 3 个 200 + 1 个 404 到不同路由 | `warden_route_requests_total{route,method,status}` 计数正确 |
| M2 | 延迟直方图 | 各 bucket 计数与总和自洽（sum(buckets)=count） |
| M3 | 在途请求 gauge | 请求中 >0，结束后回 0 |
| M4 | `GET /_metrics` | 200、`text/plain`、无需鉴权、含三种指标族 |
| M5 | 动态路由数 gauge | 增删动态路由后反映 |

**实现要点**（`metrics.go`，~150 行）：mutex 保护的
`map[routeLabel]*counters{total map[statusKey]int64, hist [10]int64, inFlight int64}`
+ `warden_route_dynamic_routes` gauge。记录点挂在 loggingMiddleware（一处，
无重复计数）。桶：1m/5m/10m/50m/100m/500m/1s/5s/+Inf。渲染函数输出
`# HELP/# TYPE` + 样本行。**不用** prometheus client 依赖。

### 2.2 每路由 ResponseHeaderTimeout

**测试先行（`timeout_test.go`）**：

| # | 用例 | 期望 |
|---|---|---|
| T1 | 路由配 `response_header_timeout="100ms"` + 上游 300ms 才响应 | 快速失败（非挂起），客户端得 5xx |
| T2 | 同上游不配超时 | 正常等待到 200 |
| T3 | WS 路由（ModeKeep，无超时） | 101 + 数据帧（超时机制不误伤） |
| T4 | 200 请求同超时配置路由 | 上游 accepted 连接数远小于 200（每路由 Transport 仍复用连接，D5 不回归） |
| T5 | Duration JSON | `"10s"` ↔ 结构体往返；负数/超 5m 被 validRoute 拒绝 |
| T6 | 两个不同超时配置的路由 | 获得不同 Transport 实例（单元断言 transportFor） |

**实现要点**：`Route` 增 `ResponseHeaderTimeout Duration`（自定义 JSON 类型，
接受 `"10s"` 字符串与纳秒数字；0=不设）。**不能用 context deadline**（会掐死
WS/流式）。方案：`sharedProxy.Transport` 换成 `routingTransport`（实现
RoundTripper），按请求 context 里的路由选 Transport：超时配 0 → 全局
`sharedTransport` 单例；否则按 `(headerTimeout, idleTimeout)` key 懒加载
独立 Transport 并缓存（连接池按路由隔离，仍复用）。validRoute 校验：
`0 ≤ t ≤ 5m`。

### 2.3 routes.toml 声明式配置 + 热加载

**格式（operator 面向，注释是刚需）**：

```toml
# 静态路由声明文件。与 config.go 的 staticRoutes() 合并，同前缀本文件优先。
# 保存后 5s 内热加载；kill -HUP 立即重载。语法错误整版拒绝并保留上一版。

[[route]]
prefix = "/wiki/"
host = "127.0.0.1"
port = 8080
mode = "strip"              # strip | keep
display = "内部 Wiki"
desc = "Bookstack"
icon = "📚"
# response_header_timeout = "10s"
```

**测试先行（`routesfile_test.go`）**：

| # | 用例 | 期望 |
|---|---|---|
| F1 | 黄金文件（全字段+注释+两种 mode） | 解析出预期 Route 列表 |
| F2 | 语法错误（缺 `=`/未闭合引号/坏 duration） | 报错带**行号** |
| F3 | 缺必填字段/端口越界/mode 非法 | 逐条报错跳过，其余保留 |
| F4 | 重复 prefix | 后者胜或报错（定：报错跳过后者） |
| F5 | `MergeFileRoutes` 优先级 | 同前缀 file 覆盖 code static；Lookup/Cards/Snapshot 一致 |
| F6 | 热加载 watcher | 改文件→调用 reload 后表更新；删文件→回退到 code static |
| F7 | 损坏文件 | 保留上一版好数据 + 响铃日志（不清空、不退出） |
| F8 | SIGHUP | 触发同一 reload 函数（直接测函数，信号本身不测） |

**实现要点**（`routesfile.go`）：**严格 TOML 子集**解析器（~180 行）：
仅支持 `#` 注释、`[[route]]` 数组表、`key = value`，值为双引号字符串
（`\" \\ \n` 转义）、整数、布尔、duration 字符串。**子集外一律报错带行号**——
刻意收窄，不做通用 TOML。watcher goroutine：5s 比对 mtime+size，变化即
reload（`SetStatic(staticRoutes())` 重建 + `MergeFileRoutes` 合并，防漂移）。
`-routes-file` flag，默认 `/workspace/router-go/routes.toml`。文件缺失=仅
code static，启动 info 日志。

## 3. 实施顺序（每步：RED→GREEN→负向验证→提交点）

1. logging（A1-A8）—— 后续指标的挂点，先行
2. metrics（M1-M5，挂在 logging middleware）
3. cookie 重写（C1-C9）
4. location 重写（L1-L8）
5. Duration 类型 + 每路由超时（T5/T6/T1/T2 → T3/T4）
6. routes.toml 解析器（F1-F4）→ 合并与 watcher（F5-F8）
7. 全量回归 + 临时实例端到端 + 上线 + 文档

## 4. 风险与对策

| 风险 | 对策 |
|---|---|
| statusRecorder 漏 Hijack 打死 WS | A4/A8 专测；D10 复跑套 middleware |
| 重写误伤 ModeKeep 应用 | C8/L6 断言不变；默认只在 ModeStrip 生效 |
| TOML 子集解析器 bug | 黄金用例 + 错误行号断言；子集外显式报错 |
| 每路由 Transport 连接池膨胀 | 按配置 key 缓存（非按路由），默认走单例 |
| 热加载把路由表改坏 | 先重建再合并；坏文件保留上一版 |
| 指标记录拖慢请求 | mutex 临界区仅 map 自增；压测对照 p50 波动 <5% |

## 5. 交付物

- 新文件：`logging.go` `metrics.go` `rewrite.go` `duration.go` `routesfile.go`
  + 对应 `_test.go`
- 改文件：`main.go`（hook/中间件/transport/watcher 接线）、`routes.go`
  （Duration 字段、validRoute、file 层合并）、`config.go`（不变）
- 文档：AGENTS.md §2 能力清单、routes.toml 示例文件、pitfalls（如有新坑）

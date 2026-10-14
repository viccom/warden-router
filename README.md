# warden-route

单域名路径分流路由器（Go，零第三方依赖，仅标准库）。本沙箱只有一个对外
共享域名（webview 网关按 sandbox-id+port 路由），多服务同时暴露公网必须
经本程序做 URL 路径分流。由 warden 托管运行（服务名 `web-gateway`，
监听 `127.0.0.1:9000`）。

## 构建与测试

```sh
go build -o build/warden-route-go .   # 产物输出到 build/（不进源码树）
go test -race -count=5 ./...          # 全量测试（表驱动 + 真 TCP 集成）
gofmt -l . && go vet ./...
```

## 部署

- warden 托管：`/workspace/warden/config/services.toml` 的 `web-gateway` 条目，
  `command` 指向 `build/warden-route-go`；改命令/参数后须显式
  `POST /api/v1/services/web-gateway/restart`（config/reload 不换进程）
- 路由配置三层：代码静态路由（`config.go`）< `routes.toml` 声明式文件
  （同前缀文件优先，5s 热加载 / `kill -HUP` 立即重载）< 动态路由
  （`/_routes` API 在线增删改，落盘 `dynamic-routes.json`，重启恢复）
- 服务发现：warden API 轮询（30s），服务的 `ui_url` 带前缀即自动挂载

## 端点

| 端点 | 说明 |
|---|---|
| `/` | 导航首页（SSR，卡片新标签页打开；内置 TCP 拨测显示健康） |
| `/_health` | 自检快照（路由三层计数、admin 鉴权状态） |
| `/_metrics` | Prometheus 指标（无鉴权只读：请求计数/延迟直方图/在途/动态路由数） |
| `/_routes` | 动态路由管理 API（写操作 Bearer token，取自 warden `.api-token`） |
| `/<prefix>/` | 按路由表转发；`ModeStrip` 剥前缀、`ModeKeep` 原样透传 |

透明代理增强：ModeStrip 路由自动重写 `Set-Cookie` 的 `Path`（前插挂载
前缀，治多应用 cookie 串台）与 `Location` 重定向（拉回挂载点内）；
Host 头原样透传浏览器值（上游 WS 同源校验依赖此项，勿改写）；每路由可配
`response_header_timeout`（routes.toml / 在线 API，`"10s"` 形式）。

## 目录导览

```
config.go       代码静态路由（基础层，同前缀被 routes.toml 覆盖）
routes.go       路由表：三层（static/discovered/dynamic）并发模型 + 校验 + 持久化
main.go         入口：flag、中间件（recover+logging）、转发核心单例、main()
discovery.go    warden API 服务发现轮询
api.go          /_routes 动态路由管理 API（Bearer 鉴权、常量时间比较）
endpoints.go    内置只读端点（/_health）与 JSON 统一出口
nav.go          导航首页 SSR + /_api/nav + 后台拨测
rewrite.go      响应重写 funnel：Set-Cookie Path / Location（仅 ModeStrip）
metrics.go      /_metrics Prometheus 文本渲染（累积直方图，零依赖）
logging.go      访问日志中间件（statusRecorder 透传 Hijack/Flush/Unwrap）
timeout.go      每路由 ResponseHeaderTimeout：routingTransport 按路由选 Transport
duration.go     可 JSON 序列化时长（"10s" 字符串 ↔ 纳秒数字双面兼容）
routesfile.go   routes.toml 严格子集解析器 + 热加载 watcher + SIGHUP
docs/           技术实施方案（IMPLEMENTATION-PLAN.md）
verify/         浏览器/WS 端到端验证脚本与截图
build/          构建产物（warden-route-go）
```

测试约定：`*_test.go` 与源码同目录；`defects_test.go` 是历史缺陷回归集
（D1-D10）；每个能力遵循 RED→GREEN→负向验证（注入缺陷→测试转红）。

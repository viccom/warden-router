package main

// warden-route (Go) —— 单域名路径分流路由器
//
// 与 Python 版的差异：
//   - 转发核心用 net/http/httputil.ReverseProxy（stdlib，10 年生产验证）：
//       * WebSocket 升级由 handleUpgradeResponse + Hijack 原生处理
//       * hop-by-hop 头按 RFC 9110 §7.6.1 自动剥离
//       * FlushInterval=-1 实现真正的流式透传
//     因此不再有任何裸 socket 管道代码 —— Python 版那个"每 15s 必断"的
//     socket 超时 bug 在此结构下不可能存在。
//   - Transport 与 ReverseProxy 均为**包级单例**，经请求 context 传递路由。
//     绝不为每个请求新建 Transport：那会导致连接零复用 + fd 泄漏
//     （实测 300 请求泄漏 600 fd）。
//   - 动态路由层：/_routes API 在线增删改，内存 RWMutex + 原子落盘，
//     不重启、不依赖 warden 轮询。写操作强制 Bearer token 鉴权。
//   - 优雅停机：SIGTERM 后给在途请求（含 WS 终端会话）一个宽限期再收尾。

import (
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	listenAddr  = flag.String("listen", "127.0.0.1:9100", "监听地址")
	wardenAPI   = flag.String("warden", "http://127.0.0.1:8789", "warden API 基址")
	wardenToken = flag.String("warden-token", "", "warden API Bearer token（留空则读 WARDEN_API_TOKEN 或 /workspace/warden/.api-token）")
	adminTokenF = flag.String("admin-token", "", "/_routes 管理 API 的 Bearer token（留空则读 ROUTE_ADMIN_TOKEN 或 /workspace/warden/.api-token）")
	refreshSecs = flag.Duration("refresh", 30*time.Second, "warden 轮询间隔（必须 > 0）")
	routesFile  = flag.String("routes-file", "/workspace/router-go/routes.toml", "routes.toml 声明式路由文件（与代码静态路由合并，同前缀文件优先；文件缺失=仅代码静态路由）")
	routesSecs  = flag.Duration("routes-refresh", 5*time.Second, "routes.toml mtime 轮询间隔（必须 > 0；kill -HUP 可立即重载）")
	dynFile     = flag.String("dyn-file", "/workspace/router-go/dynamic-routes.json", "动态路由持久化文件")
	shutdownSec = flag.Duration("shutdown-grace", 15*time.Second, "收到 SIGTERM 后等待在途请求完成的宽限期")
)

// persistPath 由 main 注入，避免 routes.go 直接读全局变量产生耦合。
var persistPath string

// wardenTokenOnce 缓存从文件读到的 token，避免每 30s 重复读盘。
var (
	tokenOnce  sync.Once
	cachedWtok string
	cachedAtok string
)

func resolveTokens() {
	tokenOnce.Do(func() {
		cachedWtok = *wardenToken
		if cachedWtok == "" {
			cachedWtok = os.Getenv("WARDEN_API_TOKEN")
		}
		if cachedWtok == "" {
			cachedWtok = readTokenFile("/workspace/warden/.api-token")
		}

		cachedAtok = *adminTokenF
		if cachedAtok == "" {
			cachedAtok = os.Getenv("ROUTE_ADMIN_TOKEN")
		}
		if cachedAtok == "" {
			cachedAtok = readTokenFile("/workspace/warden/.api-token")
		}
		if cachedAtok == "" {
			log.Printf("[route] 警告：未配置 admin-token，/_routes 写操作将全部拒绝（503）")
		}
	})
}

func readTokenFile(p string) string {
	blob, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(blob))
}

var table = NewRouteTable()

// ---------------------------------------------------------------------------
// 转发核心：单例 Transport + 单例 ReverseProxy
// ---------------------------------------------------------------------------

type routeCtxKey struct{}

// sharedTransport 全局唯一。DialContext 的 5s 超时**仅作用于建连**，
// 不影响已建立连接的读取——这正是 Python 版 create_connection(timeout=10)
// 把长连接误杀的区别所在。
var sharedTransport = &http.Transport{
	DialContext: (&net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	MaxIdleConns:        200,
	MaxIdleConnsPerHost: 64,
	IdleConnTimeout:     90 * time.Second,
	// 不设 ResponseHeaderTimeout / TLSHandshakeTimeout 之外的长超时：
	// WS 与终端会话可能长时间无数据，任何读超时都会误杀。
}

var sharedProxy = &httputil.ReverseProxy{
	FlushInterval: -1, // 立即刷新，保证 SSE/流式响应不卡
	// routingTransport 按路由的 ResponseHeaderTimeout 选 Transport：
	// 未配超时的路由全部落到 sharedTransport 单例（默认路径零变化）。
	Transport: newRoutingTransport(),
	Rewrite: func(pr *httputil.ProxyRequest) {
		rt, ok := pr.In.Context().Value(routeCtxKey{}).(*Route)
		if !ok || rt == nil {
			// 理论上不可达（proxyTo 总会注入）；兜底避免 panic
			log.Printf("[route] Rewrite 缺少路由上下文 %s", pr.In.URL.Path)
			pr.Out.URL.Path = "/"
			pr.Out.URL.RawPath = ""
			return
		}
		target := &url.URL{
			Scheme: "http",
			Host:   net.JoinHostPort(rt.Host, strconv.Itoa(rt.Port)),
		}
		pr.SetURL(target)
		pr.Out.URL.Path = rt.Effective(pr.In.URL.Path)
		pr.Out.URL.RawPath = ""
		pr.Out.URL.RawQuery = pr.In.URL.RawQuery
		// auth_bridge：CloudStudio 网关会往每个转发请求注入自己的平台
		// JWT（Authorization: Bearer <iss=cloudstudio.net>），客户端真
		// token 头到达前就被替换。带桥接 cookie 时用 cookie 值覆盖恢复
		// （登录响应侧种的，见 bridgeLoginCookie）。
		restoreAuthHeader(pr, rt)
		// Host 头默认原样透传（反向代理标准语义，与 Python 版
		// router.py:294 的显式处理一致）：上游 kula 的 WS 同源校验拿
		// Origin 与 Host 比对。但发布网关会把入站 Host 改写为内部
		// 寻址形态（9000-<key>.e2b.<region>...，X-Forwarded-Host 亦
		// 被改写、不保留浏览器原值），此时透传即把改写值送给上游，
		// 校验必败——配了 public_host 的路由按 host_fix 改写为对外
		// 域名（== 浏览器 Origin）。缺失时（HTTP/1.0 无 Host）留空，
		// net/http 自动回退为上游地址。详见 hostfix.go。
		pr.Out.Host = fixedHost(pr.In.Host, rt)
		pr.SetXForwarded()
	},
	// 响应重写 funnel：Set-Cookie Path / Location 前缀修复。
	// ReverseProxy 对 101 升级不触发 ModifyResponse，WS 路径零影响。
	ModifyResponse: rewriteResponse,
	ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
		rt, _ := r.Context().Value(routeCtxKey{}).(*Route)
		prefix := "?"
		if rt != nil {
			prefix = rt.Prefix
		}
		// 客户端主动断开不是错误，不刷 502 日志
		if errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "context canceled") {
			return
		}
		log.Printf("[route] upstream %s error: %v", prefix, err)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "502 Bad Gateway (upstream down)")
	},
}

func proxyTo(w http.ResponseWriter, r *http.Request, rt *Route) {
	ctx := context.WithValue(r.Context(), routeCtxKey{}, rt)
	sharedProxy.ServeHTTP(w, r.WithContext(ctx))
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	flag.Parse()
	persistPath = *dynFile

	if *refreshSecs <= 0 {
		log.Fatalf("[route] -refresh 必须 > 0（当前 %v）；time.NewTicker 对非正值会 panic", *refreshSecs)
	}
	if *routesSecs <= 0 {
		log.Fatalf("[route] -routes-refresh 必须 > 0（当前 %v）；time.NewTicker 对非正值会 panic", *routesSecs)
	}
	resolveTokens()

	// 1) 写死路由
	table.SetStatic(staticRoutes())

	// 2) 恢复上次的动态路由（先于 warden 发现，保证冷启动即生效）
	if err := table.LoadDynamic(); err != nil {
		log.Printf("[route] 加载动态路由失败: %v", err)
	} else if n := len(table.GetDynamic()); n > 0 {
		log.Printf("[route] 已从磁盘恢复 %d 条动态路由", n)
	}

	// 3) warden 服务发现 + 动态路由后台拨测
	go discoveryLoop()
	go probeLoop(probeInterval)

	// 4) routes.toml 声明式路由：mtime 热加载 + SIGHUP 立即重载。
	//    与代码静态路由合并，同前缀文件优先；语法错误保留上一版。
	fr := &fileRoutes{path: *routesFile}
	go fr.watch(*routesSecs)
	fr.handleSignals(nil) // 同步注册 SIGHUP，立即返回

	mux := http.NewServeMux()
	mux.HandleFunc("/_health", handleHealth)
	mux.HandleFunc("/_metrics", handleMetrics)
	mux.HandleFunc("/_routes", handleRoutesAPI)
	mux.HandleFunc("/_routes/", handleRoutesAPI)
	mux.HandleFunc("/_api/nav", handleNavAPI) // 导航页 JS 增量刷新用（只读）
	mux.HandleFunc("/", handleAll)

	srv := &http.Server{
		Addr:              *listenAddr,
		Handler:           recoverMiddleware(loggingMiddleware(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB，防超大头
	}

	// 4) 优雅停机
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-ctx.Done()
		log.Printf("[route] 收到终止信号，%v 宽限期后收尾", *shutdownSec)
		shutCtx, cancel := context.WithTimeout(context.Background(), *shutdownSec)
		defer cancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			log.Printf("[route] 优雅停机超时，强制关闭: %v", err)
			_ = srv.Close()
		}
	}()

	log.Printf("[route] warden-route(go) listening on %s", *listenAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("[route] listen: %v", err)
	}
	log.Printf("[route] 已停止")
}

// recoverMiddleware 兜住 handler panic：net/http 自带的 recover 只打一行
// "http: panic serving" 就断连接，不带堆栈、不给响应。这里补上堆栈与 500。
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("[route] PANIC %s %s: %v\n%s", r.Method, r.URL.Path, rec, debug.Stack())
				defer func() { _ = recover() }() // 响应可能已开始写出
				http.Error(w, "500 internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// HTTP 处理
// ---------------------------------------------------------------------------

func handleAll(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if path == "/" {
		writeNav(w, r)
		return
	}

	rt, ok := table.Lookup(path)
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "not found", "hint": "visit / for navigation"})
		return
	}
	// 静态注入模式的门控路径（auth_bridge_token 三件套）：命中即
	// 换 cookie / 403，不转发上游。其余请求走正常代理。
	if handleAuthGate(w, r, rt) {
		return
	}
	proxyTo(w, r, rt)
}

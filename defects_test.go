package main

// 深度审查缺陷复现集（2026-10-14）。
// 修复后这些测试应全部转绿；任一转红即回归。
// 运行：go test -race -run TestDefect -v ./...

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fdCount 读 /proc/self/fd 条目数（含目录自身 fd，两次测量一致抵消）。
func fdCount(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(ents)
}

// fdCountStable 轮询到 fd 数连续 3 次不变（等待对端/服务端连接异步关闭），
// 最长等 d。避免用固定 sleep 造成慢机器上的假阳性。
func fdCountStable(t *testing.T, d time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(d)
	last, same := -1, 0
	for time.Now().Before(deadline) {
		c := fdCount(t)
		if c == last {
			same++
			if same >= 3 {
				return c
			}
		} else {
			last, same = c, 0
		}
		time.Sleep(10 * time.Millisecond)
	}
	return last
}

// swapTable 把包级 table 换成测试表，返回恢复函数。
func swapTable(tb *RouteTable) func() {
	saved := table
	table = tb
	return func() { table = saved }
}

// upstream 起一个内存上游服务。onNewConn（可为 nil）在每次 accept 新连接时调用。
// 返回 (host, port, accepted 计数, close)。
func upstream(t *testing.T, h http.HandlerFunc) (string, int, *int64, func()) {
	t.Helper()
	var accepted int64
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ConnState = func(c net.Conn, st http.ConnState) {
		if st == http.StateNew {
			atomic.AddInt64(&accepted, 1)
		}
	}
	srv.Start()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname(), port, &accepted, srv.Close
}

// staticTable 构造只含一条静态路由的表，并替换包级 table。
func staticTable(t *testing.T, prefix, host string, port int, rt *Route) func() {
	t.Helper()
	if rt == nil {
		rt = &Route{}
	}
	rt.Prefix, rt.Host, rt.Port = prefix, host, port
	tb := NewRouteTable()
	tb.SetStatic([]*Route{rt})
	return swapTable(tb)
}

// ---------------------------------------------------------------------------
// D1 健康状态 key 不匹配：services 用 display_name 存、用 name 查
// ---------------------------------------------------------------------------

func TestDefect_HealthKeyMismatch(t *testing.T) {
	tb := NewRouteTable()
	tb.SetDiscovered(
		[]*Route{{Prefix: "/speed/", Host: "127.0.0.1", Port: 8800, Name: "librespeed", Mode: ModeStrip}},
		[]svcHealth{{Name: "librespeed", Display: "网络测速", Health: "healthy"}},
	)
	for _, c := range tb.Cards() {
		if c.Prefix == "/speed/" && c.Health != "healthy" {
			t.Errorf("health=%q，期望 healthy（services map key 与查找 key 不一致）", c.Health)
		}
	}
}

// ---------------------------------------------------------------------------
// D2 LoadDynamic 不校验脏数据
// ---------------------------------------------------------------------------

func TestDefect_LoadDynamicValidation(t *testing.T) {
	f := filepath.Join(t.TempDir(), "d.json")
	os.WriteFile(f, []byte(`{"version":1,"routes":[
	{"prefix":"speed","host":"","port":0,"mode":99},
	{"prefix":"/","host":"1.2.3.4","port":80,"mode":0}]}`), 0o600)
	persistPath = f
	defer func() { persistPath = "" }()
	tb := NewRouteTable()
	if err := tb.LoadDynamic(); err != nil {
		t.Fatal(err)
	}
	if n := len(tb.GetDynamic()); n != 0 {
		t.Errorf("加载了 %d 条非法路由，应为 0", n)
	}
	if _, ok := tb.Lookup("/anything"); ok {
		t.Error("prefix=/ 劫持了全部路径")
	}
}

// ---------------------------------------------------------------------------
// D3 并发持久化竞态 → 路由丢失 / 文件损坏
// ---------------------------------------------------------------------------

func TestDefect_PersistRace(t *testing.T) {
	f := filepath.Join(t.TempDir(), "d.json")
	persistPath = f
	defer func() { persistPath = "" }()
	tb := NewRouteTable()
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tb.Upsert(&Route{Prefix: fmt.Sprintf("/r%02d/", i), Host: "127.0.0.1", Port: 8000, Mode: ModeStrip})
		}(i)
	}
	wg.Wait()
	blob, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	var df dynamicFile
	if err := json.Unmarshal(blob, &df); err != nil {
		t.Fatalf("持久化文件损坏: %v", err)
	}
	if len(df.Routes) != 40 {
		t.Errorf("落盘 %d 条，期望 40", len(df.Routes))
	}
}

// ---------------------------------------------------------------------------
// D4 Icon 未转义 → 存储型 XSS。断言目标：**注入载荷**在渲染输出中必须
// 以转义形态出现。注意页面自身带一个 <script> 元素（渐进增强的 15s 增量
// 刷新，见 nav.go），故断言瞄准载荷字符串，不能简单禁一切 script 标签。
// ---------------------------------------------------------------------------

func TestDefect_IconXSS(t *testing.T) {
	tb := NewRouteTable()
	tb.Upsert(&Route{Prefix: "/e/", Host: "127.0.0.1", Port: 1, Mode: ModeStrip,
		Icon: `"><script>alert(1)</script>`, Display: "<img onerror=x>", Desc: "d"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	defer swapTable(tb)()
	writeNav(rec, req)
	out := rec.Body.String()
	if strings.Contains(out, `"><script>alert(1)</script>`) {
		t.Errorf("渲染输出含未转义注入载荷：\n%s", out)
	}
	if strings.Contains(out, "<img onerror") {
		t.Errorf("渲染输出含未转义 <img onerror>")
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Errorf("期望看到转义后的载荷，实际未出现")
	}
}

// ---------------------------------------------------------------------------
// D5 每请求新建 Transport → 连接零复用。
// 断言：N 次请求，上游 accepted 连接数应远小于 N。
// ---------------------------------------------------------------------------

func TestDefect_TransportReuse(t *testing.T) {
	host, port, accepted, closeUp := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})
	defer closeUp()
	defer staticTable(t, "/t/", host, port, &Route{Mode: ModeStrip, Name: "t"})()

	const n = 200
	for i := 0; i < n; i++ {
		rec := httptest.NewRecorder()
		handleAll(rec, httptest.NewRequest("GET", "/t/x", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("第 %d 次请求 code=%d body=%s", i, rec.Code, rec.Body.String())
		}
	}
	got := atomic.LoadInt64(accepted)
	if got >= n/4 {
		t.Errorf("上游 accepted %d 个连接 / %d 次请求——连接未复用（每请求新建 Transport）", got, n)
	}
	t.Logf("%d 次请求 → 上游 accepted %d 个连接", n, got)
}

// ---------------------------------------------------------------------------
// D6 fd 泄漏（实测 300 请求泄漏 600 fd）。
// 断言：N 次代理后关闭空闲连接，fd 数应回到基线。
// 注意：必须调 CloseIdleConnections 再测——修复版池化连接本就是"空闲"状态，
// 不关就分不清"池化复用"与"泄漏"；缺陷版的 Transport 每请求新建且已不可达，
// 无法关闭，其连接会一直挂住，从而被这个断言抓住。
// ---------------------------------------------------------------------------

func TestDefect_FdLeak(t *testing.T) {
	host, port, _, closeUp := upstream(t, func(w http.ResponseWriter, r *http.Request) {})
	defer closeUp()
	defer staticTable(t, "/f/", host, port, &Route{Mode: ModeStrip, Name: "f"})()

	before := fdCountStable(t, 500*time.Millisecond)
	const n = 200
	for i := 0; i < n; i++ {
		rec := httptest.NewRecorder()
		handleAll(rec, httptest.NewRequest("GET", "/f/x", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("第 %d 次请求 code=%d", i, rec.Code)
		}
	}
	sharedTransport.CloseIdleConnections()
	after := fdCountStable(t, 3*time.Second)
	if growth := after - before; growth > 8 {
		t.Errorf("%d 次代理后 fd 增长 %d（%d → %d），疑似连接泄漏", n, growth, before, after)
	} else {
		t.Logf("%d 次代理：fd %d → %d（增长 %d）", n, before, after, growth)
	}
}

// ---------------------------------------------------------------------------
// D7 裸 API 透传不该进导航宫格（Python 版 PASSTHROUGH 同样不进首页）
// ---------------------------------------------------------------------------

func TestDefect_NavHiddenPassthrough(t *testing.T) {
	tb := NewRouteTable()
	tb.SetStatic([]*Route{
		{Prefix: "/api/v1/", Host: "127.0.0.1", Port: 8789, Mode: ModeKeep, Name: "web-gateway", Hidden: true},
		{Prefix: "/warden/", Host: "127.0.0.1", Port: 8789, Mode: ModeStrip, Name: "web-gateway"},
	})
	cards := tb.Cards()
	if len(cards) != 1 {
		t.Fatalf("Cards() 返回 %d 张卡片，期望 1（Hidden 透传端点应被过滤）", len(cards))
	}
	if cards[0].Prefix != "/warden/" {
		t.Errorf("剩余卡片是 %s，期望 /warden/", cards[0].Prefix)
	}
	// Hidden 只影响导航展示，不影响转发
	if _, ok := tb.Lookup("/api/v1/services"); !ok {
		t.Error("Hidden 路由仍必须可被 Lookup 命中")
	}
	// 渲染层同样不应出现被隐藏的前缀
	rec := httptest.NewRecorder()
	defer swapTable(tb)()
	writeNav(rec, httptest.NewRequest("GET", "/", nil))
	if strings.Contains(rec.Body.String(), "/api/v1/") {
		t.Error("导航页出现了 Hidden 透传端点 /api/v1/")
	}
}

// ---------------------------------------------------------------------------
// D9 静态路由数据 parity：Name 必须是 warden **注册名**（否则健康查表落空、
// 导航恒显 unknown），裸透传必须 Hidden（否则宫格出现 /api/v1/ 这类内部端点）。
// 本测试直接断言 staticRoutes() 的产出，把"改回 warden-ui"这类数据回归
// 变成编译期之外的可失败断言。
// ---------------------------------------------------------------------------

func TestDefect_StaticRouteDataParity(t *testing.T) {
	rs := staticRoutes()
	byPrefix := map[string]*Route{}
	for _, r := range rs {
		byPrefix[r.Prefix] = r
	}
	// 健康查表依据：warden services.toml 里的注册名
	wantName := map[string]string{
		"/warden/":   "web-gateway", // warden 自身（曾误写 warden-ui 导致恒 unknown）
		"/monitor/":  "kula",
		"/terminal/": "terminal",
	}
	for p, name := range wantName {
		r, ok := byPrefix[p]
		if !ok {
			t.Errorf("缺少静态路由 %s", p)
			continue
		}
		if r.Name != name {
			t.Errorf("%s Name=%q，期望 %q（warden 注册名，健康查表依据）", p, r.Name, name)
		}
	}
	// 裸 API 透传不进导航宫格（与 Python 版 PASSTHROUGH 行为一致）
	for _, p := range []string{"/api/v1/", "/backend/"} {
		r, ok := byPrefix[p]
		if !ok {
			t.Errorf("缺少静态路由 %s", p)
			continue
		}
		if !r.Hidden {
			t.Errorf("%s 未标记 Hidden，会作为内部端点出现在导航宫格", p)
		}
		if r.Mode != ModeKeep {
			t.Errorf("%s Mode=%d，期望 ModeKeep（前缀保留透传）", p, r.Mode)
		}
	}
	// 语义锚点：/warden/ 剥离前缀，/monitor/、/terminal/ 保留前缀
	if byPrefix["/warden/"].Mode != ModeStrip {
		t.Error("/warden/ 应为 ModeStrip")
	}
	if byPrefix["/monitor/"].Mode != ModeKeep || byPrefix["/terminal/"].Mode != ModeKeep {
		t.Error("/monitor/、/terminal/ 应为 ModeKeep（base_path 应用）")
	}
}

// ---------------------------------------------------------------------------
// D8 静态路由 Name 与 warden 真实注册名不一致 → 健康状态恒 unknown。
// /warden/ 背后就是 warden 服务，注册名 web-gateway（Python 版写 "warden-ui"
// 再靠硬编码特判打补丁；Go 版用真实服务名让通用查表自然命中）。
// ---------------------------------------------------------------------------

func TestDefect_HealthByRealServiceName(t *testing.T) {
	tb := NewRouteTable()
	tb.SetStatic([]*Route{
		{Prefix: "/warden/", Host: "127.0.0.1", Port: 8789, Mode: ModeStrip, Name: "web-gateway"},
	})
	tb.SetDiscovered(nil, []svcHealth{
		{Name: "web-gateway", Display: "warden-route 路由器", Health: "healthy"},
		{Name: "kula", Display: "Kula 主机监控", Health: "healthy"},
	})
	for _, c := range tb.Cards() {
		if c.Prefix == "/warden/" && c.Health != "healthy" {
			t.Errorf("/warden/ health=%q，期望 healthy（Name 须匹配 warden 注册名 web-gateway）", c.Health)
		}
	}
}

// ---------------------------------------------------------------------------
// D10 Host 头被改写为上游地址 → 上游同源校验（kula CheckOrigin）全量 403。
// 浏览器 WS 握手必带 Origin；kula 的 CheckOrigin 要求 Origin.host == r.Host
// （internal/web/websocket.go）。路由器若把 Host 改写成 127.0.0.1:27960，
// Origin(webview...) 与 Host 必然失配 → 403 → 仪表盘 "WebSocket connection
// failed"（2026-10-14 生产实测 101 → 403）。Python 版 router.py:294 本就
// 透传原始 Host，Go 版一度回归。
// httptest.ResponseRecorder 不支持 Hijack，故本测试起真 TCP 服务器做真实
// WS 握手，上游模仿 kula 的 CheckOrigin 语义。
// ---------------------------------------------------------------------------

func TestDefect_HostForwardedForOriginCheck(t *testing.T) {
	// 上游：模仿 kula 的 CheckOrigin（Origin 非空时其 host 必须等于请求 Host 头）
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "plain")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || u.Host != r.Host {
				http.Error(w, "invalid origin", http.StatusForbidden)
				return
			}
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n" +
			"Connection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		_ = buf.Flush()
		time.Sleep(50 * time.Millisecond) // 等 router 隧道把响应头读走
	}))
	defer up.Close()
	uu, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(uu.Port())
	if err != nil {
		t.Fatal(err)
	}

	tb := NewRouteTable()
	tb.SetStatic([]*Route{{Prefix: "/mon/", Host: uu.Hostname(), Port: port, Mode: ModeKeep, Name: "kula"}})
	defer swapTable(tb)()
	// 真路由器服务器：与生产相同的 handleAll → sharedProxy 链路
	routerSrv := httptest.NewServer(recoverMiddleware(http.HandlerFunc(handleAll)))
	defer routerSrv.Close()
	ru, err := url.Parse(routerSrv.URL)
	if err != nil {
		t.Fatal(err)
	}

	wsHandshake := func(host, origin string) int {
		t.Helper()
		conn, err := net.DialTimeout("tcp", ru.Host, 5*time.Second)
		if err != nil {
			t.Fatalf("dial router: %v", err)
		}
		defer conn.Close()
		req := "GET /mon/ws HTTP/1.1\r\nHost: " + host + "\r\nUpgrade: websocket\r\n" +
			"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
			"Sec-WebSocket-Version: 13\r\n"
		if origin != "" {
			req += "Origin: " + origin + "\r\n"
		}
		req += "\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("write handshake: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			t.Fatalf("read status line: %v", err)
		}
		var code int
		if _, err := fmt.Sscanf(strings.TrimSpace(line), "HTTP/1.1 %d", &code); err != nil {
			t.Fatalf("parse status %q: %v", line, err)
		}
		return code
	}

	if code := wsHandshake("monitor.example.com", "https://monitor.example.com"); code != 101 {
		t.Errorf("浏览器同源 WS 握手 code=%d，期望 101（Host 未透传 → 上游同源校验误伤）", code)
	}
	if code := wsHandshake("monitor.example.com", ""); code != 101 {
		t.Errorf("无 Origin 的 CLI 握手 code=%d，期望 101", code)
	}
	if code := wsHandshake("monitor.example.com", "https://evil.example"); code != 403 {
		t.Errorf("跨源 WS 握手 code=%d，期望 403（上游同源校验必须仍然有效）", code)
	}
}

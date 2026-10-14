package main

// 导航前端 + 后台拨测的行为测试（2026-10-14）。
// 运行：go test -race -run 'TestNav|TestProbe' -v ./...

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// 新标签页约定：每张卡片都必须 target=_blank + rel=noopener noreferrer
// ---------------------------------------------------------------------------

func TestNav_NewTabLinks(t *testing.T) {
	host, port, _, closeUp := upstream(t, func(w http.ResponseWriter, r *http.Request) {})
	defer closeUp()
	tb := NewRouteTable()
	tb.SetStatic([]*Route{
		{Prefix: "/a/", Host: host, Port: port, Mode: ModeStrip, Name: "a", Display: "甲"},
	})
	tb.Upsert(&Route{Prefix: "/b/", Host: host, Port: port, Mode: ModeStrip, Display: "乙", Icon: "🔧"})
	defer swapTable(tb)()

	rec := httptest.NewRecorder()
	writeNav(rec, httptest.NewRequest("GET", "/", nil))
	out := rec.Body.String()
	if n := strings.Count(out, `target="_blank"`); n != 2 {
		t.Errorf("target=_blank 出现 %d 次，期望 2（每张卡片一个新标签页）", n)
	}
	if n := strings.Count(out, `rel="noopener noreferrer"`); n != 2 {
		t.Errorf("rel=noopener noreferrer 出现 %d 次，期望 2", n)
	}
	for _, want := range []string{`href="/a/"`, `href="/b/"`, "甲", "乙", "🔧"} {
		if !strings.Contains(out, want) {
			t.Errorf("导航页缺少 %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// 动态路由（/_routes API 添加的）必须实时出现在导航宫格
// ---------------------------------------------------------------------------

func TestNav_DynamicRouteAppears(t *testing.T) {
	tb := NewRouteTable()
	tb.Upsert(&Route{Prefix: "/dyn/", Host: "127.0.0.1", Port: 9999, Mode: ModeStrip,
		Display: "动态测试台", Desc: "运行时添加"})
	defer swapTable(tb)()

	rec := httptest.NewRecorder()
	writeNav(rec, httptest.NewRequest("GET", "/", nil))
	out := rec.Body.String()
	for _, want := range []string{"动态测试台", "/dyn/", "运行时添加", "动态"} {
		if !strings.Contains(out, want) {
			t.Errorf("导航页缺少 %q——动态路由应实时出现在宫格", want)
		}
	}
}

// ---------------------------------------------------------------------------
// /_api/nav 只读 JSON 端点（导航页 JS 增量刷新用）
// ---------------------------------------------------------------------------

func TestNavAPI(t *testing.T) {
	host, port, _, closeUp := upstream(t, func(w http.ResponseWriter, r *http.Request) {})
	defer closeUp()
	tb := NewRouteTable()
	tb.Upsert(&Route{Prefix: "/json-route/", Host: host, Port: port, Mode: ModeKeep, Display: "JSON 台"})
	defer swapTable(tb)()

	rec := httptest.NewRecorder()
	handleNavAPI(rec, httptest.NewRequest("GET", "/_api/nav", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET code=%d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type=%q，期望 application/json", ct)
	}
	var resp struct {
		Routes []map[string]string `json:"routes"`
		Ts     int64               `json:"ts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if len(resp.Routes) != 1 {
		t.Fatalf("routes %d 条，期望 1", len(resp.Routes))
	}
	r := resp.Routes[0]
	if r["prefix"] != "/json-route/" || r["display"] != "JSON 台" || r["health"] != "unknown" {
		t.Errorf("route 字段不符: %v", r)
	}
	if resp.Ts == 0 {
		t.Error("缺少 ts 字段")
	}

	rec2 := httptest.NewRecorder()
	handleNavAPI(rec2, httptest.NewRequest("POST", "/_api/nav", nil))
	if rec2.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST code=%d，期望 405（只读端点）", rec2.Code)
	}
}

// ---------------------------------------------------------------------------
// 拨测器：活端口 healthy、死端口 unhealthy；warden 已覆盖的不重复拨测
// ---------------------------------------------------------------------------

func TestProbe_AliveAndDead(t *testing.T) {
	host, port, _, closeUp := upstream(t, func(w http.ResponseWriter, r *http.Request) {})
	defer closeUp()
	// 死端口：listen(0) 取端口后立即关闭
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	tb := NewRouteTable()
	tb.Upsert(&Route{Prefix: "/live/", Host: host, Port: port, Mode: ModeStrip})
	tb.Upsert(&Route{Prefix: "/dead/", Host: "127.0.0.1", Port: deadPort, Mode: ModeStrip})
	defer swapTable(tb)()
	defer swapProbe()()

	probeOnce()
	health := map[string]string{}
	for _, c := range tb.Cards() {
		health[c.Prefix] = cardHealth(c)
	}
	if health["/live/"] != "healthy" {
		t.Errorf("/live/ health=%q，期望 healthy", health["/live/"])
	}
	if health["/dead/"] != "unhealthy" {
		t.Errorf("/dead/ health=%q，期望 unhealthy", health["/dead/"])
	}

	// 渲染层：unhealthy 的点必须带上对应 class
	rec := httptest.NewRecorder()
	writeNav(rec, httptest.NewRequest("GET", "/", nil))
	out := rec.Body.String()
	if !strings.Contains(out, `class="dot unhealthy"`) {
		t.Error("渲染输出缺少 unhealthy 状态点")
	}
	if !strings.Contains(out, `class="dot healthy"`) {
		t.Error("渲染输出缺少 healthy 状态点")
	}
}

// 拨测后清理：路由删除 → probeHealth 残留必须被清掉
func TestProbe_StaleCleanup(t *testing.T) {
	host, port, _, closeUp := upstream(t, func(w http.ResponseWriter, r *http.Request) {})
	defer closeUp()
	tb := NewRouteTable()
	tb.Upsert(&Route{Prefix: "/gone/", Host: host, Port: port, Mode: ModeStrip})
	defer swapTable(tb)()
	defer swapProbe()()

	probeOnce()
	if cardHealth(&Route{Prefix: "/gone/"}) != "healthy" {
		t.Fatal("前置条件不成立：拨测未生效")
	}
	tb.Delete("/gone/")
	probeOnce()
	probeMu.RLock()
	_, left := probeHealth["/gone/"]
	probeMu.RUnlock()
	if left {
		t.Error("路由已删除，probeHealth 残留未清理")
	}
}

// ---------------------------------------------------------------------------
// 只拨测回环/私网/链路本地：公网 IP 与主机名一律跳过（不做对外灯塔）
// ---------------------------------------------------------------------------

func TestProbe_SkipsExternal(t *testing.T) {
	tb := NewRouteTable()
	tb.Upsert(&Route{Prefix: "/ext/", Host: "93.184.216.34", Port: 80, Mode: ModeStrip, Display: "外部"})
	tb.Upsert(&Route{Prefix: "/dn/", Host: "example.com", Port: 443, Mode: ModeStrip, Display: "域名"})
	defer swapTable(tb)()
	defer swapProbe()()

	probeOnce()
	probeMu.RLock()
	_, ext := probeHealth["/ext/"]
	_, dn := probeHealth["/dn/"]
	probeMu.RUnlock()
	if ext || dn {
		t.Error("公网 IP / 主机名被拨测了——路由器不应对公网发起周期性连接")
	}
	for _, c := range tb.Cards() {
		if h := cardHealth(c); h != "unknown" {
			t.Errorf("%s health=%q，期望 unknown（跳过拨测）", c.Prefix, h)
		}
	}
}

func TestProbeableHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true}, {"127.8.9.9", true}, {"::1", true},
		{"10.0.0.1", true}, {"192.168.1.5", true}, {"172.16.3.4", true}, {"172.31.255.255", true},
		{"169.254.1.1", true}, {"fe80::1", true}, {"fd00::1", true},
		{"8.8.8.8", false}, {"1.1.1.1", false}, {"93.184.216.34", false},
		{"172.32.0.1", false}, // 172.16/12 之外即公网
		{"example.com", false}, {"", false},
	}
	for _, c := range cases {
		if got := probeableHost(c.host); got != c.want {
			t.Errorf("probeableHost(%q)=%v，期望 %v", c.host, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// 非法健康值归一为 unknown，防止任意字符串进入 class
// ---------------------------------------------------------------------------

func TestNav_HealthNormalized(t *testing.T) {
	tb := NewRouteTable()
	tb.Upsert(&Route{Prefix: "/weird/", Host: "127.0.0.1", Port: 1, Mode: ModeStrip, Health: "banana"})
	defer swapTable(tb)()

	rec := httptest.NewRecorder()
	writeNav(rec, httptest.NewRequest("GET", "/", nil))
	out := rec.Body.String()
	if strings.Contains(out, "dot banana") {
		t.Error("非法健康值原样渲染进了 class")
	}
	if !strings.Contains(out, `class="dot unknown"`) {
		t.Error("非法健康值应归一为 unknown")
	}
}

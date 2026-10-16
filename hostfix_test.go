package main

// host_fix 测试（2026-10-15）。
//
// 背景：artifact release 发布通道的平台网关（CloudStudio Gateway）会把
// 入站请求的 Host 改写为内部寻址 Host
// （9000-<space-key>.e2b.<region>.sandbox.cloudstudio.club），且
// X-Forwarded-Host 被一并改写、不保留浏览器原值（2026-10-15 公网
// 干净实验实锤：curl 以发布域名发出，kula 收到的 Host 是网关形态）。
// 上游 kula 的 WS 同源校验拿 Origin 与 Host 比对，必然 403。
//
// host_fix 与 auth_bridge 同构：恢复被网关破坏的请求语义。配了
// public_host 且入站 Host 确为网关形态时改写为对外域名；其余情况
// 原样透传（含未配置与本地访问）。

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// isGatewayHost 纯函数表
// ---------------------------------------------------------------------------

func TestIsGatewayHost(t *testing.T) {
	cases := []struct {
		name string
		host string
		want bool
	}{
		{"实测网关形态 gz2", "9000-3b000f6ccabc4cd0ad2c77a3285711c6.e2b.gz2.sandbox.cloudstudio.club", true},
		{"实测网关形态 sh3", "9000-3b000f6ccabc4cd0ad2c77a3285711c6.e2b.sh3.sandbox.cloudstudio.club", true},
		{"其他端口与 space-key", "1234-abcdef0123456789abcdef0123456789.e2b.gz2.sandbox.cloudstudio.club", true},
		{"带端口（剥端口后匹配）", "9000-3b000f6ccabc4cd0ad2c77a3285711c6.e2b.gz2.sandbox.cloudstudio.club:443", true},
		{"发布域名", "ad8584f64ca039337.app.workbuddy.host", false},
		{"回环", "127.0.0.1:9000", false},
		{"localhost", "localhost:9000", false},
		{"普通域名", "example.com", false},
		{"空", "", false},
		{"前缀非端口段", "evil-9000-3b000f6ccabc4cd0ad2c77a3285711c6.e2b.gz2.sandbox.cloudstudio.club", false},
		{"hex 段太短", "9000-xyz.e2b.gz2.sandbox.cloudstudio.club", false},
		{"后缀被拼接逃逸", "9000-3b000f6ccabc4cd0ad2c77a3285711c6.e2b.gz2.sandbox.cloudstudio.club.evil.com", false},
		{"大小写混合（域名不分区大小写，但网关段固定小写）", "9000-3B000F6CCABC4CD0AD2C77A3285711C6.e2b.gz2.sandbox.cloudstudio.club", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isGatewayHost(tc.host); got != tc.want {
				t.Errorf("isGatewayHost(%q) = %v，期望 %v", tc.host, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 集成：host_fix 经完整代理链（handleAll + sharedProxy）
// ---------------------------------------------------------------------------

// hostFixSeen 记录上游实际收到的寻址相关头。
type hostFixSeen struct {
	host string // Host
	xfh  string // X-Forwarded-Host
	xfp  string // X-Forwarded-Proto
}

// hostFixChain 组装完整链路：上游记录收到的 Host 与 X-Forwarded-*，
// 路由带 PublicHost / HostFixOrigin。返回 (代理基址, 记录指针)。
func hostFixChain(t *testing.T, prefix, publicHost string, hostFixOrigin bool) (*httptest.Server, *hostFixSeen) {
	t.Helper()
	var seen hostFixSeen
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.host = r.Host
		seen.xfh = r.Header.Get("X-Forwarded-Host")
		seen.xfp = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.Close)
	host, port := hostPort(t, up.URL)

	tb := NewRouteTable()
	tb.SetStatic([]*Route{{
		Prefix: prefix, Host: host, Port: port, Mode: ModeKeep,
		Name: "app", PublicHost: publicHost, HostFixOrigin: hostFixOrigin,
	}})
	t.Cleanup(swapTable(tb))

	srv := httptest.NewServer(recoverMiddleware(loggingMiddleware(http.HandlerFunc(handleAll))))
	t.Cleanup(srv.Close)
	return srv, &seen
}

// H1 网关形态 Host + 配了 public_host → 上游收到对外域名
// （kula Origin 校验 Host==Origin 自然通过，无需白名单）
func TestHostFix_GatewayHostRewritten(t *testing.T) {
	const gw = "9000-3b000f6ccabc4cd0ad2c77a3285711c6.e2b.gz2.sandbox.cloudstudio.club"
	srv, seen := hostFixChain(t, "/monitor/", "ad8584f64ca039337.app.workbuddy.host", false)

	req, _ := http.NewRequest("GET", srv.URL+"/monitor/api/config", nil)
	req.Host = gw // 模拟平台网关改写后的入站 Host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen.host != "ad8584f64ca039337.app.workbuddy.host" {
		t.Errorf("上游收到 Host = %q，期望改写为 %q", seen.host, "ad8584f64ca039337.app.workbuddy.host")
	}
}

// H2 未配 public_host → 网关形态 Host 原样透传（存量行为不变）
func TestHostFix_NoConfig_Passthrough(t *testing.T) {
	const gw = "9000-3b000f6ccabc4cd0ad2c77a3285711c6.e2b.gz2.sandbox.cloudstudio.club"
	srv, seen := hostFixChain(t, "/monitor/", "", false)

	req, _ := http.NewRequest("GET", srv.URL+"/monitor/api/config", nil)
	req.Host = gw
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen.host != gw {
		t.Errorf("上游收到 Host = %q，期望原样透传 %q", seen.host, gw)
	}
}

// H3 配了 public_host 但入站 Host 非网关形态（本地/直连）→ 不误改
func TestHostFix_NonGatewayHostUntouched(t *testing.T) {
	srv, seen := hostFixChain(t, "/monitor/", "ad8584f64ca039337.app.workbuddy.host", false)

	resp, err := http.Get(srv.URL + "/monitor/api/config") // req.Host = 127.0.0.1:port
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen.host == "ad8584f64ca039337.app.workbuddy.host" {
		t.Errorf("本地访问被误改写为对外域名：%q", seen.host)
	}
	if seen.host == "" {
		t.Errorf("上游未收到 Host")
	}
}

// H4 fixedHost 组合表（含 nil 路由安全）
func TestFixedHost(t *testing.T) {
	const gw = "9000-3b000f6ccabc4cd0ad2c77a3285711c6.e2b.gz2.sandbox.cloudstudio.club"
	const pub = "run-agent-abc-preview.agent-sandbox-bj-c1-gw.traecontent.cn"
	cases := []struct {
		name, in, origin, public, want string
		hostFixOrigin                  bool
	}{
		{"public_host+网关形态→改写", gw, "", "app.example.com", "app.example.com", false},
		{"没配+网关形态→透传", gw, "", "", gw, false},
		{"配了+普通Host→透传", "127.0.0.1:9000", "", "app.example.com", "127.0.0.1:9000", false},
		{"origin模式+公网Origin→改写", "localhost:9100", "https://" + pub, "", pub, true},
		{"origin模式+回环Origin→透传", "localhost:9100", "http://localhost:9100", "", "localhost:9100", true},
		{"origin模式+缺Origin→透传", "localhost:9100", "", "", "localhost:9100", true},
		{"未启用origin模式→透传", "localhost:9100", "https://" + pub, "", "localhost:9100", false},
		{"两种都配且网关形态→public_host优先", gw, "https://" + pub, "app.example.com", "app.example.com", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &Route{PublicHost: tc.public, HostFixOrigin: tc.hostFixOrigin}
			if got := fixedHost(tc.in, tc.origin, rt); got != tc.want {
				t.Errorf("fixedHost(%q, %q) = %q，期望 %q", tc.in, tc.origin, got, tc.want)
			}
		})
	}
	// nil 路由不得 panic
	if got := fixedHost(gw, "https://example.com", nil); got != gw {
		t.Errorf("fixedHost(%q, ..., nil) = %q，期望透传", gw, got)
	}
}

// ---------------------------------------------------------------------------
// Trae 预览通道变体（host_fix_origin，2026-10-16）
//
// 平台把入站 Host 改写成**本机地址**（localhost:9100），而浏览器 Origin
// 是每会话动态的公网域名（run-agent-<sid>-preview.<region>.traecontent.cn）。
// 以 Origin 为权威来源恢复上游 Host：kula WS 同源校验通过、OpenList
// 不再按 localhost 生成绝对链接。
// ---------------------------------------------------------------------------

// H5 host_fix_origin：入站 Host 为本机地址 + Origin 为公网域名 → 恢复为 Origin host
func TestHostFix_OriginRestored(t *testing.T) {
	const pub = "run-agent-6ad02c147712db83b652fb8a-37dlohfiq6eln3yd4ga-preview.agent-sandbox-bj-c1-gw.traecontent.cn"
	srv, seen := hostFixChain(t, "/monitor/", "", true)

	req, _ := http.NewRequest("GET", srv.URL+"/monitor/ws", nil)
	req.Host = "localhost:9100" // 模拟 Trae 预览代理改写后的入站 Host
	req.Header.Set("Origin", "https://"+pub)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen.host != pub {
		t.Errorf("上游收到 Host = %q，期望恢复为 Origin host %q", seen.host, pub)
	}
}

// H6 host_fix_origin + 无 Origin（命令行直连等非浏览器客户端）→ 原样透传
func TestHostFix_OriginAbsent_Passthrough(t *testing.T) {
	srv, seen := hostFixChain(t, "/monitor/", "", true)

	req, _ := http.NewRequest("GET", srv.URL+"/monitor/ws", nil)
	req.Host = "localhost:9100"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen.host != "localhost:9100" {
		t.Errorf("无 Origin 时不应改写，上游收到 Host = %q", seen.host)
	}
}

// H7 host_fix_origin + Origin 为回环（本地浏览器调试）→ 不误改
func TestHostFix_LoopbackOriginUntouched(t *testing.T) {
	srv, seen := hostFixChain(t, "/monitor/", "", true)

	req, _ := http.NewRequest("GET", srv.URL+"/monitor/ws", nil)
	req.Host = "localhost:9100"
	req.Header.Set("Origin", "http://localhost:9100")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen.host != "localhost:9100" {
		t.Errorf("回环 Origin 不应触发改写，上游收到 Host = %q", seen.host)
	}
}

// H8 host_fix_origin 未启用（默认）→ 即使带公网 Origin 也原样透传（零影响）
func TestHostFix_OriginDisabledByDefault(t *testing.T) {
	srv, seen := hostFixChain(t, "/monitor/", "", false)

	req, _ := http.NewRequest("GET", srv.URL+"/monitor/ws", nil)
	req.Host = "localhost:9100"
	req.Header.Set("Origin", "https://example.com")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen.host != "localhost:9100" {
		t.Errorf("未启用时不应当改写，上游收到 Host = %q", seen.host)
	}
}

// H11 Referer 回退：GET 类子资源请求浏览器不带 Origin，改用 Referer 的 host
// （同源请求默认 Referrer-Policy 会带完整 URL）
func TestHostFix_RefererFallback(t *testing.T) {
	const pub = "run-agent-abc-preview.agent-sandbox-bj-a1-gw.traecontent.cn"
	srv, seen := hostFixChain(t, "/openlist/", "", true)

	req, _ := http.NewRequest("GET", srv.URL+"/openlist/api/fs/get?path=/123pan", nil)
	req.Host = "localhost:9100"
	req.Header.Set("Referer", "https://"+pub+"/openlist/")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen.host != pub {
		t.Errorf("上游收到 Host = %q，期望按 Referer 恢复为 %q", seen.host, pub)
	}
}

// H12 X-Forwarded-Host 与裁决后的 Host 同步：上游（OpenList 等）反推对外
// URL 时优先读 XFH；若 XFH 留成平台改写后的入站内网 Host，改写 Host 也救
// 不回来（实测 2026-10-16：raw_url 仍为 http://localhost:9100/…）
func TestHostFix_XForwardedHostAligned(t *testing.T) {
	const pub = "run-agent-abc-preview.agent-sandbox-bj-a1-gw.traecontent.cn"
	srv, seen := hostFixChain(t, "/openlist/", "", true)

	req, _ := http.NewRequest("POST", srv.URL+"/openlist/api/fs/get", nil)
	req.Host = "localhost:9100" // 平台改写后的入站 Host
	req.Header.Set("Origin", "https://"+pub)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen.host != pub {
		t.Errorf("上游 Host = %q，期望 %q", seen.host, pub)
	}
	if seen.xfh != pub {
		t.Errorf("上游 X-Forwarded-Host = %q，期望同步为 %q（否则上游按 XFH 生成内网绝对链接）", seen.xfh, pub)
	}
}

// H13 X-Forwarded-Proto 同步：上游（OpenList 等）按 XFP 决定绝对链接 scheme。
// 平台入站是明文，不覆盖则 https 页面拿到 http:// 链接（混合内容）。
func TestHostFix_XForwardedProtoAligned(t *testing.T) {
	const pub = "run-agent-abc-preview.agent-sandbox-bj-a1-gw.traecontent.cn"
	srv, seen := hostFixChain(t, "/openlist/", "", true)

	req, _ := http.NewRequest("POST", srv.URL+"/openlist/api/fs/get", nil)
	req.Host = "localhost:9100"
	req.Header.Set("Origin", "https://"+pub)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen.xfp != "https" {
		t.Errorf("上游 X-Forwarded-Proto = %q，期望 https（否则 https 页面拿到 http:// 绝对链接）", seen.xfp)
	}
}

// H9 publicOriginHost 纯函数表：只认 http/https 且非回环的 host
func TestPublicOriginHost(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"公网 https", "https://run-agent-abc-preview.agent-sandbox-bj-c1-gw.traecontent.cn", "run-agent-abc-preview.agent-sandbox-bj-c1-gw.traecontent.cn"},
		{"公网带端口", "http://example.com:8080", "example.com:8080"},
		{"Referer 带路径与查询", "https://example.com/openlist/?x=1", "example.com"},
		{"回环 localhost", "http://localhost:9100", ""},
		{"回环 127", "http://127.0.0.1:9100", ""},
		{"回环 ::1", "http://[::1]:9100", ""},
		{"file 协议", "file:///tmp/x", ""},
		{"无 scheme", "example.com", ""},
		{"空", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := publicOriginHost(tc.in); got != tc.want {
				t.Errorf("publicOriginHost(%q) = %q，期望 %q", tc.in, got, tc.want)
			}
		})
	}
}

// H10 isLoopbackHost 纯函数表
func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"localhost", true},
		{"LOCALHOST", true},
		{"127.0.0.1", true},
		{"127.1.2.3", true},
		{"::1", true},
		{"0.0.0.0", true},
		{"example.com", false},
		{"10.0.0.1", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := isLoopbackHost(tc.in); got != tc.want {
				t.Errorf("isLoopbackHost(%q) = %v，期望 %v", tc.in, got, tc.want)
			}
		})
	}
}

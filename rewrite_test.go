package main

// 响应重写测试（TDD 第一批 · 步骤3/4，C1-C9 + L1-L8，IMPLEMENTATION-PLAN.md §1.1/§1.2）。
//
// 仿 D10 的真 TCP 集成模式：上游 httptest 服务发目标响应头，经完整
// 代理链（handleAll + sharedProxy.ModifyResponse）后断言客户端看到的头。

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// cookieSrv 起一个上游（按 cookies 发 Set-Cookie）+ 路由 /app/ 的代理链。
// mode 控制路由转发模式。返回代理基址。
func cookieSrv(t *testing.T, cookies []string, mode Mode) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, c := range cookies {
			w.Header().Add("Set-Cookie", c)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.Close)
	host, port := hostPort(t, up.URL)

	tb := NewRouteTable()
	tb.SetStatic([]*Route{{Prefix: "/app/", Host: host, Port: port, Mode: mode, Name: "app"}})
	t.Cleanup(swapTable(tb))

	srv := httptest.NewServer(recoverMiddleware(loggingMiddleware(http.HandlerFunc(handleAll))))
	t.Cleanup(srv.Close)
	return srv
}

// C1-C4/C6-C8 单 cookie 重写表
func TestRewriteSetCookie_Path(t *testing.T) {
	cases := []struct {
		name string
		in   string
		mode Mode
		want string
	}{
		{"C1 根路径加前缀", "s=1; Path=/; HttpOnly", ModeStrip, "s=1; Path=/app/; HttpOnly"},
		{"C2 子路径加前缀", "s=1; Path=/login", ModeStrip, "s=1; Path=/app/login"},
		{"C3 已含前缀不动", "s=1; Path=/app/x", ModeStrip, "s=1; Path=/app/x"},
		{"C4 无 Path 追加", "s=1; HttpOnly", ModeStrip, "s=1; HttpOnly; Path=/app/"},
		{"C6 小写 path= 识别", "s=1; path=/login", ModeStrip, "s=1; Path=/app/login"},
		{"C7 其它属性原样", "s=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; SameSite=Lax", ModeStrip,
			"s=1; Expires=Wed, 21 Oct 2026 07:28:00 GMT; SameSite=Lax; Path=/app/"},
		{"C8 ModeKeep 完全不变", "s=1; Path=/login", ModeKeep, "s=1; Path=/login"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := cookieSrv(t, []string{tc.in}, tc.mode)
			resp, err := http.Get(srv.URL + "/app/x")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			got := resp.Header["Set-Cookie"]
			if len(got) != 1 || got[0] != tc.want {
				t.Errorf("Set-Cookie = %q，期望 %q", got, tc.want)
			}
		})
	}
}

// C5 多个 Set-Cookie 逐条重写
func TestRewriteSetCookie_Multiple(t *testing.T) {
	srv := cookieSrv(t, []string{"a=1; Path=/", "b=2; Path=/x/y", "c=3"}, ModeStrip)
	resp, err := http.Get(srv.URL + "/app/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	want := []string{"a=1; Path=/app/", "b=2; Path=/app/x/y", "c=3; Path=/app/"}
	got := resp.Header["Set-Cookie"]
	if len(got) != len(want) {
		t.Fatalf("Set-Cookie 数量=%d（%q），期望 %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("第 %d 条 = %q，期望 %q", i, got[i], want[i])
		}
	}
}

// C9 无 cookie 响应无副作用
func TestRewriteSetCookie_None(t *testing.T) {
	srv := cookieSrv(t, nil, ModeStrip)
	resp, err := http.Get(srv.URL + "/app/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d，期望 200", resp.StatusCode)
	}
	if len(resp.Header["Set-Cookie"]) != 0 {
		t.Errorf("无 cookie 响应被写入了 Set-Cookie：%q", resp.Header["Set-Cookie"])
	}
}

// hostPort 从 http://127.0.0.1:PORT 提取 host 与 port。
func hostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	_, rest, ok := strings.Cut(rawURL, "http://")
	if !ok {
		t.Fatalf("非 http URL: %s", rawURL)
	}
	h, p, ok := strings.Cut(rest, ":")
	if !ok {
		t.Fatalf("URL 无端口: %s", rawURL)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("端口解析失败 %q: %v", p, err)
	}
	return h, port
}

// ---------------------------------------------------------------------------
// Location 重定向重写（L1-L8）
// ---------------------------------------------------------------------------

// locSrv 起上游（按 status/location 响应）+ 路由 /app/ 的代理链。
func locSrv(t *testing.T, status int, location string, mode Mode) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if location != "" {
			w.Header().Set("Location", location)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(up.Close)
	host, port := hostPort(t, up.URL)

	tb := NewRouteTable()
	tb.SetStatic([]*Route{{Prefix: "/app/", Host: host, Port: port, Mode: mode, Name: "app"}})
	t.Cleanup(swapTable(tb))

	srv := httptest.NewServer(recoverMiddleware(loggingMiddleware(http.HandlerFunc(handleAll))))
	t.Cleanup(srv.Close)
	return srv
}

// getNoRedirect 发 GET 但不跟随重定向（否则 302 会被客户端吞掉）。
func getNoRedirect(t *testing.T, u string) *http.Response {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestRewriteLocation(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		location string
		mode     Mode
		reqPath  string
		want     string
	}{
		{"L1 相对根路径", 302, "/login", ModeStrip, "/app/x", "/app/login"},
		{"L2 相对 ../x 基于上游视角解析", 302, "../x", ModeStrip, "/app/dir/page", "/app/x"},
		{"L4 外部绝对 URL 不动", 302, "https://example.com/x", ModeStrip, "/app/x", "https://example.com/x"},
		{"L5 已含前缀不动", 302, "/app/y", ModeStrip, "/app/x", "/app/y"},
		{"L6 ModeKeep 不动", 302, "/login", ModeKeep, "/app/x", "/login"},
		{"L7 201 Created 同样重写", 201, "/created", ModeStrip, "/app/x", "/app/created"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := locSrv(t, tc.status, tc.location, tc.mode)
			resp := getNoRedirect(t, srv.URL+tc.reqPath)
			if got := resp.Header.Get("Location"); got != tc.want {
				t.Errorf("Location = %q，期望 %q", got, tc.want)
			}
		})
	}
}

// L8 畸形 Location：裸 TCP 验证（Go http.Client 对 3xx 总是先解析 Location，
// 畸形值会在客户端侧报错，测不到服务端行为）。
func TestRewriteLocation_Malformed(t *testing.T) {
	srv := locSrv(t, 302, "http://[::1", ModeStrip)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET /app/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	raw, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	head := string(raw)
	if !strings.Contains(head, "HTTP/1.1 302") {
		t.Errorf("状态行异常：%q", head)
	}
	if !strings.Contains(head, "Location: http://[::1") {
		t.Errorf("畸形 Location 被改写或吞掉：%q", head)
	}
}

// L3 指回上游自己的绝对 URL：相对化并前插前缀（绝不把浏览器导向 127.0.0.1）
func TestRewriteLocation_PointsToUpstream(t *testing.T) {
	var up *httptest.Server
	up = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", up.URL+"/login")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(up.Close)
	host, port := hostPort(t, up.URL)

	tb := NewRouteTable()
	tb.SetStatic([]*Route{{Prefix: "/app/", Host: host, Port: port, Mode: ModeStrip, Name: "app"}})
	t.Cleanup(swapTable(tb))

	srv := httptest.NewServer(recoverMiddleware(loggingMiddleware(http.HandlerFunc(handleAll))))
	t.Cleanup(srv.Close)

	resp := getNoRedirect(t, srv.URL+"/app/x")
	if got := resp.Header.Get("Location"); got != "/app/login" {
		t.Errorf("Location = %q，期望 %q（应相对化并前插前缀）", got, "/app/login")
	}
}

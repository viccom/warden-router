package main

// auth_bridge 测试（2026-10-15）。
//
// 仿 rewrite_test.go 的真 TCP 集成模式：上游 httptest 服务发登录/业务
// 响应，经完整代理链（handleAll + sharedProxy）后断言：
//   - 客户端看到的 Set-Cookie（响应侧种 cookie）
//   - 上游收到的 Authorization 头（请求侧恢复）

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// authBridgeUpstream 起一个记录请求头、按 path 发响应的上游。
// 返回 (host, port, close)。
func authBridgeUpstream(t *testing.T, h http.HandlerFunc) (string, int, func()) {
	t.Helper()
	up := httptest.NewServer(h)
	t.Cleanup(up.Close)
	host, port := hostPort(t, up.URL)
	return host, port, up.Close
}

// ---------------------------------------------------------------------------
// extractToken 纯函数表
// ---------------------------------------------------------------------------

func TestExtractToken(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
		ok   bool
	}{
		{"vnts2/openlist 实际结构", `{"code":200,"msg":"success","data":{"token":"abc.def.ghi"}}`, "abc.def.ghi", true},
		{"顶层 token", `{"code":200,"token":"t0p"}`, "t0p", true},
		{"data.token 优先于顶层", `{"token":"top","data":{"token":"inner"}}`, "inner", true},
		{"业务响应无 token", `{"code":200,"data":{"name":"x","content":[]}}`, "", false},
		{"data 非对象", `{"data":"oops","token":""}`, "", false},
		{"token 为空串", `{"data":{"token":""}}`, "", false},
		{"token 非字符串", `{"data":{"token":123}}`, "", false},
		{"非 JSON", `<html>login</html>`, "", false},
		{"空 body", ``, "", false},
		{"JSON 数组", `[1,2,3]`, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := extractToken([]byte(tc.body))
			if ok != tc.ok || got != tc.want {
				t.Errorf("extractToken(%s) = (%q,%v)，期望 (%q,%v)", tc.body, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 集成：登录种 cookie + 请求恢复 Authorization
// ---------------------------------------------------------------------------

// bridgeChain 组装完整链路：上游（可编程响应）+ 代理（带 AuthBridge）。
// 返回 (代理基址, 上游收到的 Authorization 指针)。
func bridgeChain(t *testing.T, prefix string, ab *AuthBridge, up http.HandlerFunc) (*httptest.Server, *string) {
	t.Helper()
	var seenAuth string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		up(w, r)
	})
	upHost, upPort, closeUp := authBridgeUpstream(t, handler)

	tb := NewRouteTable()
	tb.SetStatic([]*Route{{
		Prefix: prefix, Host: upHost, Port: upPort, Mode: ModeKeep,
		Name: "app", AuthBridge: ab,
	}})
	t.Cleanup(swapTable(tb))

	srv := httptest.NewServer(recoverMiddleware(loggingMiddleware(http.HandlerFunc(handleAll))))
	t.Cleanup(srv.Close)
	_ = closeUp
	return srv, &seenAuth
}

// B1 登录响应种 cookie：Path 限定在路由前缀内，HttpOnly+SameSite=Lax+Max-Age
func TestAuthBridge_LoginSetsCookie(t *testing.T) {
	up := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":200,"data":{"token":"jwt.xxx.yyy"}}`)
	}
	srv, _ := bridgeChain(t, "/api/", &AuthBridge{Scheme: "Bearer"}, up)

	resp, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(`{"username":"a"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "jwt.xxx.yyy") {
		t.Fatalf("响应体被破坏：%s", body)
	}
	cookies := resp.Header["Set-Cookie"]
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie = %v，期望 1 条", cookies)
	}
	c := cookies[0]
	for _, want := range []string{"_wrauth=jwt.xxx.yyy", "Path=/api/", "HttpOnly", "SameSite=Lax", "Max-Age=86400"} {
		if !strings.Contains(c, want) {
			t.Errorf("cookie %q 缺少 %q", c, want)
		}
	}
}

// B2 请求侧恢复：无 Authorization + 带 cookie → 上游看到 Bearer 头
func TestAuthBridge_RestoresHeader(t *testing.T) {
	up := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":200,"data":{"networks":[]}}`)
	}
	srv, seen := bridgeChain(t, "/api/", &AuthBridge{Scheme: "Bearer"}, up)

	req, _ := http.NewRequest("GET", srv.URL+"/api/networks", nil)
	req.Header.Set("Cookie", "_wrauth=jwt.xxx.yyy")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if *seen != "Bearer jwt.xxx.yyy" {
		t.Errorf("上游收到 Authorization = %q，期望 %q", *seen, "Bearer jwt.xxx.yyy")
	}
}

// B3 scheme 为空（OpenList）：上游看到原样 token
func TestAuthBridge_RawScheme(t *testing.T) {
	up := func(w http.ResponseWriter, r *http.Request) {}
	srv, seen := bridgeChain(t, "/openlist/", &AuthBridge{Scheme: ""}, up)

	req, _ := http.NewRequest("GET", srv.URL+"/openlist/api/me", nil)
	req.Header.Set("Cookie", "_wrauth=raw-token-123")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if *seen != "raw-token-123" {
		t.Errorf("上游收到 Authorization = %q，期望原样 %q", *seen, "raw-token-123")
	}
}

// B4 cookie 覆盖 Authorization 头：CloudStudio 网关会往每个转发请求
// 注入平台 JWT（iss=cloudstudio.net），"有头就跳过"会把假 token 放行
// 给上游导致 401。桥接 cookie 必须赢。
func TestAuthBridge_CookieOverridesHeader(t *testing.T) {
	up := func(w http.ResponseWriter, r *http.Request) {}
	srv, seen := bridgeChain(t, "/api/", &AuthBridge{Scheme: "Bearer"}, up)

	req, _ := http.NewRequest("GET", srv.URL+"/api/networks", nil)
	req.Header.Set("Authorization", "Bearer gateway-injected-fake-jwt")
	req.Header.Set("Cookie", "_wrauth=jwt.xxx.yyy")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if *seen != "Bearer jwt.xxx.yyy" {
		t.Errorf("上游收到 Authorization = %q，期望 cookie 值 %q（覆盖网关注入的假 token）", *seen, "Bearer jwt.xxx.yyy")
	}
}

// B5 未配置 AuthBridge：不种 cookie、不恢复头
func TestAuthBridge_Disabled(t *testing.T) {
	up := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":200,"data":{"token":"should-not-bridge"}}`)
	}
	srv, seen := bridgeChain(t, "/api/", nil, up)

	resp, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(resp.Header["Set-Cookie"]) != 0 {
		t.Errorf("未配置却种了 cookie：%v", resp.Header["Set-Cookie"])
	}

	req, _ := http.NewRequest("GET", srv.URL+"/api/networks", nil)
	req.Header.Set("Cookie", "_wrauth=abc")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if *seen != "" {
		t.Errorf("未配置却恢复了 Authorization：%q", *seen)
	}
}

// B6 业务响应（POST 但 body 无 token 字段）不种 cookie
func TestAuthBridge_NonLoginNoCookie(t *testing.T) {
	up := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":200,"data":{"name":"net1","id":1}}`)
	}
	srv, _ := bridgeChain(t, "/api/", &AuthBridge{Scheme: "Bearer"}, up)

	resp, err := http.Post(srv.URL+"/api/networks", "application/json", strings.NewReader(`{"name":"net1"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(resp.Header["Set-Cookie"]) != 0 {
		t.Errorf("业务响应被种了 cookie：%v", resp.Header["Set-Cookie"])
	}
}

// B7 GET 即使带 token 也不种（登录都是 POST，收紧触发面）
func TestAuthBridge_GetNoCookie(t *testing.T) {
	up := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"token":"x"}}`)
	}
	srv, _ := bridgeChain(t, "/api/", &AuthBridge{Scheme: "Bearer"}, up)

	resp, err := http.Get(srv.URL + "/api/token")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(resp.Header["Set-Cookie"]) != 0 {
		t.Errorf("GET 被种了 cookie：%v", resp.Header["Set-Cookie"])
	}
}

// B8 非 JSON 登录响应不种
func TestAuthBridge_NonJSONNoCookie(t *testing.T) {
	up := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<html>ok</html>`)
	}
	srv, _ := bridgeChain(t, "/api/", &AuthBridge{Scheme: "Bearer"}, up)

	resp, err := http.Post(srv.URL+"/api/login", "text/html", strings.NewReader(`x`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(resp.Header["Set-Cookie"]) != 0 {
		t.Errorf("非 JSON 被种了 cookie：%v", resp.Header["Set-Cookie"])
	}
}

// B9 登录失败（非 200）不种
func TestAuthBridge_FailedLoginNoCookie(t *testing.T) {
	up := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"code":401,"data":{"token":""}}`)
	}
	srv, _ := bridgeChain(t, "/api/", &AuthBridge{Scheme: "Bearer"}, up)

	resp, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(resp.Header["Set-Cookie"]) != 0 {
		t.Errorf("401 登录被种了 cookie：%v", resp.Header["Set-Cookie"])
	}
}

// B10 chunked 登录响应（无 Content-Length）也能桥接且响应体完整
func TestAuthBridge_ChunkedLogin(t *testing.T) {
	up := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // 无 Content-Length → chunked
		_, _ = io.WriteString(w, `{"code":200,"data":{"token":"chunked.tok"}}`)
	}
	srv, _ := bridgeChain(t, "/api/", &AuthBridge{Scheme: "Bearer"}, up)

	resp, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "chunked.tok") {
		t.Fatalf("chunked 响应体被破坏：%q", body)
	}
	c := resp.Header.Get("Set-Cookie")
	if !strings.Contains(c, "_wrauth=chunked.tok") {
		t.Errorf("chunked 登录未种 cookie：%q", c)
	}
}

// B11 scheme 校验（路由校验器复用）
func TestValidAuthBridgeScheme(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", true},
		{"Bearer", true},
		{"bearer", true},
		{"Basic", true},
		{"Two Words", false},   // 空格破坏头结构
		{"Bad\nHeader", false}, // CRLF 头注入
		{"中文", false},          // 非 ASCII
	}
	for _, tc := range cases {
		if got := validAuthBridgeScheme(tc.in); got != tc.want {
			t.Errorf("validAuthBridgeScheme(%q) = %v，期望 %v", tc.in, got, tc.want)
		}
	}
}

// B12 cookie 名校验
func TestValidAuthBridgeCookieName(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", true},
		{"_wrauth", true},
		{"_wrauth-api", true},
		{"a;b", false},  // 分号截断 Set-Cookie
		{"a=b", false},  // 等号歧义
		{"a b", false},  // 空格
		{"a,b", false},  // 逗号
		{"a\"b", false}, // 引号
	}
	for _, tc := range cases {
		if got := validAuthBridgeCookieName(tc.in); got != tc.want {
			t.Errorf("validAuthBridgeCookieName(%q) = %v，期望 %v", tc.in, got, tc.want)
		}
	}
}

// B13 自定义 cookie 名：登录种的是配置名，请求也只认配置名
func TestAuthBridge_CustomCookieName(t *testing.T) {
	up := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":200,"data":{"token":"tok.custom"}}`)
	}
	srv, seen := bridgeChain(t, "/api/", &AuthBridge{Scheme: "Bearer", CookieName: "_wrauth-api"}, up)

	resp, err := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if c := resp.Header.Get("Set-Cookie"); !strings.Contains(c, "_wrauth-api=tok.custom") {
		t.Fatalf("应种配置的 cookie 名：%q", c)
	}

	// 默认名的 cookie 不被识别（隔离性）
	req, _ := http.NewRequest("GET", srv.URL+"/api/networks", nil)
	req.Header.Set("Cookie", "_wrauth=tok.default")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if *seen != "" {
		t.Errorf("默认名 cookie 不应被恢复：%q", *seen)
	}

	// 配置名恢复
	req2, _ := http.NewRequest("GET", srv.URL+"/api/networks", nil)
	req2.Header.Set("Cookie", "_wrauth-api=tok.custom")
	resp3, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if *seen != "Bearer tok.custom" {
		t.Errorf("配置名应恢复：%q", *seen)
	}
}

// B14 双路由不同 cookie 名共存：网关把两条 Set-Cookie 的 Path 都改成
// "/" 后，同名 cookie 会互相覆盖——不同名则各自登录态互不干扰
// （用户同时开 vnts-admin 与 openlist 两个标签页的场景）。
func TestAuthBridge_TwoRoutesIsolation(t *testing.T) {
	var seenA, seenB string
	upA := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenA = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":200,"data":{"token":"token-A"}}`)
	})
	upB := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenB = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":200,"data":{"token":"token-B"}}`)
	})
	hostA, portA, _ := authBridgeUpstream(t, upA)
	hostB, portB, _ := authBridgeUpstream(t, upB)

	tb := NewRouteTable()
	tb.SetStatic([]*Route{
		{Prefix: "/api/", Host: hostA, Port: portA, Mode: ModeKeep, Name: "a",
			AuthBridge: &AuthBridge{Scheme: "Bearer", CookieName: "_wrauth-a"}},
		{Prefix: "/openlist/", Host: hostB, Port: portB, Mode: ModeKeep, Name: "b",
			AuthBridge: &AuthBridge{Scheme: "", CookieName: "_wrauth-b"}},
	})
	t.Cleanup(swapTable(tb))
	srv := httptest.NewServer(recoverMiddleware(loggingMiddleware(http.HandlerFunc(handleAll))))
	t.Cleanup(srv.Close)

	// 两个服务各登录一次，拿到两条 cookie（模拟网关把 Path 都改成 /）
	respA, _ := http.Post(srv.URL+"/api/login", "application/json", strings.NewReader(`{}`))
	respA.Body.Close()
	respB, _ := http.Post(srv.URL+"/openlist/api/auth/login", "application/json", strings.NewReader(`{}`))
	respB.Body.Close()
	cookieA := respA.Header.Get("Set-Cookie")
	cookieB := respB.Header.Get("Set-Cookie")
	if !strings.HasPrefix(cookieA, "_wrauth-a=") || !strings.HasPrefix(cookieB, "_wrauth-b=") {
		t.Fatalf("两条 cookie 名应不同：A=%q B=%q", cookieA, cookieB)
	}
	nameVal := func(c string) string {
		return strings.SplitN(strings.SplitN(c, ";", 2)[0], "=", 2)[1]
	}
	both := "_wrauth-a=" + nameVal(cookieA) + "; _wrauth-b=" + nameVal(cookieB)

	// 同时带两条 cookie 访问两个服务：各自恢复各自的 token
	reqA, _ := http.NewRequest("GET", srv.URL+"/api/networks", nil)
	reqA.Header.Set("Cookie", both)
	respA2, _ := http.DefaultClient.Do(reqA)
	respA2.Body.Close()
	reqB, _ := http.NewRequest("GET", srv.URL+"/openlist/api/me", nil)
	reqB.Header.Set("Cookie", both)
	respB2, _ := http.DefaultClient.Do(reqB)
	respB2.Body.Close()

	if seenA != "Bearer token-A" {
		t.Errorf("A 应恢复自己的 token，得到 %q", seenA)
	}
	if seenB != "token-B" {
		t.Errorf("B 应恢复自己的裸 token，得到 %q", seenB)
	}
}

package main

// auth_bridge 静态注入模式测试（2026-10-16，warden 管理台公网 401 修复）。
//
// 背景：warden 无登录 API（token 是静态预共享密钥，UI 只发
// Authorization: Bearer 头），登录流桥接（种 cookie=token 值）用不上。
// 静态模式：门控路径换 cookie（值是 HMAC 标记），请求侧带有效 cookie 时
// 用配置的静态 token 覆盖 Authorization 头（覆盖而非跳过——公网链路
// 到达的已是平台 JWT，见 restoreAuthHeader 注释）。
//
// 仿 authbridge_test.go 的真 TCP 集成模式：完整代理链 + 可编程上游。

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// staticGateAB 静态模式配置（warden 生产形态）。
func staticGateAB() *AuthBridge {
	return &AuthBridge{
		Token:    "warden-static-token",
		Scheme:   "Bearer",
		GatePath: "/warden/.gate",
		GateKey:  "0123456789abcdef",
	}
}

// platformJWT 模拟 CloudStudio 发布网关注入的平台 JWT（386 字符形态，
// 值与真实 JWT 无关，只表征"客户端真 token 已被替换"）。
const platformJWT = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJjbG91ZHN0dWRpby5uZXQifQ.sig"

// noRedirectClient 不跟随重定向的客户端（门控断言需要看 302 本身，
// http.Get 默认跟随会拿到最终 200）。
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// gateChain 组装静态模式完整链路。返回 (代理基址, 上游收到的 Authorization
// 指针, 上游命中计数指针)。
func gateChain(t *testing.T, ab *AuthBridge, up http.HandlerFunc) (*httptest.Server, *string, *int) {
	t.Helper()
	var seenAuth string
	var hits int
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		seenAuth = r.Header.Get("Authorization")
		up(w, r)
	})
	upHost, upPort, _ := authBridgeUpstream(t, handler)

	tb := NewRouteTable()
	tb.SetStatic([]*Route{{
		Prefix: "/warden/", Host: upHost, Port: upPort, Mode: ModeKeep,
		Name: "warden", AuthBridge: ab,
	}})
	t.Cleanup(swapTable(tb))

	srv := httptest.NewServer(recoverMiddleware(loggingMiddleware(http.HandlerFunc(handleAll))))
	t.Cleanup(srv.Close)
	return srv, &seenAuth, &hits
}

// okJSON 上游默认响应：200 JSON（warden API 形态）。
func okJSON(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"services":[]}`)
}

// ---------------------------------------------------------------------------
// 门控：换 cookie
// ---------------------------------------------------------------------------

// G1 正确密钥 → 302 回前缀 + 种门控 cookie；上游不被命中
func TestStaticGate_CorrectKeySetsCookie(t *testing.T) {
	srv, _, hits := gateChain(t, staticGateAB(), okJSON)

	resp, err := noRedirectClient().Get(srv.URL + "/warden/.gate?k=0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("状态码 = %d，期望 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/warden/" {
		t.Errorf("Location = %q，期望 /warden/", loc)
	}
	cookies := resp.Header["Set-Cookie"]
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie = %v，期望 1 条", cookies)
	}
	c := cookies[0]
	want := gateCookieValue(staticGateAB())
	for _, part := range []string{
		"_wrauth-gate=" + want, "Path=/warden/", "HttpOnly", "SameSite=Lax", "Max-Age=86400",
	} {
		if !strings.Contains(c, part) {
			t.Errorf("cookie %q 缺少 %q", c, part)
		}
	}
	if *hits != 0 {
		t.Errorf("上游被命中 %d 次，门控请求不应转发", *hits)
	}
}

// G2 错误密钥 → 403，不种 cookie，上游不被命中
func TestStaticGate_WrongKeyForbidden(t *testing.T) {
	srv, _, hits := gateChain(t, staticGateAB(), okJSON)

	resp, err := noRedirectClient().Get(srv.URL + "/warden/.gate?k=wrongkey-wrongkey")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("状态码 = %d，期望 403", resp.StatusCode)
	}
	if c := resp.Header["Set-Cookie"]; len(c) != 0 {
		t.Errorf("不应种 cookie，得到 %v", c)
	}
	if *hits != 0 {
		t.Errorf("上游被命中 %d 次，403 不应转发", *hits)
	}
}

// G3 缺密钥 → 403
func TestStaticGate_MissingKeyForbidden(t *testing.T) {
	srv, _, hits := gateChain(t, staticGateAB(), okJSON)

	resp, err := noRedirectClient().Get(srv.URL + "/warden/.gate")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("状态码 = %d，期望 403", resp.StatusCode)
	}
	if *hits != 0 {
		t.Errorf("上游被命中 %d 次，403 不应转发", *hits)
	}
}

// G4 非门控路径正常转发（不带 cookie 不注入）
func TestStaticGate_NonGatePathProxied(t *testing.T) {
	srv, _, hits := gateChain(t, staticGateAB(), okJSON)

	resp, err := http.Get(srv.URL + "/warden/api/v1/services")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200", resp.StatusCode)
	}
	if *hits != 1 {
		t.Errorf("上游命中 %d 次，期望 1", *hits)
	}
}

// G5 重定向保留 sharecode 等其余查询参数（只剥 k）
func TestStaticGate_RedirectPreservesQuery(t *testing.T) {
	srv, _, _ := gateChain(t, staticGateAB(), okJSON)

	resp, err := noRedirectClient().Get(srv.URL + "/warden/.gate?k=0123456789abcdef&sharecode=zzz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "/warden/?sharecode=zzz" {
		t.Errorf("Location = %q，期望 /warden/?sharecode=zzz", loc)
	}
}

// G6 非 GET/HEAD 方法 → 405（门控只服务浏览器导航）
func TestStaticGate_MethodNotAllowed(t *testing.T) {
	srv, _, hits := gateChain(t, staticGateAB(), okJSON)

	resp, err := http.Post(srv.URL+"/warden/.gate?k=0123456789abcdef", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("状态码 = %d，期望 405", resp.StatusCode)
	}
	if *hits != 0 {
		t.Errorf("上游被命中 %d 次，405 不应转发", *hits)
	}
}

// ---------------------------------------------------------------------------
// 请求侧：带有效门控 cookie → 注入静态 token
// ---------------------------------------------------------------------------

// S1 平台 JWT + 有效 cookie → 上游看到配置的 Bearer token（覆盖）
func TestStaticInject_PlatformJWTReplaced(t *testing.T) {
	srv, seen, _ := gateChain(t, staticGateAB(), okJSON)

	req, _ := http.NewRequest("GET", srv.URL+"/warden/api/v1/services", nil)
	req.Header.Set("Authorization", platformJWT) // 网关替换后的假 token
	req.Header.Set("Cookie", "_wrauth-gate="+gateCookieValue(staticGateAB()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := *seen; got != "Bearer warden-static-token" {
		t.Errorf("上游收到 Authorization = %q，期望 %q", got, "Bearer warden-static-token")
	}
}

// S2 无 cookie → 原样透传（平台 JWT 到达上游，warden 判 401——router 不添乱）
func TestStaticInject_NoCookiePassthrough(t *testing.T) {
	srv, seen, _ := gateChain(t, staticGateAB(), okJSON)

	req, _ := http.NewRequest("GET", srv.URL+"/warden/api/v1/services", nil)
	req.Header.Set("Authorization", platformJWT)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := *seen; got != platformJWT {
		t.Errorf("上游收到 Authorization = %q，期望原样 %q", got, platformJWT)
	}
}

// S3 伪造 cookie 值 → 不注入（HMAC 校验失败）
func TestStaticInject_ForgedCookieRejected(t *testing.T) {
	srv, seen, _ := gateChain(t, staticGateAB(), okJSON)

	req, _ := http.NewRequest("GET", srv.URL+"/warden/api/v1/services", nil)
	req.Header.Set("Authorization", platformJWT)
	req.Header.Set("Cookie", "_wrauth-gate=forged-or-guessed")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := *seen; got != platformJWT {
		t.Errorf("上游收到 Authorization = %q，期望原样 %q（伪造 cookie 不得注入）", got, platformJWT)
	}
}

// S4 空 cookie 值 → 不注入
func TestStaticInject_EmptyCookieRejected(t *testing.T) {
	srv, seen, _ := gateChain(t, staticGateAB(), okJSON)

	req, _ := http.NewRequest("GET", srv.URL+"/warden/api/v1/services", nil)
	req.Header.Set("Authorization", platformJWT)
	req.Header.Set("Cookie", "_wrauth-gate=")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := *seen; got != platformJWT {
		t.Errorf("上游收到 Authorization = %q，期望原样 %q", got, platformJWT)
	}
}

// S5 Scheme 为空 → 原样 token（无 Bearer 前缀）
func TestStaticInject_RawScheme(t *testing.T) {
	ab := staticGateAB()
	ab.Scheme = ""
	srv, seen, _ := gateChain(t, ab, okJSON)

	req, _ := http.NewRequest("GET", srv.URL+"/warden/api/v1/services", nil)
	req.Header.Set("Authorization", platformJWT)
	req.Header.Set("Cookie", "_wrauth-gate="+gateCookieValue(ab))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := *seen; got != "warden-static-token" {
		t.Errorf("上游收到 Authorization = %q，期望原样 token", got)
	}
}

// S6 无 Authorization + 有效 cookie → 也注入（本地无网关场景同样可用）
func TestStaticInject_NoHeaderAlsoInjected(t *testing.T) {
	srv, seen, _ := gateChain(t, staticGateAB(), okJSON)

	req, _ := http.NewRequest("GET", srv.URL+"/warden/api/v1/services", nil)
	req.Header.Set("Cookie", "_wrauth-gate="+gateCookieValue(staticGateAB()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := *seen; got != "Bearer warden-static-token" {
		t.Errorf("上游收到 Authorization = %q，期望 %q", got, "Bearer warden-static-token")
	}
}

// S7 自定义 cookie 名（auth_bridge_cookie）参与 HMAC 绑定
func TestStaticInject_CustomCookieName(t *testing.T) {
	ab := staticGateAB()
	ab.CookieName = "_wrauth-warden"
	srv, seen, _ := gateChain(t, ab, okJSON)

	req, _ := http.NewRequest("GET", srv.URL+"/warden/api/v1/services", nil)
	req.Header.Set("Authorization", platformJWT)
	req.Header.Set("Cookie", "_wrauth-warden="+gateCookieValue(ab))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := *seen; got != "Bearer warden-static-token" {
		t.Errorf("上游收到 Authorization = %q，期望 %q", got, "Bearer warden-static-token")
	}
}

// S8 静态模式下响应侧不种登录 cookie（warden 的 POST API 也可能返回
// 含 token 字段的 JSON，不能被误当登录响应桥接）
func TestStaticMode_NoLoginCookieSideEffect(t *testing.T) {
	up := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"code":200,"data":{"token":"should-not-bridge"}}`)
	}
	srv, _, _ := gateChain(t, staticGateAB(), up)

	resp, err := http.Post(srv.URL+"/warden/api/v1/services/x/restart", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if c := resp.Header["Set-Cookie"]; len(c) != 0 {
		t.Errorf("静态模式不应种登录 cookie，得到 %v", c)
	}
}

// S9 登录流模式不受静态分支影响（回归：cookie 值即 token）
func TestStaticMode_LoginFlowStillWorks(t *testing.T) {
	up := func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"code":200,"data":{"token":"jwt.xxx.yyy"}}`)
			return
		}
		okJSON(w, r)
	}
	srv, seen, _ := gateChain(t, &AuthBridge{Scheme: "Bearer"}, up)

	// 登录种 cookie
	resp, err := http.Post(srv.URL+"/warden/api/login", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// 带 cookie 请求 → 上游看到登录得到的 token
	req, _ := http.NewRequest("GET", srv.URL+"/warden/api/v1/services", nil)
	req.Header.Set("Cookie", "_wrauth=jwt.xxx.yyy")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if got := *seen; got != "Bearer jwt.xxx.yyy" {
		t.Errorf("上游收到 Authorization = %q，期望 %q", got, "Bearer jwt.xxx.yyy")
	}
}

// ---------------------------------------------------------------------------
// gateCookieValue 纯函数
// ---------------------------------------------------------------------------

func TestGateCookieValue(t *testing.T) {
	ab := staticGateAB()
	v1 := gateCookieValue(ab)
	if len(v1) != 32 {
		t.Errorf("cookie 值长度 = %d，期望 32（hex 截断）", len(v1))
	}
	if v1 != gateCookieValue(staticGateAB()) {
		t.Errorf("同配置应得同值（无状态验证）")
	}
	// 换 gate_key → 变
	ab2 := staticGateAB()
	ab2.GateKey = "fedcba9876543210"
	if gateCookieValue(ab2) == v1 {
		t.Errorf("不同 gate_key 应得不同 cookie 值")
	}
	// 换 cookie 名 → 变（HMAC 绑定 cookie 名，防跨路由 cookie  tossing）
	ab3 := staticGateAB()
	ab3.CookieName = "_wrauth-warden"
	if gateCookieValue(ab3) == v1 {
		t.Errorf("不同 cookie 名应得不同 cookie 值")
	}
}

// ---------------------------------------------------------------------------
// 校验：静态三件套（token/gate/gate_key）语义
// ---------------------------------------------------------------------------

func TestValidAuthBridge_StaticTrio(t *testing.T) {
	cases := []struct {
		name string
		ab   *AuthBridge
		ok   bool
	}{
		{"完整三件套", &AuthBridge{Token: "tok", Scheme: "Bearer", GatePath: "/warden/.gate", GateKey: "0123456789abcdef"}, true},
		{"登录流模式（无静态字段）", &AuthBridge{Scheme: "Bearer"}, true},
		{"nil", nil, true},
		{"只有 token", &AuthBridge{Token: "tok"}, false},
		{"只有 gate", &AuthBridge{GatePath: "/warden/.gate"}, false},
		{"只有 gate_key", &AuthBridge{GateKey: "0123456789abcdef"}, false},
		{"缺 gate_key", &AuthBridge{Token: "tok", GatePath: "/warden/.gate"}, false},
		{"缺 gate", &AuthBridge{Token: "tok", GateKey: "0123456789abcdef"}, false},
		{"缺 token", &AuthBridge{GatePath: "/warden/.gate", GateKey: "0123456789abcdef"}, false},
		{"gate 不在前缀内", &AuthBridge{Token: "tok", GatePath: "/other/.gate", GateKey: "0123456789abcdef"}, false},
		{"gate 等于前缀", &AuthBridge{Token: "tok", GatePath: "/warden/", GateKey: "0123456789abcdef"}, false},
		{"gate 缺前导斜杠", &AuthBridge{Token: "tok", GatePath: "warden/.gate", GateKey: "0123456789abcdef"}, false},
		{"gate_key 太短", &AuthBridge{Token: "tok", GatePath: "/warden/.gate", GateKey: "short"}, false},
		{"gate_key 非法字符", &AuthBridge{Token: "tok", GatePath: "/warden/.gate", GateKey: "0123456789abcde!"}, false},
		{"gate_key 含空格", &AuthBridge{Token: "tok", GatePath: "/warden/.gate", GateKey: "0123456789abcde "}, false},
		{"token 含 CRLF（头注入）", &AuthBridge{Token: "tok\r\nX-Evil: 1", GatePath: "/warden/.gate", GateKey: "0123456789abcdef"}, false},
		{"token 含空格", &AuthBridge{Token: "to k", GatePath: "/warden/.gate", GateKey: "0123456789abcdef"}, false},
		{"token 为空串", &AuthBridge{Token: "", GatePath: "/warden/.gate", GateKey: "0123456789abcdef"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &Route{
				Prefix: "/warden/", Host: "127.0.0.1", Port: 8789, Mode: ModeKeep,
				AuthBridge: tc.ab,
			}
			if got := validRoute(r); got != tc.ok {
				t.Errorf("validRoute() = %v，期望 %v", got, tc.ok)
			}
		})
	}
}

// 静态字段与非静态字段混用不破坏登录流校验（回归表）
func TestValidAuthBridge_LoginFieldsUnaffected(t *testing.T) {
	r := &Route{
		Prefix: "/api/", Host: "127.0.0.1", Port: 8080, Mode: ModeKeep,
		AuthBridge: &AuthBridge{Scheme: "Bearer", CookieName: "_wrauth-api"},
	}
	if !validRoute(r) {
		t.Errorf("登录流配置应仍然合法")
	}
}

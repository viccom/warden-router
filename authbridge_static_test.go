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
	"net/url"
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
		"_wrauth-gate=" + want, "Path=/;", "HttpOnly", "SameSite=Lax", "Max-Age=86400",
	} {
		if !strings.Contains(c, part) {
			t.Errorf("cookie %q 缺少 %q", c, part)
		}
	}
	if *hits != 0 {
		t.Errorf("上游被命中 %d 次，门控请求不应转发", *hits)
	}
}

// G2 错误密钥 → 403 错误页（含重试输入框），不种 cookie，上游不被命中
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
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `name="k"`) {
		t.Errorf("403 错误页应含重试输入框，得到：%s", body)
	}
	if c := resp.Header["Set-Cookie"]; len(c) != 0 {
		t.Errorf("不应种 cookie，得到 %v", c)
	}
	if *hits != 0 {
		t.Errorf("上游被命中 %d 次，403 不应转发", *hits)
	}
}

// G3 无密钥 → 200 密钥输入页（全新浏览器的登录入口：粘贴 token 提交
// 即换 cookie；URL 不泄露信息，密钥经 GET form 提交）
func TestStaticGate_MissingKeyShowsPrompt(t *testing.T) {
	srv, _, hits := gateChain(t, staticGateAB(), okJSON)

	resp, err := noRedirectClient().Get(srv.URL + "/warden/.gate")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200（输入页）", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	for _, want := range []string{`action="/warden/.gate"`, `name="k"`, `type="password"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("输入页缺少 %q，得到：%s", want, body)
		}
	}
	if c := resp.Header["Set-Cookie"]; len(c) != 0 {
		t.Errorf("输入页不应种 cookie，得到 %v", c)
	}
	if *hits != 0 {
		t.Errorf("上游被命中 %d 次，输入页不应转发", *hits)
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

// G6 非 GET/HEAD/POST 方法 → 405（门控只服务导航/表单）
func TestStaticGate_MethodNotAllowed(t *testing.T) {
	srv, _, hits := gateChain(t, staticGateAB(), okJSON)

	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/warden/.gate?k=0123456789abcdef", nil)
	resp, err := noRedirectClient().Do(req)
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

// G7 免输：持有效门控 cookie 访问门控路径 → 直接 302 回前缀（不显示输入页）。
// 导航卡片恒定指向 GatePath，若每次都逼重输，24h 免输形同虚设（审查发现）。
func TestStaticGate_ValidCookieSkipsPrompt(t *testing.T) {
	srv, _, hits := gateChain(t, staticGateAB(), okJSON)

	req, _ := http.NewRequest("GET", srv.URL+"/warden/.gate", nil)
	req.Header.Set("Cookie", "_wrauth-gate="+gateCookieValue(staticGateAB()))
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("状态码 = %d，期望 302（免输直接回前缀）", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/warden/" {
		t.Errorf("Location = %q，期望 /warden/", loc)
	}
	if *hits != 0 {
		t.Errorf("上游被命中 %d 次，免输跳转不应转发", *hits)
	}
}

// G7b 伪造 cookie 不足以免输 → 仍显示输入页
func TestStaticGate_ForgedCookieStillPrompts(t *testing.T) {
	srv, _, _ := gateChain(t, staticGateAB(), okJSON)

	req, _ := http.NewRequest("GET", srv.URL+"/warden/.gate", nil)
	req.Header.Set("Cookie", "_wrauth-gate=forged-value")
	resp, err := noRedirectClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200（输入页）", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `name="k"`) {
		t.Errorf("伪造 cookie 应看到输入页，得到：%s", body)
	}
}

// G8 POST 表单提交（密钥不进 URL/浏览器历史/访问日志/Referer）：
// 正确密钥 → 303 See Other（POST→GET 语义）+ 种 cookie
func TestStaticGate_PostSubmitSetsCookie(t *testing.T) {
	srv, _, hits := gateChain(t, staticGateAB(), okJSON)

	resp, err := noRedirectClient().PostForm(srv.URL+"/warden/.gate",
		url.Values{"k": {"0123456789abcdef"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("状态码 = %d，期望 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "/warden/" {
		t.Errorf("Location = %q，期望 /warden/", loc)
	}
	cookies := resp.Header["Set-Cookie"]
	if len(cookies) != 1 || !strings.Contains(cookies[0], "_wrauth-gate="+gateCookieValue(staticGateAB())) {
		t.Errorf("应种门控 cookie，得到 %v", cookies)
	}
	if *hits != 0 {
		t.Errorf("上游被命中 %d 次，门控不应转发", *hits)
	}
}

// G8b POST 错密钥 → 403 + 重试输入框
func TestStaticGate_PostWrongKeyForbidden(t *testing.T) {
	srv, _, hits := gateChain(t, staticGateAB(), okJSON)

	resp, err := noRedirectClient().PostForm(srv.URL+"/warden/.gate",
		url.Values{"k": {"wrongkey-wrongkey"}})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("状态码 = %d，期望 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `name="k"`) {
		t.Errorf("403 错误页应含重试输入框，得到：%s", body)
	}
	if *hits != 0 {
		t.Errorf("上游被命中 %d 次，403 不应转发", *hits)
	}
}

// G9 门控输入页用 POST 提交（密钥不进 URL）
func TestStaticGate_PromptUsesPostForm(t *testing.T) {
	srv, _, _ := gateChain(t, staticGateAB(), okJSON)

	resp, err := noRedirectClient().Get(srv.URL + "/warden/.gate")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `method="post"`) {
		t.Errorf("输入页应用 POST 提交（避免密钥进 URL），得到：%s", body)
	}
}

// ---------------------------------------------------------------------------
// 消费型路由（token+key 无 gate）：只验 cookie 注入、不提供门控入口。
// 场景：warden UI 的 API 路由（/api/v1/）——换 cookie 的入口在 /warden/
// 一条即可，API 路由无需（也不该）再暴露一个门控路径（否则 302 落到
// API 根，体验错误）。
// ---------------------------------------------------------------------------

func TestStaticInject_ConsumerRouteWithoutGate(t *testing.T) {
	var seenAuth string
	up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		okJSON(w, r)
	})
	upHost, upPort, _ := authBridgeUpstream(t, up)

	issuer := staticGateAB() // /warden/：完整三件套（发 cookie）
	consumer := &AuthBridge{ // /api/v1/：仅消费（token+key，无 gate）
		Token: "warden-static-token", Scheme: "Bearer", GateKey: "0123456789abcdef",
	}
	if !validRoute(&Route{Prefix: "/api/v1/", Host: "127.0.0.1", Port: 8789, Mode: ModeKeep, AuthBridge: consumer}) {
		t.Fatal("消费型路由（token+key 无 gate）应通过校验")
	}

	tb := NewRouteTable()
	tb.SetStatic([]*Route{
		{Prefix: "/warden/", Host: upHost, Port: upPort, Mode: ModeKeep, Name: "warden", AuthBridge: issuer},
		{Prefix: "/api/v1/", Host: upHost, Port: upPort, Mode: ModeKeep, Name: "warden", AuthBridge: consumer},
	})
	t.Cleanup(swapTable(tb))

	srv := httptest.NewServer(recoverMiddleware(loggingMiddleware(http.HandlerFunc(handleAll))))
	t.Cleanup(srv.Close)

	// 消费型路由不再提供门控入口：请求其 gate 风格路径不会被拦截
	// （GatePath 为空 → 不匹配任何路径，正常转发）
	respGate, err := noRedirectClient().Get(srv.URL + "/api/v1/.gate")
	if err != nil {
		t.Fatal(err)
	}
	respGate.Body.Close()
	if respGate.StatusCode == http.StatusForbidden || respGate.StatusCode == http.StatusSeeOther {
		t.Errorf("消费型路由不应有门控入口，得到 %d", respGate.StatusCode)
	}

	// 用 /warden/ 门控种下的 cookie（同 key 同默认名 → 同 HMAC 值），
	// 请求 /api/v1/ → 注入生效
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/services", nil)
	req.Header.Set("Authorization", platformJWT)
	req.Header.Set("Cookie", "_wrauth-gate="+gateCookieValue(issuer))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := seenAuth; got != "Bearer warden-static-token" {
		t.Errorf("消费型路由收到 Authorization = %q，期望注入", got)
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
		{"只有 gate_key（无 token 可注入）", &AuthBridge{GateKey: "0123456789abcdef"}, false},
		{"gate+key 无 token", &AuthBridge{GatePath: "/warden/.gate", GateKey: "0123456789abcdef"}, false},
		{"缺 gate_key（token 无 key = 有伪造风险）", &AuthBridge{Token: "tok", GatePath: "/warden/.gate"}, false},
		{"缺 gate（消费型，合法）", &AuthBridge{Token: "tok", GateKey: "0123456789abcdef"}, true},
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

// S10 回归（2026-10-16 实测踩坑）：warden UI 是全内联单页，API 用根绝对
// 路径 /api/v1/...（与 UI 所在的 /warden/ 前缀是两条不同路由）。门控
// cookie 必须 Path=/ 且两条路由都配三件套，否则浏览器对 /api/v1/ 请求
// 不发 cookie、注入也不发生——症状是"cookie 种上了但 UI 仍 401"。
func TestStaticInject_APIRouteSharesTrio(t *testing.T) {
	var seenAuthAPI, seenAuthOther string
	var hitsAPI, hitsOther int
	up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			hitsAPI++
			seenAuthAPI = r.Header.Get("Authorization")
		} else {
			hitsOther++
			seenAuthOther = r.Header.Get("Authorization")
		}
		okJSON(w, r)
	})
	upHost, upPort, _ := authBridgeUpstream(t, up)

	ab := staticGateAB()
	tb := NewRouteTable()
	tb.SetStatic([]*Route{
		{Prefix: "/warden/", Host: upHost, Port: upPort, Mode: ModeKeep, Name: "warden", AuthBridge: ab},
		{Prefix: "/api/v1/", Host: upHost, Port: upPort, Mode: ModeKeep, Name: "warden", AuthBridge: ab},
		// 第三条路由不配三件套：同 cookie 不得被注入
		{Prefix: "/other/", Host: upHost, Port: upPort, Mode: ModeKeep, Name: "other"},
	})
	t.Cleanup(swapTable(tb))

	srv := httptest.NewServer(recoverMiddleware(loggingMiddleware(http.HandlerFunc(handleAll))))
	t.Cleanup(srv.Close)

	// 门控换 cookie（Path=/，浏览器后续对所有路径都会发）
	resp, err := noRedirectClient().Get(srv.URL + "/warden/.gate?k=0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("门控状态码 = %d，期望 302", resp.StatusCode)
	}
	var cookieVal string
	for _, c := range resp.Header["Set-Cookie"] {
		if strings.HasPrefix(c, "_wrauth-gate=") {
			cookieVal = strings.TrimPrefix(c, "_wrauth-gate=")
			if idx := strings.Index(cookieVal, ";"); idx >= 0 {
				cookieVal = cookieVal[:idx]
			}
		}
	}
	if cookieVal == "" {
		t.Fatal("未取到门控 cookie 值")
	}

	// UI 的 API 路径（另一条路由、同三件套）+ 平台 JWT → 应被注入
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/services", nil)
	req.Header.Set("Authorization", platformJWT)
	req.Header.Set("Cookie", "_wrauth-gate="+cookieVal)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if hitsAPI != 1 {
		t.Fatalf("/api/v1/ 路由命中 %d 次，期望 1", hitsAPI)
	}
	if got := seenAuthAPI; got != "Bearer warden-static-token" {
		t.Errorf("/api/v1/ 路由收到 Authorization = %q，期望注入 %q", got, "Bearer warden-static-token")
	}

	// 未配三件套的路由：带同 cookie 也不注入
	req2, _ := http.NewRequest("GET", srv.URL+"/other/x", nil)
	req2.Header.Set("Authorization", platformJWT)
	req2.Header.Set("Cookie", "_wrauth-gate="+cookieVal)
	resp3, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if hitsOther != 1 {
		t.Fatalf("/other/ 路由命中 %d 次，期望 1", hitsOther)
	}
	if got := seenAuthOther; got != platformJWT {
		t.Errorf("/other/ 路由收到 Authorization = %q，期望原样 %q（无三件套不注入）", got, platformJWT)
	}
}

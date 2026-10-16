package main

// auth_bridge：授权头桥接（2026-10-15，实测根因驱动的 workaround）。
//
// 背景：artifact release 发布通道的 CloudStudio Gateway 会**剥离客户端发来的
// Authorization 请求头**（三层实测：公网域名+头=401，本地 router+头=200，
// 直连上游+头=200）。vnts2 Web 管理与 OpenList 两个前端都把登录得到的 token
// 放在 Authorization 头里做业务认证（token 存 localStorage，不用 cookie），
// 于是公网环境下出现「登录 API 200 → 跳转后业务 API 401 → 前端 logout
// 弹回登录页」，用户感知为"登录成功但无法跳转到登录后的页面"。
//
// 桥接原理（对浏览器与上游均透明，按路由 opt-in）：
//  1. 响应侧：登录响应（POST + 200 + JSON + 含 data.token/token）→ 读 body
//     提取 token，种 Set-Cookie（Path 限定本路由前缀内，多应用不串台，
//     HttpOnly，SameSite=Lax）。
//  2. 请求侧：请求无 Authorization 头但携带桥接 cookie → 用 cookie 值恢复
//     Authorization 头（scheme 可配："Bearer" 前缀或原样 token）。
//
// 与 Mode 正交：vnts2(/api/) 与 OpenList(/openlist/) 均为 keep 挂载，
// bridge 不依赖 ModeStrip/Keep，只认 Route.AuthBridge 配置。

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
)

// authBridgeCookieDefault 默认桥接 cookie 名。发布网关会把 Set-Cookie 的
// Path 统一改写成 "/"（第三方上下文 cookie 化），多路由桥接时同名 cookie
// 会互相覆盖——故生产部署按路由配不同名字（auth_bridge_cookie）。
const authBridgeCookieDefault = "_wrauth"

// authBridgeMaxBody 只读小于此大小的 JSON 响应体（登录响应仅数百字节）。
// 超过则放弃桥接，避免把大响应整体缓冲进内存。
const authBridgeMaxBody = 64 << 10

// authBridgeMaxAge cookie 寿命（秒）。与 vnts2 JWT 的 24h 有效期对齐；
// openlist token 长期有效，一天后重登一次是可接受的代价。
const authBridgeMaxAge = 24 * 60 * 60

// ---------------------------------------------------------------------------
// 请求侧：从 cookie 恢复 Authorization 头
// ---------------------------------------------------------------------------

// authBridgeCookieName 解析路由实际使用的桥接 cookie 名。静态模式
// （Token 非空）缺省用 authBridgeGateCookieDefault（"_wrauth-gate"），
// 登录流缺省用 authBridgeCookieDefault（"_wrauth"）——两种模式的
// cookie 值语义不同（HMAC 标记 vs token 本身），默认名必须区分，
// 否则门控种的 cookie 请求侧认不出。
func authBridgeCookieName(ab *AuthBridge) string {
	if ab.CookieName != "" {
		return ab.CookieName
	}
	if ab.Token != "" {
		return authBridgeGateCookieDefault
	}
	return authBridgeCookieDefault
}

// restoreAuthHeader 在 Rewrite 内调用：用桥接 cookie 的值恢复
// Authorization 头。
//
// 为什么无条件覆盖（而非"有头就跳过"）：实测 CloudStudio 发布网关会往
// **每个**转发请求注入自己的平台 JWT（Authorization: Bearer <iss=
// cloudstudio.net 的 JWT>）。客户端浏览器发出的真 token 头到达 router
// 前就被替换成了这个假 token，"有头就跳过"会把平台 JWT 当客户端原值
// 放行，上游收到的必然 401。桥接 cookie 是本域 HttpOnly 的登录态，
// 比任何透传头都可信，故覆盖。
//
// 两种模式（按 AuthBridge.Token 是否非空区分）：
//   - 登录流（Token 为空）：cookie 值就是登录得到的 token，原样恢复
//     （vnts2 / OpenList）。
//   - 静态（Token 非空）：cookie 值是门控 HMAC 标记（不是 token），
//     验过 HMAC 后用配置的静态 Token 覆盖（warden：无登录 API）。
func restoreAuthHeader(pr *httputil.ProxyRequest, rt *Route) {
	if rt == nil || rt.AuthBridge == nil {
		return
	}
	name := authBridgeCookieName(rt.AuthBridge)
	c, err := pr.In.Cookie(name)
	if err != nil || c.Value == "" {
		return
	}
	if rt.AuthBridge.Token != "" {
		// 静态模式：cookie 值须等于门控 HMAC 标记，防伪造/猜测
		if subtle.ConstantTimeCompare([]byte(c.Value), []byte(gateCookieValue(rt.AuthBridge))) != 1 {
			return
		}
		val := rt.AuthBridge.Token
		if rt.AuthBridge.Scheme != "" {
			val = rt.AuthBridge.Scheme + " " + val
		}
		pr.Out.Header.Set("Authorization", val)
		return
	}
	val := c.Value
	if rt.AuthBridge.Scheme != "" {
		val = rt.AuthBridge.Scheme + " " + val
	}
	pr.Out.Header.Set("Authorization", val)
}

// ---------------------------------------------------------------------------
// 静态模式：门控路径换 cookie（warden 类无登录 API 的上游）
// ---------------------------------------------------------------------------

// authBridgeGateCookieDefault 静态模式默认门控 cookie 名。与登录流的
// "_wrauth" 区分：两种模式的 cookie 值语义不同（HMAC 标记 vs token
// 本身），同名会造成语义混淆；且发布网关会把 Path 改写成 "/"（实测），
// 多路由必须不同名。
const authBridgeGateCookieDefault = "_wrauth-gate"

// gateCookieValue 计算门控 cookie 的期望值：HMAC-SHA256(GateKey,
// "warden-route:static-gate:"+cookieName) 的 hex 前 32 字符。
// 无状态（无需服务端会话存储）、可验证（防伪造 cookie）、随 GateKey
// 轮换而失效。绑定 cookie 名：同 GateKey 的不同路由得不同值，
// 杜绝跨路由 cookie  tossing。
func gateCookieValue(ab *AuthBridge) string {
	name := authBridgeCookieName(ab)
	mac := hmac.New(sha256.New, []byte(ab.GateKey))
	_, _ = mac.Write([]byte("warden-route:static-gate:" + name))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// handleAuthGate 处理静态模式门控路径。返回 true 表示已处理完毕
// （调用方不应再转发）。仅当路由配了静态三件套且请求路径恰好等于
// GatePath 时介入；其余请求原样放行转发。
//
// 安全模型：GateKey 是唯一凭据（常量时间比对）——拿到分享链接的
// 攻击者没有 Key 时：门控 403、业务路径无 cookie 不注入，上游
// 收到平台 JWT 判 401，零控制权。
func handleAuthGate(w http.ResponseWriter, r *http.Request, rt *Route) bool {
	if rt == nil || rt.AuthBridge == nil || rt.AuthBridge.Token == "" {
		return false
	}
	if r.URL.Path != rt.AuthBridge.GatePath {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return true
	}
	got := r.URL.Query().Get("k")
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(rt.AuthBridge.GateKey)) != 1 {
		http.Error(w, "forbidden: invalid gate key", http.StatusForbidden)
		return true
	}
	name := authBridgeCookieName(rt.AuthBridge)
	// Path 固定 "/"（而非 rt.Prefix）：warden UI 是全内联单页，API 用
	// **根绝对路径**（/api/v1/...，它假设自己部署在域名根下），而 UI 自身
	// 挂在 /warden/ 前缀下——cookie 只种前缀内的话，浏览器对 /api/v1/
	// 请求根本不发，注入无从发生（2026-10-16 实测踩坑：jar 里有 cookie、
	// 请求头里没有）。全局 Path 无副作用：cookie 名独立（_wrauth-gate）
	// 且值是 HMAC 标记，其他路由收到也不认；且发布网关本来就会把
	// Set-Cookie Path 改写成 "/"（auth_bridge 历史实测），公网现实即全局。
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    gateCookieValue(rt.AuthBridge),
		Path:     "/",
		MaxAge:   authBridgeMaxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	// 302 回前缀，保留 sharecode 等其余查询参数（发布链接的访问凭据
	// 可能挂在查询串上，剥 k 即可）。
	q := r.URL.Query()
	q.Del("k")
	loc := rt.Prefix
	if enc := q.Encode(); enc != "" {
		loc += "?" + enc
	}
	http.Redirect(w, r, loc, http.StatusFound)
	return true
}

// ---------------------------------------------------------------------------
// 响应侧：登录响应提取 token 种 cookie
// ---------------------------------------------------------------------------

// bridgeLoginCookie 在 ModifyResponse 内调用（置于 Set-Cookie/Location
// 重写之后，避免自身种的 cookie 被 rewriteSetCookie 二次加前缀）。
// 只认「POST + 200 + JSON + body 含 token 字段」的响应——登录接口的形态；
// 其余响应原样放回，零行为变化。
//
// 静态模式（Token 非空）直接跳过：warden 的 POST API 也可能返回含
// token 字段的 JSON，不能被误当登录响应桥接；门控 cookie 由
// handleAuthGate 专门发放。
func bridgeLoginCookie(resp *http.Response, rt *Route) {
	if rt == nil || rt.AuthBridge == nil || resp.Request == nil {
		return
	}
	if rt.AuthBridge.Token != "" {
		return
	}
	if resp.Request.Method != http.MethodPost || resp.StatusCode != http.StatusOK {
		return
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "json") {
		return
	}
	if resp.ContentLength > authBridgeMaxBody {
		return // 大响应不桥接（读 body 前先按声明长度筛掉）
	}

	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	// 无论读取成败都要把 body 装回去——ModifyResponse 之后 ReverseProxy
	// 直接写 resp.Body，丢了就是空响应。
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if resp.ContentLength >= 0 {
		resp.ContentLength = int64(len(body))
	}
	if err != nil {
		log.Printf("[route] auth_bridge 读登录响应体失败 %s: %v", resp.Request.URL.Path, err)
		return
	}

	token, ok := extractToken(body)
	if !ok {
		return // 非登录响应（业务 JSON 也常是 200），不种 cookie
	}

	name := authBridgeCookieName(rt.AuthBridge)
	cookie := name + "=" + token +
		"; Path=" + rt.Prefix +
		"; Max-Age=" + itoa(authBridgeMaxAge) +
		"; HttpOnly; SameSite=Lax"
	resp.Header.Add("Set-Cookie", cookie)
}

// extractToken 从登录响应 JSON 提取 token。依次尝试：
//   - data.token（vnts2 与 openlist 的实际结构 {"code":200,"data":{"token":"..."}}）
//   - token（顶层，兼容其它服务）
func extractToken(body []byte) (string, bool) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return "", false
	}
	if raw, ok := m["data"]; ok {
		var d map[string]json.RawMessage
		if err := json.Unmarshal(raw, &d); err == nil {
			if t, ok := jsonString(d["token"]); ok && t != "" {
				return t, true
			}
		}
	}
	if t, ok := jsonString(m["token"]); ok && t != "" {
		return t, true
	}
	return "", false
}

// jsonString 把 RawMessage 解为非空字符串。
func jsonString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// itoa 避免为一个小转换引 strconv（本文件只需这一处）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// validAuthBridgeScheme 校验 scheme：仅允许 token 字符（RFC 7235 的
// auth-scheme 是字母开头，但实际配 "Bearer"；放宽到可见 ASCII 且不含
// 空格与控制字符——空格会破坏头结构，CR/LF 是头注入）。
func validAuthBridgeScheme(s string) bool {
	if s == "" {
		return true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c >= 0x7f {
			return false
		}
	}
	return true
}

// validAuthBridgeCookieName 校验 cookie 名（RFC 6265 token：可见 ASCII
// 且不含分隔符 , ; = 空格等——分号会截断 Set-Cookie，等号会歧义）。
func validAuthBridgeCookieName(s string) bool {
	if s == "" {
		return true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= ' ' || c >= 0x7f {
			return false
		}
		switch c {
		case ',', ';', '=', '"', '\\':
			return false
		}
	}
	return true
}

// 静态注入三件套的字段约束。
const (
	maxStaticTokenLen = 512 // token 进 HTTP 头，512 足够任何真实 token
	minGateKeyLen     = 16  // 门控密钥是唯一凭据，短于 16 位可暴力
	maxGateKeyLen     = 128
	maxGatePathLen    = 256
)

// validStaticToken 校验静态 token：可见 ASCII（0x21-0x7e）、非空、
// 不超长。禁空格（会破坏 "Bearer <token>" 头结构）与控制字符
// （CRLF=头注入）。
func validStaticToken(s string) bool {
	if s == "" || len(s) > maxStaticTokenLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// validGateKey 校验门控密钥：[A-Za-z0-9_-]，16-128 位。URL 安全字符集
// 避免查询串编解码歧义（浏览器/Go 对 % 等字符的处理差异会让比对失败）；
// 长度下限保证不可暴力。
func validGateKey(s string) bool {
	if len(s) < minGateKeyLen || len(s) > maxGateKeyLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// authBridgeStaticReason 返回静态三件套的问题描述（""=无问题）。
// validAuthBridgeStatic 与 routesfile 的条目级 warning 共用，保证
// 在线 API 与磁盘加载的判定逻辑单一权威。
func authBridgeStaticReason(ab *AuthBridge, prefix string) string {
	hasToken, hasGate, hasKey := ab.Token != "", ab.GatePath != "", ab.GateKey != ""
	if !hasToken && !hasGate && !hasKey {
		return ""
	}
	if !hasToken || !hasGate || !hasKey {
		return "auth_bridge 静态三件套（auth_bridge_token/auth_bridge_gate/auth_bridge_gate_key）须成对配置"
	}
	if !validStaticToken(ab.Token) {
		return "auth_bridge_token 含非法字符（空格/控制字符/非 ASCII）或为空/超长"
	}
	if !validGateKey(ab.GateKey) {
		return "auth_bridge_gate_key 须为 16-128 位 URL 安全字符 [A-Za-z0-9_-]"
	}
	if !strings.HasPrefix(ab.GatePath, "/") || len(ab.GatePath) > maxGatePathLen {
		return "auth_bridge_gate 须为以 / 开头的绝对路径且不超过 256 字符"
	}
	// gate 必须在前缀内（否则 Lookup 命中不了本路由，门控永不生效），
	// 且不能等于前缀本身（那会遮蔽路由 UI）。
	if !strings.HasPrefix(ab.GatePath, prefix) || ab.GatePath == prefix {
		return fmt.Sprintf("auth_bridge_gate 须位于路由前缀内且不等于前缀（gate=%q，prefix=%q）", ab.GatePath, prefix)
	}
	return ""
}

// validAuthBridgeStatic 校验静态三件套的整体语义（字段级 charset 由
// validStaticToken/validGateKey 在解析层兜底）：
//   - 全不配 → true（登录流或未启用）
//   - 全配且 gate 落在前缀内、gate != 前缀 → true
//   - 任一为缺 → false（缺一三件套即拒绝，杜绝无条件注入）
func validAuthBridgeStatic(ab *AuthBridge, prefix string) bool {
	return authBridgeStaticReason(ab, prefix) == ""
}

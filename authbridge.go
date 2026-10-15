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
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
)

// authBridgeCookieName 桥接 cookie 名。值按 Path 隔离在不同挂载点内，
// 故全局一个名字即可（不会串台：浏览器只把 Path 匹配的 cookie 发回来）。
const authBridgeCookieName = "_wrauth"

// authBridgeMaxBody 只读小于此大小的 JSON 响应体（登录响应仅数百字节）。
// 超过则放弃桥接，避免把大响应整体缓冲进内存。
const authBridgeMaxBody = 64 << 10

// authBridgeMaxAge cookie 寿命（秒）。与 vnts2 JWT 的 24h 有效期对齐；
// openlist token 长期有效，一天后重登一次是可接受的代价。
const authBridgeMaxAge = 24 * 60 * 60

// ---------------------------------------------------------------------------
// 请求侧：从 cookie 恢复 Authorization 头
// ---------------------------------------------------------------------------

// restoreAuthHeader 在 Rewrite 内调用：用桥接 cookie 的值恢复
// Authorization 头。
//
// 为什么无条件覆盖（而非"有头就跳过"）：实测 CloudStudio 发布网关会往
// **每个**转发请求注入自己的平台 JWT（Authorization: Bearer <iss=
// cloudstudio.net 的 JWT>）。客户端浏览器发出的真 token 头到达 router
// 前就被替换成了这个假 token，"有头就跳过"会把平台 JWT 当客户端原值
// 放行，上游收到的必然 401。桥接 cookie 是本域 HttpOnly + Path 隔离的
// 登录态，比任何透传头都可信，故覆盖。
func restoreAuthHeader(pr *httputil.ProxyRequest, rt *Route) {
	if rt == nil || rt.AuthBridge == nil {
		return
	}
	c, err := pr.In.Cookie(authBridgeCookieName)
	if err != nil || c.Value == "" {
		return
	}
	val := c.Value
	if rt.AuthBridge.Scheme != "" {
		val = rt.AuthBridge.Scheme + " " + val
	}
	pr.Out.Header.Set("Authorization", val)
}

// ---------------------------------------------------------------------------
// 响应侧：登录响应提取 token 种 cookie
// ---------------------------------------------------------------------------

// bridgeLoginCookie 在 ModifyResponse 内调用（置于 Set-Cookie/Location
// 重写之后，避免自身种的 cookie 被 rewriteSetCookie 二次加前缀）。
// 只认「POST + 200 + JSON + body 含 token 字段」的响应——登录接口的形态；
// 其余响应原样放回，零行为变化。
func bridgeLoginCookie(resp *http.Response, rt *Route) {
	if rt == nil || rt.AuthBridge == nil || resp.Request == nil {
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

	cookie := authBridgeCookieName + "=" + token +
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

package main

// 响应重写（TDD 第一批 · 步骤3/4，C1-C9 + L1-L8，IMPLEMENTATION-PLAN.md §1.1/§1.2）。
//
// 透明代理的三类断裂修复：上游发的 Set-Cookie Path=/ 会撒满整个域名
// （多应用 cookie 串台）、Location: /login 相对重定向跳出挂载点 404。
// 修复原则：
//   - 只改 ModeStrip 路由的响应（ModeKeep 的 kula/ttyd 类自带 base_path，
//     路径本就是全站视角，动了反而坏）；
//   - ModifyResponse 是唯一 funnel（ReverseProxy 对 101 升级不触发它，
//     因此 WS 路径零影响）；
//   - 逐条按 RFC 6265 属性切分，name=value 首段与其它属性原样保留。

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// rewriteResponse 挂在 sharedProxy.ModifyResponse 的单一 funnel。
func rewriteResponse(resp *http.Response) error {
	rt, ok := resp.Request.Context().Value(routeCtxKey{}).(*Route)
	if !ok || rt == nil || rt.Mode != ModeStrip {
		// 无路由上下文 / ModeKeep：Set-Cookie/Location 重写一律不碰
		// （kula/ttyd 类自带 base_path，路径是全站视角，动了反而坏）。
		// 注意 auth_bridge 与 Mode 正交，下面的桥接不受此分支影响。
		if rt != nil {
			bridgeLoginCookie(resp, rt)
		}
		return nil
	}
	rewriteSetCookie(resp, rt.Prefix)
	rewriteLocation(resp, rt)
	// bridge 放在最后：自种的 cookie 带最终 Path（前缀），不被
	// rewriteSetCookie 二次加前缀。
	bridgeLoginCookie(resp, rt)
	return nil
}

// ---------------------------------------------------------------------------
// Set-Cookie Path 重写
// ---------------------------------------------------------------------------

// rewriteSetCookie 逐条重写 Set-Cookie 的 Path 属性：
// 值不带路由前缀则前插（Path=/login → /app/login）；无 Path 段则追加。
func rewriteSetCookie(resp *http.Response, prefix string) {
	cookies := resp.Header["Set-Cookie"]
	if len(cookies) == 0 {
		return
	}
	for i, c := range cookies {
		cookies[i] = rewriteCookiePath(c, prefix)
	}
}

// rewriteCookiePath 重写单条 Set-Cookie 的 Path 段。
// 按 ";" 切段保真重建：只替换 path 段内容，其余段（含各自前导空白）原样。
func rewriteCookiePath(c, prefix string) string {
	segs := strings.Split(c, ";")
	pathIdx := -1
	for i := 1; i < len(segs); i++ { // 0 段是 name=value，跳过
		attr := strings.TrimLeft(segs[i], " \t")
		if strings.HasPrefix(strings.ToLower(attr), "path=") {
			pathIdx = i
			break
		}
	}
	if pathIdx < 0 {
		return c + "; Path=" + prefix
	}

	seg := segs[pathIdx]
	lead := seg[:len(seg)-len(strings.TrimLeft(seg, " \t"))]
	// 属性名已由上方大小写不敏感前缀匹配确认，按固定长度剥离（TrimPrefix
	// 大小写敏感，会把 "Path=/login" 整体当值，酿成 Path=/app/Path=/login）
	val := strings.TrimLeft(seg, " \t")[len("path="):]
	if strings.HasPrefix(val, prefix) {
		return c // 已含前缀，原样返回
	}
	// 宽容处理带引号的 path 值（RFC 6265 不带引号，防御性保留）
	quoted := len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"'
	if quoted {
		val = val[1 : len(val)-1]
	}
	newVal := prefix + strings.TrimPrefix(val, "/")
	if quoted {
		newVal = `"` + newVal + `"`
	}
	segs[pathIdx] = lead + "Path=" + newVal
	return strings.Join(segs, ";")
}

// ---------------------------------------------------------------------------
// Location 重定向重写
// ---------------------------------------------------------------------------

// rewriteLocation 把上游的 Location 重定向拉回挂载点内。
//
// 三类处理：
//   - 相对路径（/login、../x、login）：先对**出站请求 URL**（上游视角）
//     解析成绝对路径，再前插路由前缀；
//   - 绝对 URL（含 protocol-relative //host/x）指回上游自己：去掉
//     scheme/host 相对化并前插前缀——绝不把浏览器导向 127.0.0.1 死地；
//   - 外部绝对 URL：原样不动。
func rewriteLocation(resp *http.Response, rt *Route) {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}
	u, err := url.Parse(loc)
	if err != nil {
		return // 畸形 Location：原样返回，不 panic（L8）
	}
	if u.Scheme != "" || u.Host != "" {
		if !pointsToUpstream(u, rt) {
			return // 外部绝对 URL，不动（L4）
		}
		u.Scheme, u.Host = "", "" // 相对化（L3）
	} else if resp.Request != nil && resp.Request.URL != nil {
		// 相对 URL：先对上游视角的出站请求解析（处理 ../x / 裸文件名，L2）。
		// 注意出站 URL 带 scheme/host，ResolveReference 会继承它们，
		// 解析后必须清掉，否则把浏览器导向 http://127.0.0.1:PORT 死地。
		u = resp.Request.URL.ResolveReference(u)
		u.Scheme, u.Host = "", ""
	}

	path := u.Path
	if !strings.HasPrefix(path, rt.Prefix) {
		path = rt.Prefix + strings.TrimPrefix(path, "/")
	}
	u.Path = path
	u.RawPath = ""
	resp.Header.Set("Location", u.String())
}

// pointsToUpstream 判断绝对 URL 是否指回本路由的上游自己
// （host 名匹配、端口缺省或匹配）。
func pointsToUpstream(u *url.URL, rt *Route) bool {
	if u.Hostname() != rt.Host {
		return false
	}
	if u.Port() == "" {
		return true // 端口缺省：80/443，上游 http 时视作指向自己
	}
	p, err := strconv.Atoi(u.Port())
	return err == nil && p == rt.Port
}

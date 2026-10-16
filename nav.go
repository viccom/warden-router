package main

// 导航首页（宫格）+ 只读 JSON 端点 + 后台健康探测。
//
// 设计约定：
//   - 服务端渲染（SSR）：禁用 JS 时页面完整可用；JS 仅做 15s 增量刷新
//     （渐进增强，刷新失败静默保留 SSR 内容）。
//   - 卡片链接一律 target="_blank" rel="noopener noreferrer"：导航页点开
//     后端网站应在**新标签页**打开，导航页本身作为"前厅"常驻。
//   - 所有插值字段经 htmlEsc 转义——Display/Desc/Icon/Prefix 可来自用户
//     可写的动态路由，漏一个就是存储型 XSS（TestDefect_IconXSS 守着这条）。
//   - warden 注册服务的健康状态由 Cards() 注入；动态路由没有 warden 登记，
//     由后台 TCP 拨测（probeOnce）补位，且只探测回环/内网地址——避免把
//     路由器变成对公网地址的周期性灯塔。

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// probeInterval 后台拨测间隔。warden 轮询是 30s，这里取一半，
// 让动态路由的健康状态翻新比自动发现更跟手。
const probeInterval = 15 * time.Second

// dialTimeout 单次 TCP 拨测超时。拨测是后台行为，宁可判死不可拖慢页面。
const dialTimeout = 800 * time.Millisecond

// ---------------------------------------------------------------------------
// 后台健康探测（仅覆盖 warden 未登记的动态路由）
// ---------------------------------------------------------------------------

var (
	probeMu     sync.RWMutex
	probeHealth = map[string]string{} // 路由前缀 → healthy | unhealthy
)

// swapProbe 替换包级 probeHealth，返回恢复函数（测试用）。
func swapProbe() func() {
	probeMu.Lock()
	saved := probeHealth
	probeHealth = map[string]string{}
	probeMu.Unlock()
	return func() {
		probeMu.Lock()
		probeHealth = saved
		probeMu.Unlock()
	}
}

func probeLoop(interval time.Duration) {
	for {
		probeOnce()
		time.Sleep(interval)
	}
}

// probeOnce 对"warden 未覆盖 + 回环/内网地址"的路由做 TCP 拨测，
// 结果整批替换 probeHealth（顺带清理已删除前缀的残留）。
func probeOnce() {
	want := map[string]bool{}
	next := map[string]string{}
	for _, c := range table.Cards() {
		if c.Health != "" {
			continue // warden 已有健康来源，不重复拨测
		}
		if !probeableHost(c.Host) {
			continue // 公网 IP / 主机名不拨测
		}
		want[c.Prefix] = true
		if dialOK(c.Host, c.Port) {
			next[c.Prefix] = "healthy"
		} else {
			next[c.Prefix] = "unhealthy"
		}
	}
	probeMu.Lock()
	for p := range probeHealth {
		if !want[p] {
			delete(probeHealth, p)
		}
	}
	for p, h := range next {
		probeHealth[p] = h
	}
	probeMu.Unlock()
}

// probeableHost 只拨测回环 / 私网 / 链路本地地址。主机名一律跳过：
// 动态路由若误填外部域名，解析+连接会把路由器变成对外灯塔。
func probeableHost(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
}

func dialOK(host string, port int) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), dialTimeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// cardHealth 卡片展示用健康值：warden 来源优先，其次拨测结果，
// 最后 unknown。非三态值一律归一为 unknown（防止用户写入任意 class）。
func cardHealth(c *Route) string {
	h := c.Health
	if h == "" {
		probeMu.RLock()
		h = probeHealth[c.Prefix]
		probeMu.RUnlock()
	}
	switch h {
	case "healthy", "unhealthy", "unknown":
		return h
	}
	return "unknown"
}

// sourceLabel 路由来源徽章文案。
func sourceLabel(src string) string {
	switch src {
	case "static":
		return "静态"
	case "discovered":
		return "发现"
	case "dynamic":
		return "动态"
	}
	return "—"
}

// ---------------------------------------------------------------------------
// 导航页渲染
// ---------------------------------------------------------------------------

// navLink 返回导航卡片的打开链接。静态注入路由（auth_bridge 三件套，
// 见 authbridge.go）直达门控路径——卡片即公网登录入口（落地 302 回前缀
// 并种 24h cookie）；其余路由打开前缀本身。
func navLink(c *Route) string {
	if c.AuthBridge != nil && c.AuthBridge.Token != "" && c.AuthBridge.GatePath != "" {
		return c.AuthBridge.GatePath
	}
	return c.Prefix
}

// writeNav 导航宫格页。**所有插值字段一律转义**——Icon/Prefix/Display 来自
// 用户可写的动态路由，漏一个就是存储型 XSS。
func writeNav(w http.ResponseWriter, r *http.Request) {
	cards := table.Cards()
	var sb strings.Builder
	online, bad := 0, 0
	for i, c := range cards {
		h := cardHealth(c)
		switch h {
		case "healthy":
			online++
		case "unhealthy":
			bad++
		}
		disp := c.Display
		if disp == "" {
			disp = c.Name
		}
		icon := c.Icon
		if icon == "" {
			icon = "🌐"
		}
		desc := c.Desc
		if desc == "" {
			desc = "&nbsp;" // 占位，保证无描述卡片与有描述卡片行高一致
		}
		fmt.Fprintf(&sb, `<a class="card" href="%s" target="_blank" rel="noopener noreferrer" `+
			`data-prefix="%s" style="--i:%d" title="在新标签页打开 %s">`+
			`<span class="ico" aria-hidden="true">%s</span>`+
			`<span class="t">%s</span><span class="d">%s</span>`+
			`<span class="b"><span class="dot %s"></span>`+
			`<span class="p">%s</span><span class="src">%s</span>`+
			`<span class="go" aria-hidden="true">↗</span></span></a>`,
			htmlEsc(navLink(c)), htmlEsc(c.Prefix), i, htmlEsc(c.Prefix),
			htmlEsc(icon), htmlEsc(disp), desc,
			htmlEsc(h), htmlEsc(c.Prefix), htmlEsc(sourceLabel(c.Source)))
	}
	items := sb.String()
	if items == "" {
		items = `<p class="empty">暂无已挂载服务 —— 在 services.toml 配置 ui_url 即自动出现</p>`
	}
	stat := strconv.Itoa(len(cards)) + " 项服务 · " + strconv.Itoa(online) + " 在线"
	if bad > 0 {
		stat += " · " + strconv.Itoa(bad) + " 异常"
	}
	page := navHead + `<div class="stat" id="stat">` + htmlEsc(stat) + `</div></header>` +
		`<div class="grid">` + items + `</div>` + navTail
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(page)))
	w.WriteHeader(200)
	_, _ = io.WriteString(w, page)
}

// ---------------------------------------------------------------------------
// 只读 JSON 端点（供导航页 JS 增量刷新，无需鉴权——内容与公开页面一致）
// ---------------------------------------------------------------------------

func handleNavAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	cards := table.Cards()
	out := make([]map[string]string, 0, len(cards))
	for _, c := range cards {
		disp := c.Display
		if disp == "" {
			disp = c.Name
		}
		out = append(out, map[string]string{
			"prefix": c.Prefix, "display": disp, "icon": c.Icon,
			"health": cardHealth(c), "source": c.Source,
		})
	}
	writeJSON(w, 200, map[string]any{"routes": out, "ts": time.Now().Unix()})
}

func htmlEsc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;")
	return r.Replace(s)
}

// navHead 页头 + 全部样式。视觉方向「仪表前厅 / Precision Paper」：
// 暖纸底、墨色排版、朱砂 accent、等宽字体做前缀/徽章的"基础设施纹理"。
// 浅色为默认，prefers-color-scheme 暗色整套换变量；无 webfont / 无 CDN，
// 等宽栈与中文黑体栈均为系统可用字体，完全离线自包含。
const navHead = `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>服务导航 · warden-route</title><style>
:root{--paper:#f6f5f1;--surface:#fff;--ink:#1d1f24;--ink2:#6f6a61;--ink3:#a39d92;
--line:#e6e3dc;--line2:#d3cfc5;--accent:#c2402a;--ok:#1e7f4e;--bad:#c2402a;--warn:#a97e00;
--grid:rgba(29,31,36,.030);--shadow:0 1px 2px rgba(29,31,36,.04),0 10px 28px -14px rgba(29,31,36,.14);
--shadow-h:0 2px 4px rgba(29,31,36,.05),0 16px 36px -16px rgba(29,31,36,.20)}
@media (prefers-color-scheme:dark){:root{--paper:#141519;--surface:#1c1e23;--ink:#ece8e1;
--ink2:#9b968c;--ink3:#6b675f;--line:#2a2c32;--line2:#3b3e45;--accent:#e0654c;--ok:#57b183;
--bad:#e0654c;--warn:#d2a83c;--grid:rgba(236,232,225,.035);
--shadow:0 1px 2px rgba(0,0,0,.28),0 10px 28px -14px rgba(0,0,0,.50);
--shadow-h:0 2px 4px rgba(0,0,0,.30),0 18px 40px -18px rgba(0,0,0,.65)}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;color:var(--ink);background-color:var(--paper);
background-image:linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px);
background-size:44px 44px;
font-family:"Avenir Next","Segoe UI Variable Text","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
-webkit-font-smoothing:antialiased}
.wrap{width:min(1060px,92vw);margin:0 auto;padding:60px 0 48px}
header{display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:14px;
padding-bottom:18px;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:8px;font-family:"JetBrains Mono","SF Mono","Cascadia Code",Consolas,"Liberation Mono",monospace;
font-size:11px;letter-spacing:.14em;color:var(--ink3);margin-bottom:10px}
.brand .mark{color:var(--accent);font-size:12px}
h1{font-size:32px;font-weight:650;margin:0;letter-spacing:.01em}
.sub{margin:7px 0 0;font-size:13px;color:var(--ink2)}
.stat{font-family:"JetBrains Mono","SF Mono","Cascadia Code",Consolas,"Liberation Mono",monospace;
font-size:12px;color:var(--ink2);white-space:nowrap;padding-bottom:3px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(232px,1fr));gap:14px;margin-top:30px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:17px 17px 13px;
color:var(--ink);text-decoration:none;display:flex;flex-direction:column;gap:5px;
box-shadow:var(--shadow);animation:rise .45s cubic-bezier(.2,.7,.3,1) both;animation-delay:calc(var(--i,0)*45ms);
transition:transform .18s cubic-bezier(.2,.7,.3,1),border-color .18s,box-shadow .18s}
.card:hover,.card:focus-visible{transform:translateY(-2px);border-color:var(--line2);box-shadow:var(--shadow-h)}
.card:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.card:hover .go,.card:focus-visible .go{opacity:1;transform:none}
.card:hover .t{color:var(--accent)}
.ico{font-size:22px;line-height:1.2}
.t{font-weight:600;font-size:15px;transition:color .18s}
.d{color:var(--ink2);font-size:12.5px;line-height:1.55;flex:1;min-height:2.4em}
.b{display:flex;align-items:center;gap:8px;margin-top:4px;
font-family:"JetBrains Mono","SF Mono","Cascadia Code",Consolas,"Liberation Mono",monospace;
font-size:11px;color:var(--ink3)}
.p{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.src{border:1px solid var(--line2);border-radius:4px;padding:0 5px;font-size:10px;line-height:16px;flex:none}
.go{margin-left:auto;color:var(--accent);opacity:0;transform:translate(-2px,2px);
transition:opacity .18s,transform .18s;flex:none}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block;flex:none}
.dot.healthy{background:var(--ok)}
.dot.unhealthy{background:var(--bad);animation:blink 1.6s ease-in-out infinite}
.dot.unknown{background:var(--warn)}
.empty{grid-column:1/-1;text-align:center;color:var(--ink2);font-size:13px;padding:48px 0}
footer{margin-top:42px;padding-top:16px;border-top:1px solid var(--line);
font-family:"JetBrains Mono","SF Mono","Cascadia Code",Consolas,"Liberation Mono",monospace;
font-size:11px;color:var(--ink3);display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}
@keyframes rise{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.35}}
@media (prefers-reduced-motion:reduce){.card,.dot.unhealthy{animation:none}.card{transition:none}}
@media (max-width:560px){.wrap{padding-top:40px}h1{font-size:26px}.grid{margin-top:22px}}
</style></head><body><div class="wrap"><header>
<div><div class="brand"><span class="mark">◈</span>WARDEN-ROUTE</div>
<h1>服务导航</h1>
<p class="sub">单域名路径分流入口 · 点击卡片在新标签页打开</p></div>
`

// navTail 收尾：JS 仅做渐进增强的 15s 增量刷新（失败静默），
// 发现新前缀才整页重载。字符串拼接、不用模板字符串，避免反引号。
const navTail = `</div>
<footer><span>warden-route(go) · 路由动态管理 /_routes</span><span>discovery 30s · probe 15s</span></footer>
</div><script>
(function(){
function stat(){var cs=document.querySelectorAll('.card'),
ok=document.querySelectorAll('.dot.healthy').length,bad=document.querySelectorAll('.dot.unhealthy').length,
s=cs.length+' 项服务 · '+ok+' 在线';if(bad)s+=' · '+bad+' 异常';
var el=document.getElementById('stat');if(el)el.textContent=s;}
function refresh(){fetch('/_api/nav',{cache:'no-store'}).then(function(r){return r.json()}).then(function(d){
var seen={},news=false;
document.querySelectorAll('.card').forEach(function(c){seen[c.getAttribute('data-prefix')]=1;});
(d.routes||[]).forEach(function(r){if(!seen[r.prefix]){news=true;return;}
var card=document.querySelector('.card[data-prefix="'+CSS.escape(r.prefix)+'"]');
if(card){var dot=card.querySelector('.dot');if(dot)dot.className='dot '+r.health;}});
if(news){location.reload();return;}stat();
}).catch(function(){});}
stat();setInterval(refresh,15000);
})();
</script></body></html>`

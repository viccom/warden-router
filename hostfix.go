package main

// host_fix：对外 Host 修复（2026-10-15，公网干净实验实锤驱动）。
//
// 背景：artifact release 发布通道的平台网关（CloudStudio Gateway）会把
// 入站请求的 Host 改写为内部寻址 Host：
//
//	9000-<space-key>.e2b.<region>.sandbox.cloudstudio.club
//
// 且 X-Forwarded-Host 被一并改写——**没有任何请求头保留浏览器原始
// 域名**（2026-10-15 23:00 实测：curl 以 ad8584f64ca039337.app.
// workbuddy.host 发出，route-go 收到的 Host/X-Forwarded-Host 均为
// 网关形态）。上游 kula 的 WS 同源校验（gorilla Upgrader.CheckOrigin）
// 拿 Origin 与 Host 比对，浏览器 Origin 是发布域名、Host 是网关形态，
// 必然不匹配 → /monitor/ws 403 → 仪表盘无数据（main.go 转发注释里
// 预言的"改写 Host 会把所有浏览器 WS 连接判成跨站 403"在 artifact
// release 链路应验）。
//
// 机制（与 auth_bridge 同构：恢复被网关破坏的请求语义，按路由 opt-in）：
// 配了 public_host 且入站 Host 确为网关形态时，把发给上游的 Host
// 改写为对外域名——上游收到 Host == Origin（发布域名），同源校验
// 自然通过，无需上游配 allowed_origins 白名单。其余情况（未配置、
// 本地访问、直连）原样透传，零行为变化。
//
// Trae 预览通道变体（2026-10-16，第二类平台，症状相同、形态不同）：
// 字节 Trae 的预览代理把入站 Host 改写为**本机地址**（localhost:<port>
// / 127.0.0.1:<port>，如 localhost:9100），而对外域名是每会话动态的
// run-agent-<sid>-preview.<region>.traecontent.cn（还带 _session_token
// 查询参数），**无法用静态 public_host 表达**。实测证据：kula 日志
// "WebSocket upgrade blocked: Origin (<公网域名>) does not match Host
// (localhost:9100)"。此时改以**请求的 Origin 头**为权威来源——浏览器
// 在 WS 握手与 POST 上必带 Origin，其 host 即公网域名——配了
// host_fix_origin 的路由据此把上游 Host 恢复成 Origin 的 host：
// kula WS 同源校验通过；按 Host 生成绝对链接的上游（OpenList 视频
// raw_url）不再泄漏 localhost:<port>（浏览器会去连自己的机器而拒连，
// 即 ERR_CONNECTION_REFUSED）。
//
// 本变体解决的问题（场景 → 症状 → 本项如何解决）：
//  1) kula 主机监控/:27960 —— 场景：浏览器从公网入口访问 /monitor/；
//     症状：WS 握手被拒，日志 "WebSocket upgrade blocked: Origin (<公网域名>)
//     does not match Host (localhost:9100)"，面板无实时数据；
//     解决：按 Origin 把上游 Host 还原为公网域名（== 浏览器 Origin）。
//  2) OpenList 文件库/:5244 —— 场景：浏览器点播 123pan 上的视频；
//     症状：api/fs/get 返回的 raw_url 是 http://localhost:9100/openlist/p/…，
//     浏览器去连自己的 9100 端口 → net::ERR_CONNECTION_REFUSED，无法在线播放；
//     解决：Host 与 X-Forwarded-Host 一并还原为公网域名，raw_url 随之正确
//     （注：如今 OpenList 侧另有"生成相对链接"补丁，两者叠加更稳）。
//  3) 通用绝对链接 —— 场景：https 入口上用 XFP 推导 scheme 的上游；
//     症状：入站是明文（TLS 已在平台侧终止）→ 生成 http:// 绝对链接，
//     https 页面上触发混合内容；解决：按 Origin/Referer 的 scheme 覆盖 XFP。

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

// gatewayHostRe CloudStudio Gateway 内部寻址 Host 形态：
//
//	<port>-<16+位hex space-key>.e2b.<region>.sandbox.cloudstudio.club
//
// port 段泛化（route-go 监听端口不写死 9000，测试环境 9100 同样匹配）；
// region 段覆盖已实测的 gz2/sh3 及未来区域；大小写敏感（实测网关
// 输出固定小写，大写输入按不匹配处理更保守）。
var gatewayHostRe = regexp.MustCompile(
	`^[0-9]+-[0-9a-f]{16,}\.e2b\.[a-z0-9-]+\.sandbox\.cloudstudio\.club$`)

// isGatewayHost 判断入站 Host 是否为 CloudStudio Gateway 寻址形态。
// 先剥端口再匹配（浏览器可能带非默认端口）。
func isGatewayHost(host string) bool {
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h // 带端口：剥掉再匹配
	}
	return gatewayHostRe.MatchString(host)
}

// fixedHost 返回实际发给上游的 Host 值。
//
// 两种 opt-in 修复，按路由生效，互不干扰：
//
//   - public_host：入站 Host 是 CloudStudio 网关形态 → 改写为静态对外域名；
//   - host_fix_origin：src 为浏览器侧公网 URL（调用方择优传入 Origin 或
//     Referer）→ 改写为它的 host，供"对外域名每会话动态、入站 Host 被改写
//     成本机地址"的平台使用。
//
// 其余（未配置 / src 为空 / src 回环或非 http(s) / nil 路由）→ 原样透传。
func fixedHost(inHost, src string, rt *Route) string {
	if rt == nil {
		return inHost
	}
	if rt.PublicHost != "" && isGatewayHost(inHost) {
		return rt.PublicHost
	}
	if rt.HostFixOrigin {
		if h := publicOriginHost(src); h != "" {
			return h
		}
	}
	return inHost
}

// maxOriginLen Origin 头长度上界（Origin 本身很短；超长一律视为不可用，
// 防畸形输入做 URL 解析）。
const maxOriginLen = 1024

// publicOriginHost 从 Origin 头解析出可用的对外 host（含端口，若有）。
// 仅接受 http/https 且 host 非回环的值；其余（空串 / 畸形 / 无 scheme /
// 回环 localhost 与 127.0.0.0/8 与 ::1 / file: 等）返回 ""，调用方据此
// 跳过改写——绝不把畸形值或内网地址送给上游（头注入与内网泄漏双防）。
func publicOriginHost(origin string) string {
	if origin == "" || len(origin) > maxOriginLen {
		return ""
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	h := u.Hostname()
	if h == "" || isLoopbackHost(h) {
		return ""
	}
	return u.Host
}

// originScheme 从 Origin/Referer 解析对外 scheme（"http"/"https"）。
// 非 http(s) 或解析失败返回 ""，调用方据此不覆盖 X-Forwarded-Proto。
func originScheme(src string) string {
	if src == "" || len(src) > maxOriginLen {
		return ""
	}
	u, err := url.Parse(src)
	if err != nil {
		return ""
	}
	if u.Scheme == "http" || u.Scheme == "https" {
		return u.Scheme
	}
	return ""
}

// isLoopbackHost 判断 hostname 是否为回环/本机地址。
func isLoopbackHost(h string) bool {
	switch strings.ToLower(h) {
	case "localhost", "::1", "0.0.0.0":
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// validPublicHost 校验 public_host 配置值：合法 hostname（RFC 1123
// 宽松形态——字母/数字/点/横线，非空，不超 253，无路径分隔符与
// 控制字符）。防头注入（CR/LF/空格）与误配 URL（带 scheme/path）。
func validPublicHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if strings.ContainsAny(s, "/ \t\r\n:@?#[]") {
		return false
	}
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '-':
		default:
			return false
		}
	}
	return true
}

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

import (
	"net"
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
//   - 路由配了 public_host 且入站 Host 是网关形态 → 改写为 public_host
//   - 其余（未配置 / 本地 / 直连 / nil 路由）→ 原样透传
func fixedHost(inHost string, rt *Route) string {
	if rt != nil && rt.PublicHost != "" && isGatewayHost(inHost) {
		return rt.PublicHost
	}
	return inHost
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

package main

// 每路由响应头超时（TDD 第二批 · 步骤5，T1-T4/T6，IMPLEMENTATION-PLAN.md §2.2）。
//
// 为什么不能用 context deadline：context 取消对**已建立连接**同样生效，
// WS 终端会话与 SSE 流会被秒级掐死（实测教训：长连接场景 deadline 是错工具）。
// http.Transport.ResponseHeaderTimeout 只约束"等响应头"这一段，
// 响应头到达后的数据流不受限——正是我们要的语义。
//
// 实现：routingTransport 实现 RoundTripper，从请求 context 取路由：
//   - 超时配 0 → 全局 sharedTransport 单例（默认路径零变化）；
//   - 配了超时 → 按 (headerTimeout, idleTimeout) key 懒加载独立 Transport
//     并缓存。按配置而非按路由前缀缓存：同配置的路由共享连接池，
//     不会随路由数线性膨胀。

import (
	"net/http"
	"sync"
	"time"
)

// transportKey 是每路由 Transport 的缓存键。
type transportKey struct {
	headerTimeout time.Duration
	idleTimeout   time.Duration
}

// routingTransport 按路由超时配置分流的 RoundTripper。
type routingTransport struct {
	mu     sync.Mutex
	custom map[transportKey]*http.Transport
}

func newRoutingTransport() *routingTransport {
	return &routingTransport{custom: map[transportKey]*http.Transport{}}
}

func (rt *routingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r, _ := req.Context().Value(routeCtxKey{}).(*Route)
	return rt.transportFor(r).RoundTrip(req)
}

// transportFor 返回路由对应的 Transport（懒加载 + 按配置缓存）。
// 无路由上下文或未配超时（<=0）→ 全局 sharedTransport 单例。
func (rt *routingTransport) transportFor(r *Route) *http.Transport {
	if r == nil || r.ResponseHeaderTimeout <= 0 {
		return sharedTransport
	}
	key := transportKey{
		headerTimeout: time.Duration(r.ResponseHeaderTimeout),
		idleTimeout:   sharedTransport.IdleConnTimeout, // idle 回收策略与全局一致
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if tr, ok := rt.custom[key]; ok {
		return tr
	}
	// 以全局 Transport 为模板覆写，连接池参数（MaxIdleConns 等）保持一致
	tr := sharedTransport.Clone()
	tr.ResponseHeaderTimeout = key.headerTimeout
	rt.custom[key] = tr
	return tr
}

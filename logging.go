package main

// 访问日志中间件（TDD 第一批 · 步骤1，对应 IMPLEMENTATION-PLAN.md A1-A8）。
//
// 设计约束：
//   - statusRecorder 必须完整透传 Hijack/Flush/Unwrap：漏 Hijack 直接
//     打死 WebSocket 升级（kula /monitor/ws、ttyd 终端全部依赖它）；
//     漏 Unwrap 会让 http.ResponseController 无法穿透到真实连接。
//   - 日志单行、字段稳定，供后续 /_metrics 与人工排障共用：
//     [access] METHOD PATH -> STATUS BYTES DURATION route=PREFIX
//   - route 标签由中间件自做路由表查询（未命中记 "-"），不侵入 handler。

import (
	"bufio"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

// statusRecorder 包装 ResponseWriter，捕获状态码与响应字节数。
//
// 三个透传方法是生死线：
//   - Hijack：WS 升级与 ttyd 终端会话的唯一通道；
//   - Flush：SSE/kula 实时流不卡的关键；
//   - Unwrap：http.ResponseController（SetWriteDeadline 等）的
//     标准穿透钩子（Go 1.20+ 约定）。
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK // 隐式 200：首次 Write 前未显式 WriteHeader
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code // 只认第一次；后续 WriteHeader 由 net/http 记为 no-op
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (r *statusRecorder) Flush() {
	if fl, ok := r.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

// Unwrap 供 http.ResponseController 找到原始 ResponseWriter。
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// loggingMiddleware 记录每个请求的单行访问日志，并驱动指标采集。
//
// enter/leave 是指标的唯一记录点（无重复计数）。route 查找一次两用：
// 日志标签 + 指标标签。未命中路由的请求（404 / 内置端点）route="-"。
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		route := "-"
		if rt, ok := table.Lookup(r.URL.Path); ok {
			route = rt.Prefix
		}
		metrics.enter(route)
		rec := &statusRecorder{ResponseWriter: w}
		defer func() {
			dur := time.Since(start)
			status := "-"
			if rec.status != 0 {
				status = strconv.Itoa(rec.status)
			}
			metrics.leave(route, r.Method, status, dur)
			log.Printf("[access] %s %s -> %s %d %s route=%s",
				r.Method, r.URL.RequestURI(), status, rec.bytes,
				dur.Round(time.Microsecond), route)
		}()
		next.ServeHTTP(rec, r)
	})
}

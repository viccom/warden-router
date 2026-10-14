package main

// Prometheus 文本格式指标（TDD 第一批 · 步骤2，M1-M5，IMPLEMENTATION-PLAN.md §2.1）。
//
// 零第三方依赖手写 exposition 格式渲染。记录点唯一：loggingMiddleware
// 的请求出口（enter/leave 各一次，不会重复计数）。
//
// 指标族：
//   - warden_route_requests_total{method,route,status}      counter
//   - warden_route_request_duration_seconds{route}          histogram（累积桶）
//   - warden_route_requests_in_flight{route}                gauge
//   - warden_route_dynamic_routes                           gauge（渲染时实时读表）

import (
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// histBounds 直方图上界（秒）。累积语义：bucket i 计数 = 耗时 <= bounds[i]
// 的请求数；末桶 +Inf 恒等于总数。取值对齐常见 Web 延迟观测粒度。
// histBuckets = len(histBounds) + 1（+Inf 尾桶）；TestMetrics_HistogramSelfConsistent
// 断言渲染桶数与之相等，改边界数量必须同步改这里。
var histBounds = []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5}

const histBuckets = 9 // 8 个有限上界 + 1 个 +Inf 尾桶

// routeMetrics 单路由标签的全部指标。mu 保护整个 registry。
type routeMetrics struct {
	total    map[string]int64 // key: method + "|" + status
	hist     [histBuckets]int64
	histSum  float64 // 秒
	inFlight int64
}

type metricsRegistry struct {
	mu   sync.Mutex
	data map[string]*routeMetrics // key: 路由前缀（未命中记 "-"）
}

var metrics = &metricsRegistry{data: map[string]*routeMetrics{}}

// resetMetrics 仅测试用：清空全部计数器。指标是进程级全局状态，
// 不 reset 的话测试间互相污染。
func resetMetrics() {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.data = map[string]*routeMetrics{}
}

// entry 调用方须持有 mu。
func (m *metricsRegistry) entry(route string) *routeMetrics {
	e, ok := m.data[route]
	if !ok {
		e = &routeMetrics{total: map[string]int64{}}
		m.data[route] = e
	}
	return e
}

// enter 请求进入（先于 handler 执行，保证在途可观测）。
func (m *metricsRegistry) enter(route string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entry(route).inFlight++
}

// leave 请求离开：计数 + 直方图 + 在途递减，一次临界区完成。
func (m *metricsRegistry) leave(route, method, status string, d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.entry(route)
	e.inFlight--
	e.total[method+"|"+status]++
	sec := d.Seconds()
	e.histSum += sec
	// 累积桶：从首个 >= sec 的边界起，到尾桶全部 +1
	idx := len(histBounds) // 默认 +Inf 桶
	for i, b := range histBounds {
		if sec <= b {
			idx = i
			break
		}
	}
	for i := idx; i < histBuckets; i++ {
		e.hist[i]++
	}
}

// snapshot 复制一份用于渲染，避免持锁做字符串拼接。
func (m *metricsRegistry) snapshot() map[string]routeMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]routeMetrics, len(m.data))
	for k, v := range m.data {
		out[k] = *v // total map 与 hist 数组均为值拷贝（map 浅拷足够，只读）
	}
	return out
}

func leLabel(b float64) string {
	return strconv.FormatFloat(b, 'g', -1, 64)
}

// renderMetrics 输出 Prometheus exposition text（version 0.0.4）。
// 路由标签按字典序输出，保证同配置下渲染稳定（diff 友好）。
func renderMetrics() string {
	snap := metrics.snapshot()
	dynamic := len(table.GetDynamic())

	routes := make([]string, 0, len(snap))
	for r := range snap {
		routes = append(routes, r)
	}
	sort.Strings(routes)

	var b strings.Builder
	b.WriteString("# HELP warden_route_requests_total 按路由/方法/状态码的请求总数\n")
	b.WriteString("# TYPE warden_route_requests_total counter\n")
	for _, r := range routes {
		e := snap[r]
		keys := make([]string, 0, len(e.total))
		for k := range e.total {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts := strings.SplitN(k, "|", 2)
			method, status := parts[0], parts[1]
			b.WriteString("warden_route_requests_total{method=\"")
			b.WriteString(method)
			b.WriteString("\",route=\"")
			b.WriteString(r)
			b.WriteString("\",status=\"")
			b.WriteString(status)
			b.WriteString("\"} ")
			b.WriteString(strconv.FormatInt(e.total[k], 10))
			b.WriteByte('\n')
		}
	}

	b.WriteString("# HELP warden_route_request_duration_seconds 请求处理耗时直方图（秒，累积桶）\n")
	b.WriteString("# TYPE warden_route_request_duration_seconds histogram\n")
	for _, r := range routes {
		e := snap[r]
		for i, bound := range histBounds {
			b.WriteString("warden_route_request_duration_seconds_bucket{route=\"")
			b.WriteString(r)
			b.WriteString("\",le=\"")
			b.WriteString(leLabel(bound))
			b.WriteString("\"} ")
			b.WriteString(strconv.FormatInt(e.hist[i], 10))
			b.WriteByte('\n')
		}
		b.WriteString("warden_route_request_duration_seconds_bucket{route=\"")
		b.WriteString(r)
		b.WriteString("\",le=\"+Inf\"} ")
		b.WriteString(strconv.FormatInt(e.hist[histBuckets-1], 10))
		b.WriteByte('\n')
		b.WriteString("warden_route_request_duration_seconds_sum{route=\"")
		b.WriteString(r)
		b.WriteString("\"} ")
		b.WriteString(strconv.FormatFloat(e.histSum, 'g', -1, 64))
		b.WriteByte('\n')
		b.WriteString("warden_route_request_duration_seconds_count{route=\"")
		b.WriteString(r)
		b.WriteString("\"} ")
		b.WriteString(strconv.FormatInt(e.hist[histBuckets-1], 10))
		b.WriteByte('\n')
	}

	b.WriteString("# HELP warden_route_requests_in_flight 正在处理的请求数（含 WS 会话）\n")
	b.WriteString("# TYPE warden_route_requests_in_flight gauge\n")
	for _, r := range routes {
		b.WriteString("warden_route_requests_in_flight{route=\"")
		b.WriteString(r)
		b.WriteString("\"} ")
		b.WriteString(strconv.FormatInt(snap[r].inFlight, 10))
		b.WriteByte('\n')
	}

	b.WriteString("# HELP warden_route_dynamic_routes 当前动态路由条数\n")
	b.WriteString("# TYPE warden_route_dynamic_routes gauge\n")
	b.WriteString("warden_route_dynamic_routes ")
	b.WriteString(strconv.Itoa(dynamic))
	b.WriteByte('\n')
	return b.String()
}

// handleMetrics 无需鉴权的只读端点（与 /_health 同级的运维面）。
func handleMetrics(w http.ResponseWriter, r *http.Request) {
	body := renderMetrics()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if _, err := io.WriteString(w, body); err != nil {
		log.Printf("[route] /_metrics write: %v", err)
	}
}

package main

// 指标测试（TDD 第一批 · 步骤2，M1-M5，IMPLEMENTATION-PLAN.md §2.1）。
//
// 指标是进程级全局状态，每个测试开头必须 resetMetrics()，
// 否则测试间互相污染（Prometheus exporter 的经典陷阱）。

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// metricsGET 经完整中间件链请求 /_metrics，顺带断言 200 + text/plain。
func metricsGET(t *testing.T, base string) string {
	t.Helper()
	resp, err := http.Get(base + "/_metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /_metrics status=%d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type=%q，期望 text/plain", ct)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// newMetricsSrv 搭最小服务：/_metrics + 透传 handleAll，走完整中间件链
// （与 main.go 接线一致，指标挂点才被覆盖）。
func newMetricsSrv(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/_metrics", handleMetrics)
	mux.HandleFunc("/", handleAll)
	srv := httptest.NewServer(recoverMiddleware(loggingMiddleware(mux)))
	t.Cleanup(srv.Close)
	return srv
}

// M1 计数器：3 个 200（/a/ x2 + /b/ x1）+ 1 个 404（未命中）
func TestMetrics_RequestsTotal(t *testing.T) {
	resetMetrics()
	host, port, _, closeUp := upstream(t, func(w http.ResponseWriter, r *http.Request) {})
	defer closeUp()
	tb := NewRouteTable()
	tb.SetStatic([]*Route{
		{Prefix: "/a/", Host: host, Port: port, Mode: ModeStrip, Name: "a"},
		{Prefix: "/b/", Host: host, Port: port, Mode: ModeStrip, Name: "b"},
	})
	defer swapTable(tb)()

	srv := newMetricsSrv(t)
	for _, path := range []string{"/a/x", "/a/y", "/b/x", "/nope"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	body := metricsGET(t, srv.URL)
	for _, want := range []string{
		`warden_route_requests_total{method="GET",route="/a/",status="200"} 2`,
		`warden_route_requests_total{method="GET",route="/b/",status="200"} 1`,
		`warden_route_requests_total{method="GET",route="-",status="404"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("缺少样本行 %q：\n%s", want, body)
		}
	}
}

// M2 直方图自洽：+Inf 桶 == _count == requests_total，桶计数单调不减。
func TestMetrics_HistogramSelfConsistent(t *testing.T) {
	resetMetrics()
	host, port, _, closeUp := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Millisecond) // 让样本落进中间桶而非全在 le=0.001
	})
	defer closeUp()
	tb := NewRouteTable()
	tb.SetStatic([]*Route{{Prefix: "/h/", Host: host, Port: port, Mode: ModeStrip, Name: "h"}})
	defer swapTable(tb)()

	srv := newMetricsSrv(t)
	for i := 0; i < 5; i++ {
		resp, err := http.Get(srv.URL + "/h/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	body := metricsGET(t, srv.URL)

	// 收集 route="/h/" 的 bucket 样本
	type bkt struct {
		le string
		n  int64
	}
	var buckets []bkt
	var sum, count float64
	lastField := func(line string) string {
		return strings.TrimSpace(line[strings.LastIndex(line, " ")+1:])
	}
	for _, line := range strings.Split(body, "\n") {
		switch {
		case strings.Contains(line, `warden_route_request_duration_seconds_bucket{route="/h/",le="`):
			rest := line[strings.Index(line, `le="`)+4:]
			le := rest[:strings.Index(rest, `"`)]
			n, err := strconv.ParseInt(lastField(line), 10, 64)
			if err != nil {
				t.Fatalf("bucket 行数值解析失败: %q (%v)", line, err)
			}
			buckets = append(buckets, bkt{le, n})
		case strings.Contains(line, `warden_route_request_duration_seconds_sum{route="/h/"}`):
			sum, _ = strconv.ParseFloat(lastField(line), 64)
		case strings.Contains(line, `warden_route_request_duration_seconds_count{route="/h/"}`):
			count, _ = strconv.ParseFloat(lastField(line), 64)
		}
	}
	if len(buckets) != len(histBounds)+1 {
		t.Fatalf("bucket 行数=%d，期望 %d（8 边界 + +Inf）", len(buckets), len(histBounds)+1)
	}
	// 单调不减（Prometheus 累积直方图语义）
	for i := 1; i < len(buckets); i++ {
		if buckets[i].n < buckets[i-1].n {
			t.Errorf("bucket %s(%d) < 前一个 %s(%d)，累积直方图被破坏",
				buckets[i].le, buckets[i].n, buckets[i-1].le, buckets[i-1].n)
		}
	}
	// 自洽三等式
	if buckets[len(buckets)-1].le != "+Inf" || buckets[len(buckets)-1].n != 5 {
		t.Errorf("+Inf 桶 = %s/%d，期望 +Inf/5", buckets[len(buckets)-1].le, buckets[len(buckets)-1].n)
	}
	if count != 5 {
		t.Errorf("_count=%v，期望 5", count)
	}
	if sum <= 0 {
		t.Errorf("_sum=%v，期望 > 0", sum)
	}
	if want := `warden_route_requests_total{method="GET",route="/h/",status="200"} 5`; !strings.Contains(body, want) {
		t.Errorf("直方图总数与计数器不一致：缺少 %q", want)
	}
}

// M3 在途 gauge：请求中 > 0，结束后回 0。
func TestMetrics_InFlightGauge(t *testing.T) {
	resetMetrics()
	release := make(chan struct{})
	entered := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(loggingMiddleware(h))
	t.Cleanup(srv.Close)

	done := make(chan struct{})
	go func() {
		resp, err := http.Get(srv.URL + "/slow")
		if err == nil {
			resp.Body.Close()
		}
		close(done)
	}()

	<-entered // enter() 在 ServeHTTP 前调用，此刻必然已 +1
	metrics.mu.Lock()
	e := metrics.data["-"]
	var got int64
	if e != nil {
		got = e.inFlight
	}
	metrics.mu.Unlock()
	if got != 1 {
		t.Errorf("请求处理中 in_flight=%d，期望 1", got)
	}

	close(release)
	<-done
	// leave() 与客户端 read 完成无 happens-before，轮询等待归零
	deadline := time.Now().Add(2 * time.Second)
	for {
		metrics.mu.Lock()
		e := metrics.data["-"]
		var n int64
		if e != nil {
			n = e.inFlight
		}
		metrics.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("请求结束后 in_flight=%d，未回 0", n)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// M4 端点契约：200、text/plain、无需鉴权、三种指标族齐备。
func TestMetrics_Endpoint(t *testing.T) {
	resetMetrics()
	srv := newMetricsSrv(t)
	body := metricsGET(t, srv.URL) // 内部断言 200 + text/plain
	for _, want := range []string{
		"# HELP warden_route_requests_total",
		"# TYPE warden_route_requests_total counter",
		"# TYPE warden_route_request_duration_seconds histogram",
		"# TYPE warden_route_requests_in_flight gauge",
		"# TYPE warden_route_dynamic_routes gauge",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("缺少 %q：\n%s", want, body)
		}
	}
}

// M5 动态路由 gauge：增删动态路由后实时反映。
func TestMetrics_DynamicRoutesGauge(t *testing.T) {
	resetMetrics()
	tb := NewRouteTable()
	defer swapTable(tb)()
	srv := newMetricsSrv(t)

	if err := tb.Upsert(&Route{Prefix: "/d1/", Host: "127.0.0.1", Port: 1234, Mode: ModeStrip, Name: "d1"}); err != nil {
		t.Fatal(err)
	}
	if err := tb.Upsert(&Route{Prefix: "/d2/", Host: "127.0.0.1", Port: 1235, Mode: ModeKeep, Name: "d2"}); err != nil {
		t.Fatal(err)
	}
	if body := metricsGET(t, srv.URL); !strings.Contains(body, "warden_route_dynamic_routes 2") {
		t.Errorf("新增 2 条后 gauge 不含 2：\n%s", body)
	}
	if !tb.Delete("/d1/") {
		t.Fatal("Delete(/d1/) 返回 false")
	}
	if body := metricsGET(t, srv.URL); !strings.Contains(body, "warden_route_dynamic_routes 1") {
		t.Errorf("删除 1 条后 gauge 不含 1：\n%s", body)
	}
}

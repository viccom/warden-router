package main

// 每路由超时测试（TDD 第二批 · 步骤5，T1-T6，IMPLEMENTATION-PLAN.md §2.2）。
//
// 核心约束：超时**不能用 context deadline**（会掐死 WS/流式），
// 必须走 http.Transport.ResponseHeaderTimeout 按路由分流。

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// timeoutSrv 搭路由 /slow/（ModeStrip，可配超时）指向给定上游的代理链。
func timeoutSrv(t *testing.T, host string, port int, d Duration) *httptest.Server {
	t.Helper()
	tb := NewRouteTable()
	tb.SetStatic([]*Route{{
		Prefix: "/slow/", Host: host, Port: port, Mode: ModeStrip,
		ResponseHeaderTimeout: d, Name: "slow",
	}})
	t.Cleanup(swapTable(tb))
	srv := httptest.NewServer(recoverMiddleware(loggingMiddleware(http.HandlerFunc(handleAll))))
	t.Cleanup(srv.Close)
	return srv
}

// T1 配 100ms 超时 + 上游 300ms 才响应 → 快速失败得 5xx
func TestTimeout_FastFail(t *testing.T) {
	// 上游延迟 600ms（> 断言阈值 250ms 的 2 倍余量）：-race + 全包并发下
	// 调度抖动曾把 250ms 阈值吃穿（既有 flaky，2026-10-16 审查发现），
	// 拉开上游延迟让"快速失败"的语义断言稳定成立。
	host, port, _, closeUp := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(600 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	defer closeUp()

	srv := timeoutSrv(t, host, port, Duration(100*time.Millisecond))
	start := time.Now()
	resp, err := http.Get(srv.URL + "/slow/x")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 500 {
		t.Errorf("status=%d，期望 5xx（超时快速失败）", resp.StatusCode)
	}
	if elapsed > 250*time.Millisecond {
		t.Errorf("耗时 %v，未快速失败（期望 < 250ms）", elapsed)
	}
}

// T2 同上游不配超时 → 正常等待到 200
func TestTimeout_NoTimeoutWaits(t *testing.T) {
	host, port, _, closeUp := upstream(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	defer closeUp()

	srv := timeoutSrv(t, host, port, 0)
	resp, err := http.Get(srv.URL + "/slow/x")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d，期望 200", resp.StatusCode)
	}
}

// T3 WS 路由（ModeKeep，无超时）→ 101 + 数据帧，超时机制不误伤
func TestTimeout_WSUnaffected(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", 500)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nWS-DATA-FRAME\r\n")
		_ = buf.Flush()
		time.Sleep(100 * time.Millisecond)
	}))
	defer up.Close()
	uu, _ := url.Parse(up.URL)
	port, _ := strconv.Atoi(uu.Port())

	tb := NewRouteTable()
	tb.SetStatic([]*Route{{Prefix: "/ws/", Host: uu.Hostname(), Port: port, Mode: ModeKeep, Name: "t"}})
	defer swapTable(tb)()

	srv := httptest.NewServer(recoverMiddleware(loggingMiddleware(http.HandlerFunc(handleAll))))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET /ws/x HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "101") {
		t.Fatalf("状态行 = %q, err=%v", statusLine, err)
	}
	var payload string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		if strings.Contains(line, "WS-DATA-FRAME") {
			payload = line
			break
		}
	}
	if !strings.Contains(payload, "WS-DATA-FRAME") {
		t.Errorf("WS 数据帧未收到（payload=%q）", payload)
	}
}

// T4 200 个 200 请求走同一超时配置路由 → 上游 accepted 远小于 200
// （每路由 Transport 仍复用连接，D5 不回归）
func TestTimeout_ConnReuse(t *testing.T) {
	host, port, accepted, closeUp := upstream(t, func(w http.ResponseWriter, r *http.Request) {})
	defer closeUp()

	srv := timeoutSrv(t, host, port, Duration(100*time.Millisecond))
	for i := 0; i < 200; i++ {
		resp, err := http.Get(srv.URL + "/slow/x")
		if err != nil {
			t.Fatalf("第 %d 次 Get: %v", i, err)
		}
		resp.Body.Close()
	}
	if n := int(*accepted); n >= 20 {
		t.Errorf("上游 accepted=%d，期望远小于 200（连接未复用？）", n)
	}
}

// T6 transportFor 单元：不同超时→不同实例；同超时→共享；0→全局单例
func TestTimeout_TransportForRouting(t *testing.T) {
	rt := &routingTransport{custom: map[transportKey]*http.Transport{}}
	r100a := &Route{Prefix: "/a/", Host: "h", Port: 1, ResponseHeaderTimeout: Duration(100 * time.Millisecond)}
	r100b := &Route{Prefix: "/b/", Host: "h", Port: 2, ResponseHeaderTimeout: Duration(100 * time.Millisecond)}
	r2s := &Route{Prefix: "/c/", Host: "h", Port: 3, ResponseHeaderTimeout: Duration(2 * time.Second)}
	rNone := &Route{Prefix: "/d/", Host: "h", Port: 4}

	if rt.transportFor(r100a) == rt.transportFor(r2s) {
		t.Error("不同超时配置获得了同一 Transport 实例")
	}
	if rt.transportFor(r100a) != rt.transportFor(r100b) {
		t.Error("相同超时配置应共享 Transport（按配置缓存，防连接池膨胀）")
	}
	if got := rt.transportFor(r100a).ResponseHeaderTimeout; got != 100*time.Millisecond {
		t.Errorf("ResponseHeaderTimeout=%v，期望 100ms", got)
	}
	if rt.transportFor(rNone) != sharedTransport {
		t.Error("未配超时的路由应走全局 sharedTransport 单例")
	}
}

// T5a Duration JSON 往返：字符串 ↔ 结构体
func TestDuration_JSONRoundTrip(t *testing.T) {
	var rt Route
	blob := []byte(`{"prefix":"/a/","host":"h","port":1,"response_header_timeout":"10s"}`)
	if err := json.Unmarshal(blob, &rt); err != nil {
		t.Fatalf("Unmarshal 字符串 duration: %v", err)
	}
	if rt.ResponseHeaderTimeout != Duration(10*time.Second) {
		t.Errorf("ResponseHeaderTimeout=%v，期望 10s", rt.ResponseHeaderTimeout)
	}
	out, err := json.Marshal(rt)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"response_header_timeout":"10s"`) {
		t.Errorf("Marshal 输出缺 duration 字段：%s", out)
	}
}

// T5b Duration 接受纳秒数字（兼容旧数据与在线 API 的裸数字）
func TestDuration_JSONNumber(t *testing.T) {
	var rt Route
	blob := []byte(`{"prefix":"/a/","host":"h","port":1,"response_header_timeout":10000000000}`)
	if err := json.Unmarshal(blob, &rt); err != nil {
		t.Fatalf("Unmarshal 数字 duration: %v", err)
	}
	if rt.ResponseHeaderTimeout != Duration(10*time.Second) {
		t.Errorf("ResponseHeaderTimeout=%v，期望 10s", rt.ResponseHeaderTimeout)
	}
}

// T5c 无效 duration 字符串报错
func TestDuration_JSONInvalid(t *testing.T) {
	var rt Route
	blob := []byte(`{"prefix":"/a/","host":"h","port":1,"response_header_timeout":"abc"}`)
	if err := json.Unmarshal(blob, &rt); err == nil {
		t.Error("\"abc\" 应报错，却解析成功了")
	}
}

// T5d validRoute 边界：负数/超 5m 拒绝，0 与 5m 放行
func TestDuration_ValidRouteBounds(t *testing.T) {
	base := func(d Duration) Route {
		return Route{Prefix: "/a/", Host: "h", Port: 1, ResponseHeaderTimeout: d}
	}
	cases := []struct {
		name string
		rt   Route
		want bool
	}{
		{"负数拒绝", base(Duration(-time.Second)), false},
		{"超 5m 拒绝", base(Duration(6 * time.Minute)), false},
		{"0 放行", base(0), true},
		{"5m 边界放行", base(Duration(5 * time.Minute)), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := validRoute(&tc.rt); got != tc.want {
				t.Errorf("validRoute = %v，期望 %v", got, tc.want)
			}
		})
	}
}

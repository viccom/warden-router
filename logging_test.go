package main

// 访问日志中间件测试（TDD 第一批 · 步骤1）。
// A1-A8 对应 IMPLEMENTATION-PLAN.md §1.3。

import (
	"bufio"
	"bytes"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A1/A3 隐式 200 与字节累计
func TestStatusRecorder_Implicit200AndBytes(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	n, err := rec.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	n, _ = rec.Write([]byte("!"))
	if rec.status != http.StatusOK {
		t.Errorf("status=%d，期望 200（隐式）", rec.status)
	}
	if rec.bytes != 6 {
		t.Errorf("bytes=%d，期望 6", rec.bytes)
	}
}

// A2 显式状态码（含 502 错误路径）
func TestStatusRecorder_ExplicitCode(t *testing.T) {
	for _, code := range []int{204, 301, 404, 502} {
		rec := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
		rec.WriteHeader(code)
		if rec.status != code {
			t.Errorf("WriteHeader(%d) 后 status=%d", code, rec.status)
		}
	}
}

// A4 Hijack 透传：下游支持 Hijack 时必须成功，否则 WS 全灭
func TestStatusRecorder_HijackPassthrough(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("loggingMiddleware 丢了 Hijacker 能力——WS 会全灭")
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			t.Errorf("Hijack: %v", err)
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HIJACK-OK\r\n")
		_ = buf.Flush()
	})
	srv := httptest.NewServer(loggingMiddleware(h))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET /x HTTP/1.1\r\nHost: x\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(line, "HIJACK-OK") {
		t.Errorf("hijack 响应 = %q, err=%v", line, err)
	}
}

// A5 Flush 透传：SSE/流式不能卡
func TestStatusRecorder_FlushPassthrough(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	// httptest.Recorder 实现了 Flusher；能调通即透传链没断
	rec.Flush()
}

// A6 Unwrap 供 http.ResponseController 穿透
func TestStatusRecorder_Unwrap(t *testing.T) {
	inner := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: inner}
	if rec.Unwrap() != inner {
		t.Error("Unwrap 未返回原始 ResponseWriter")
	}
}

// syncBuf 是并发安全的日志捕获缓冲：日志由服务端 goroutine 写入，
// 测试 goroutine 轮询读取，无锁会被 -race 抓。
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// A7 日志行含关键字段（log 输出捕获）
//
// 时序说明：http.Get 收到响应头即返回，而服务端 handler 返回后才打印
// 日志，两者没有 happens-before 保证，必须轮询等待而非直接读。
func TestLoggingMiddleware_LogFields(t *testing.T) {
	sb := &syncBuf{}
	log.SetOutput(sb)
	defer log.SetOutput(os.Stderr)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	})
	srv := httptest.NewServer(loggingMiddleware(h))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/nope")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	deadline := time.Now().Add(3 * time.Second)
	var line string
	for time.Now().Before(deadline) {
		line = sb.String()
		if strings.Contains(line, "[access]") {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	for _, want := range []string{"[access]", "GET", "/nope", "404", "route=-"} {
		if !strings.Contains(line, want) {
			t.Errorf("日志行缺少 %q：%s", want, line)
		}
	}
}

// A8 WS 握手经 loggingMiddleware 仍 101（守 Hijack 透传的集成面）
func TestLoggingMiddleware_WSPassthrough(t *testing.T) {
	// 上游：同 D10 的 origin 校验 + 101
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
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = buf.Flush()
		time.Sleep(50 * time.Millisecond)
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
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(line, "101") {
		t.Errorf("WS 经 loggingMiddleware 状态行 = %q，期望 101", line)
	}
}

package main

// host_fix 测试（2026-10-15）。
//
// 背景：artifact release 发布通道的平台网关（CloudStudio Gateway）会把
// 入站请求的 Host 改写为内部寻址 Host
// （9000-<space-key>.e2b.<region>.sandbox.cloudstudio.club），且
// X-Forwarded-Host 被一并改写、不保留浏览器原值（2026-10-15 公网
// 干净实验实锤：curl 以发布域名发出，kula 收到的 Host 是网关形态）。
// 上游 kula 的 WS 同源校验拿 Origin 与 Host 比对，必然 403。
//
// host_fix 与 auth_bridge 同构：恢复被网关破坏的请求语义。配了
// public_host 且入站 Host 确为网关形态时改写为对外域名；其余情况
// 原样透传（含未配置与本地访问）。

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// isGatewayHost 纯函数表
// ---------------------------------------------------------------------------

func TestIsGatewayHost(t *testing.T) {
	cases := []struct {
		name string
		host string
		want bool
	}{
		{"实测网关形态 gz2", "9000-3b000f6ccabc4cd0ad2c77a3285711c6.e2b.gz2.sandbox.cloudstudio.club", true},
		{"实测网关形态 sh3", "9000-3b000f6ccabc4cd0ad2c77a3285711c6.e2b.sh3.sandbox.cloudstudio.club", true},
		{"其他端口与 space-key", "1234-abcdef0123456789abcdef0123456789.e2b.gz2.sandbox.cloudstudio.club", true},
		{"带端口（剥端口后匹配）", "9000-3b000f6ccabc4cd0ad2c77a3285711c6.e2b.gz2.sandbox.cloudstudio.club:443", true},
		{"发布域名", "ad8584f64ca039337.app.workbuddy.host", false},
		{"回环", "127.0.0.1:9000", false},
		{"localhost", "localhost:9000", false},
		{"普通域名", "example.com", false},
		{"空", "", false},
		{"前缀非端口段", "evil-9000-3b000f6ccabc4cd0ad2c77a3285711c6.e2b.gz2.sandbox.cloudstudio.club", false},
		{"hex 段太短", "9000-xyz.e2b.gz2.sandbox.cloudstudio.club", false},
		{"后缀被拼接逃逸", "9000-3b000f6ccabc4cd0ad2c77a3285711c6.e2b.gz2.sandbox.cloudstudio.club.evil.com", false},
		{"大小写混合（域名不分区大小写，但网关段固定小写）", "9000-3B000F6CCABC4CD0AD2C77A3285711C6.e2b.gz2.sandbox.cloudstudio.club", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isGatewayHost(tc.host); got != tc.want {
				t.Errorf("isGatewayHost(%q) = %v，期望 %v", tc.host, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 集成：host_fix 经完整代理链（handleAll + sharedProxy）
// ---------------------------------------------------------------------------

// hostFixChain 组装完整链路：上游记录收到的 Host，路由带 PublicHost。
// 返回 (代理基址, 上游收到的 Host 指针)。
func hostFixChain(t *testing.T, prefix, publicHost string) (*httptest.Server, *string) {
	t.Helper()
	var seenHost string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(up.Close)
	host, port := hostPort(t, up.URL)

	tb := NewRouteTable()
	tb.SetStatic([]*Route{{
		Prefix: prefix, Host: host, Port: port, Mode: ModeKeep,
		Name: "app", PublicHost: publicHost,
	}})
	t.Cleanup(swapTable(tb))

	srv := httptest.NewServer(recoverMiddleware(loggingMiddleware(http.HandlerFunc(handleAll))))
	t.Cleanup(srv.Close)
	return srv, &seenHost
}

// H1 网关形态 Host + 配了 public_host → 上游收到对外域名
// （kula Origin 校验 Host==Origin 自然通过，无需白名单）
func TestHostFix_GatewayHostRewritten(t *testing.T) {
	const gw = "9000-3b000f6ccabc4cd0ad2c77a3285711c6.e2b.gz2.sandbox.cloudstudio.club"
	srv, seen := hostFixChain(t, "/monitor/", "ad8584f64ca039337.app.workbuddy.host")

	req, _ := http.NewRequest("GET", srv.URL+"/monitor/api/config", nil)
	req.Host = gw // 模拟平台网关改写后的入站 Host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if *seen != "ad8584f64ca039337.app.workbuddy.host" {
		t.Errorf("上游收到 Host = %q，期望改写为 %q", *seen, "ad8584f64ca039337.app.workbuddy.host")
	}
}

// H2 未配 public_host → 网关形态 Host 原样透传（存量行为不变）
func TestHostFix_NoConfig_Passthrough(t *testing.T) {
	const gw = "9000-3b000f6ccabc4cd0ad2c77a3285711c6.e2b.gz2.sandbox.cloudstudio.club"
	srv, seen := hostFixChain(t, "/monitor/", "")

	req, _ := http.NewRequest("GET", srv.URL+"/monitor/api/config", nil)
	req.Host = gw
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if *seen != gw {
		t.Errorf("上游收到 Host = %q，期望原样透传 %q", *seen, gw)
	}
}

// H3 配了 public_host 但入站 Host 非网关形态（本地/直连）→ 不误改
func TestHostFix_NonGatewayHostUntouched(t *testing.T) {
	srv, seen := hostFixChain(t, "/monitor/", "ad8584f64ca039337.app.workbuddy.host")

	resp, err := http.Get(srv.URL + "/monitor/api/config") // req.Host = 127.0.0.1:port
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if *seen == "ad8584f64ca039337.app.workbuddy.host" {
		t.Errorf("本地访问被误改写为对外域名：%q", *seen)
	}
	if *seen == "" {
		t.Errorf("上游未收到 Host")
	}
}

// H4 fixedHost 组合表（含 nil 路由安全）
func TestFixedHost(t *testing.T) {
	const gw = "9000-3b000f6ccabc4cd0ad2c77a3285711c6.e2b.gz2.sandbox.cloudstudio.club"
	cases := []struct {
		name, in, public, want string
	}{
		{"配了+网关形态→改写", gw, "app.example.com", "app.example.com"},
		{"没配+网关形态→透传", gw, "", gw},
		{"配了+普通Host→透传", "127.0.0.1:9000", "app.example.com", "127.0.0.1:9000"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &Route{PublicHost: tc.public}
			if got := fixedHost(tc.in, rt); got != tc.want {
				t.Errorf("fixedHost(%q, %q) = %q，期望 %q", tc.in, tc.public, got, tc.want)
			}
		})
	}
	// nil 路由不得 panic
	if got := fixedHost(gw, nil); got != gw {
		t.Errorf("fixedHost(%q, nil) = %q，期望透传", gw, got)
	}
}

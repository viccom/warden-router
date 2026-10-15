package main

// routes.toml 声明式路由测试（TDD 第二批 · 步骤6，F1-F8，IMPLEMENTATION-PLAN.md §2.3）。
//
// 严格 TOML 子集解析器：F1 黄金文件 / F2 致命语法错误带行号 /
// F3 条目级问题逐条跳过 / F4 重复 prefix。

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// F1 黄金文件：全字段 + 注释 + 两种 mode + duration
func TestParseRoutesFile_Golden(t *testing.T) {
	toml := `# 静态路由声明文件（黄金用例）
# 与 config.go 的 staticRoutes() 合并，同前缀本文件优先。

[[route]]
prefix = "/wiki/"
host = "127.0.0.1"
port = 8080
mode = "strip"
display = "内部 Wiki"
desc = "Bookstack"
icon = "📚"

[[route]]
prefix = "/term/"
host = "127.0.0.1"
port = 27970
mode = "keep"
response_header_timeout = "10s"
`
	res, err := parseRoutes([]byte(toml))
	if err != nil {
		t.Fatalf("黄金文件应解析成功: %v", err)
	}
	if len(res.Routes) != 2 {
		t.Fatalf("解析出 %d 条，期望 2 条", len(res.Routes))
	}
	if len(res.Warnings) != 0 {
		t.Errorf("黄金文件不应有 warning：%v", res.Warnings)
	}
	w := res.Routes[0]
	if w.Prefix != "/wiki/" || w.Host != "127.0.0.1" || w.Port != 8080 || w.Mode != ModeStrip {
		t.Errorf("route[0] 基本字段错：%+v", w)
	}
	if w.Display != "内部 Wiki" || w.Desc != "Bookstack" || w.Icon != "📚" {
		t.Errorf("route[0] 展示字段错：%+v", w)
	}
	if w.ResponseHeaderTimeout != 0 {
		t.Errorf("route[0] 未配超时应为 0，得到 %v", w.ResponseHeaderTimeout)
	}
	term := res.Routes[1]
	if term.Prefix != "/term/" || term.Port != 27970 || term.Mode != ModeKeep {
		t.Errorf("route[1] 错：%+v", term)
	}
	if term.ResponseHeaderTimeout != Duration(10*time.Second) {
		t.Errorf("route[1] 超时=%v，期望 10s", term.ResponseHeaderTimeout)
	}
}

// F2 致命语法错误：一律报错且带行号（整版拒绝的依据）
func TestParseRoutesFile_FatalSyntax(t *testing.T) {
	cases := []struct {
		name string
		toml string
		want string // 错误信息须包含的子串（含"第 N 行"时校验行号）
	}{
		{"缺等号", "[[route]]\nprefix \"/x/\"\n", "第 2 行"},
		{"未闭合引号", "[[route]]\ndisplay = \"未闭合\n", "第 2 行"},
		{"坏 duration", "[[route]]\nprefix = \"/x/\"\nresponse_header_timeout = \"abc\"\n", "第 3 行"},
		{"错误表名", "[[routes]]\n", "第 1 行"},
		{"单表语法", "[route]\n", "第 1 行"},
		{"表外键值", "prefix = \"/x/\"\n", "第 1 行"},
		{"未加引号的字符串", "[[route]]\nprefix = /x/\n", "第 2 行"},
		{"坏转义", "[[route]]\ndisplay = \"a\\qb\"\n", "第 2 行"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRoutes([]byte(tc.toml))
			if err == nil {
				t.Fatalf("应报错：%q", tc.toml)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("错误 %q 不含 %q", err, tc.want)
			}
		})
	}
}

// F3 条目级问题：逐条报错跳过，其余保留
func TestParseRoutesFile_EntryLevelSkip(t *testing.T) {
	toml := `[[route]]
prefix = "/good/"
host = "127.0.0.1"
port = 8080
mode = "strip"

[[route]]
host = "127.0.0.1"
port = 8080
mode = "strip"

[[route]]
prefix = "/badport/"
host = "127.0.0.1"
port = 99999
mode = "strip"

[[route]]
prefix = "/badmode/"
host = "127.0.0.1"
port = 8080
mode = "bogus"
`
	res, err := parseRoutes([]byte(toml))
	if err != nil {
		t.Fatalf("条目级问题不应整版拒绝: %v", err)
	}
	if len(res.Routes) != 1 || res.Routes[0].Prefix != "/good/" {
		t.Fatalf("应只保留 /good/，得到 %+v", res.Routes)
	}
	if len(res.Warnings) != 3 {
		t.Fatalf("应有 3 条 warning，得到 %d 条：%v", len(res.Warnings), res.Warnings)
	}
	for _, w := range res.Warnings {
		if !strings.Contains(w, "第 ") || !strings.Contains(w, " 行") {
			t.Errorf("warning 缺行号：%q", w)
		}
	}
}

// F4 重复 prefix：报错跳过后者
func TestParseRoutesFile_DuplicatePrefix(t *testing.T) {
	toml := `[[route]]
prefix = "/dup/"
host = "127.0.0.1"
port = 8080

[[route]]
prefix = "/dup/"
host = "127.0.0.1"
port = 9090
`
	res, err := parseRoutes([]byte(toml))
	if err != nil {
		t.Fatalf("重复 prefix 不应整版拒绝: %v", err)
	}
	if len(res.Routes) != 1 {
		t.Fatalf("应只有 1 条（后者跳过），得到 %d 条", len(res.Routes))
	}
	if res.Routes[0].Port != 8080 {
		t.Errorf("后者胜出了：port=%d，期望保留前者的 8080", res.Routes[0].Port)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "重复") {
		t.Errorf("应有 1 条『重复』warning：%v", res.Warnings)
	}
}

// parseRoutesFile 从磁盘读并解析（watcher 与测试共用入口）。
func TestParseRoutesFile_FromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "routes.toml")
	if err := os.WriteFile(path, []byte("[[route]]\nprefix = \"/d/\"\nhost = \"h\"\nport = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := parseRoutesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Routes) != 1 || res.Routes[0].Prefix != "/d/" {
		t.Errorf("磁盘解析结果异常：%+v", res.Routes)
	}
}

// ---------------------------------------------------------------------------
// 合并与热加载（F5-F8）
// ---------------------------------------------------------------------------

const tomlV1 = `[[route]]
prefix = "/a/"
host = "127.0.0.1"
port = 1111
mode = "strip"
`

const tomlV2 = `[[route]]
prefix = "/a/"
host = "127.0.0.1"
port = 2222
mode = "keep"
`

// F5 MergeFileRoutes 优先级：同前缀 file 覆盖 code static；
// Lookup/Cards/Snapshot 三视图一致。
func TestMergeFileRoutes_Priority(t *testing.T) {
	tb := NewRouteTable()
	tb.SetStatic([]*Route{{Prefix: "/a/", Host: "code", Port: 1, Mode: ModeStrip, Name: "code"}})
	tb.MergeFileRoutes([]*Route{
		{Prefix: "/a/", Host: "file", Port: 2, Mode: ModeKeep, Name: "file"},
	})

	rt, ok := tb.Lookup("/a/x")
	if !ok {
		t.Fatal("Lookup(/a/x) 未命中")
	}
	if rt.Host != "file" || rt.Port != 2 || rt.Mode != ModeKeep {
		t.Errorf("file 未覆盖 code：%+v", rt)
	}
	snap := tb.Snapshot()
	counts := snap["counts"].(map[string]int)
	if counts["static"] != 1 {
		t.Errorf("static 计数=%d，期望 1（覆盖而非新增）", counts["static"])
	}
	cards := tb.Cards()
	if len(cards) != 1 || cards[0].Port != 2 {
		t.Errorf("Cards 与 Lookup 不一致：%+v", cards)
	}
}

// F6 热加载：改文件→reload 后表更新；删文件→回退仅 code static。
func TestFileRoutes_Reload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.toml")
	if err := os.WriteFile(path, []byte(tomlV1), 0o644); err != nil {
		t.Fatal(err)
	}
	defer swapTable(NewRouteTable())() // reload 内部以 staticRoutes() 为基线，先隔离
	fr := &fileRoutes{path: path}

	// 首次加载：file 生效 + code static 基线保留
	if err := fr.reload(); err != nil {
		t.Fatalf("首次 reload: %v", err)
	}
	rt, ok := table.Lookup("/a/x")
	if !ok || rt.Port != 1111 {
		t.Fatalf("file 路由未生效：%+v ok=%v", rt, ok)
	}
	if _, ok := table.Lookup("/monitor/"); !ok {
		t.Error("code static 基线丢失（/monitor/ 应来自 staticRoutes()）")
	}

	// 改文件：内容更新
	if err := os.WriteFile(path, []byte(tomlV2), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fr.reload(); err != nil {
		t.Fatalf("二次 reload: %v", err)
	}
	rt, ok = table.Lookup("/a/x")
	if !ok || rt.Port != 2222 || rt.Mode != ModeKeep {
		t.Errorf("热加载未更新：%+v ok=%v", rt, ok)
	}

	// 删文件：回退仅 code static
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := fr.reload(); err != nil {
		t.Fatalf("删文件后 reload 不应报错: %v", err)
	}
	if _, ok := table.Lookup("/a/x"); ok {
		t.Error("删文件后 /a/ 应消失")
	}
	if _, ok := table.Lookup("/monitor/"); !ok {
		t.Error("删文件后 code static 应保留")
	}
}

// F7 损坏文件：保留上一版好数据，reload 返回错误（不清空、不退出）。
func TestFileRoutes_CorruptKeepsPrevious(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.toml")
	if err := os.WriteFile(path, []byte(tomlV1), 0o644); err != nil {
		t.Fatal(err)
	}
	defer swapTable(NewRouteTable())()
	fr := &fileRoutes{path: path}
	if err := fr.reload(); err != nil {
		t.Fatalf("首次 reload: %v", err)
	}

	// 写入语法损坏的文件
	if err := os.WriteFile(path, []byte("[[route\nprefix = \"/x/\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fr.reload(); err == nil {
		t.Fatal("损坏文件应返回错误")
	}
	// 上一版好数据必须原样保留
	rt, ok := table.Lookup("/a/x")
	if !ok || rt.Port != 1111 {
		t.Errorf("上一版数据被冲掉：%+v ok=%v", rt, ok)
	}
}

// F8 SIGHUP 触发同一 reload 函数（真实信号，验证运维最常用路径）。
func TestFileRoutes_SIGHUP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.toml")
	if err := os.WriteFile(path, []byte(tomlV1), 0o644); err != nil {
		t.Fatal(err)
	}
	defer swapTable(NewRouteTable())()
	fr := &fileRoutes{path: path}
	if err := fr.reload(); err != nil {
		t.Fatalf("首次 reload: %v", err)
	}

	stop := make(chan struct{})
	defer close(stop)
	fr.handleSignals(stop) // 同步调用：Notify 在返回前已完成注册

	// 改文件后发 SIGHUP，应立即重载生效
	if err := os.WriteFile(path, []byte(tomlV2), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if rt, ok := table.Lookup("/a/x"); ok && rt.Port == 2222 {
			return // SIGHUP 重载生效
		}
		if time.Now().After(deadline) {
			rt, _ := table.Lookup("/a/x")
			t.Fatalf("SIGHUP 未触发热加载（当前 /a/ = %+v）", rt)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// hidden = true 使路由代理保留但不进导航宫格（与 code static 的 Hidden 一致）；
// 非布尔字面量属值级解析错误，与字符串字段引号错误一致按致命语法错误处理。
func TestParseRoutesFile_Hidden(t *testing.T) {
	toml := `[[route]]
prefix = "/vnts-admin/"
host = "127.0.0.1"
port = 39871
mode = "strip"
display = "VNT 管理台"

[[route]]
prefix = "/speed/"
host = "127.0.0.1"
port = 8800
mode = "strip"
hidden = true

[[route]]
prefix = "/keep/"
host = "127.0.0.1"
port = 8082
hidden = false
`
	res, err := parseRoutes([]byte(toml))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(res.Routes) != 3 {
		t.Fatalf("解析出 %d 条，期望 3 条", len(res.Routes))
	}
	if res.Routes[0].Hidden {
		t.Errorf("未写 hidden 的条目应默认 false")
	}
	if !res.Routes[1].Hidden {
		t.Errorf("hidden = true 应生效")
	}
	if res.Routes[2].Hidden {
		t.Errorf("hidden = false 应显式关闭")
	}
	if len(res.Warnings) != 0 {
		t.Errorf("不应有 warning：%v", res.Warnings)
	}

	bad := `[[route]]
prefix = "/bad/"
host = "127.0.0.1"
port = 8081
hidden = "yes"
`
	if _, err := parseRoutes([]byte(bad)); err == nil {
		t.Errorf("hidden = \"yes\" 应为致命语法错误")
	}
}

// AB1 auth_bridge / auth_bridge_scheme 解析（含隐式启用与致命错误）
func TestParseRoutesFile_AuthBridge(t *testing.T) {
	toml := `[[route]]
prefix = "/api/"
host = "127.0.0.1"
port = 39871
mode = "keep"
auth_bridge = true
auth_bridge_scheme = "Bearer"
auth_bridge_cookie = "_wrauth-vnts"

[[route]]
prefix = "/openlist/"
host = "127.0.0.1"
port = 5244
mode = "keep"
auth_bridge = true
auth_bridge_scheme = ""

[[route]]
prefix = "/plain/"
host = "127.0.0.1"
port = 8080
auth_bridge = false

[[route]]
prefix = "/implicit/"
host = "127.0.0.1"
port = 8081
auth_bridge_scheme = "Bearer"
`
	res, err := parseRoutes([]byte(toml))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(res.Routes) != 4 || len(res.Warnings) != 0 {
		t.Fatalf(" Routes=%d Warnings=%v", len(res.Routes), res.Warnings)
	}
	if res.Routes[0].AuthBridge == nil || res.Routes[0].AuthBridge.Scheme != "Bearer" {
		t.Errorf("route[0] auth_bridge 错：%+v", res.Routes[0].AuthBridge)
	}
	if res.Routes[0].AuthBridge.CookieName != "_wrauth-vnts" {
		t.Errorf("route[0] cookie 名错：%+v", res.Routes[0].AuthBridge)
	}
	if res.Routes[1].AuthBridge == nil || res.Routes[1].AuthBridge.Scheme != "" {
		t.Errorf("route[1] 应启用且 scheme 为空串（原样 token）：%+v", res.Routes[1].AuthBridge)
	}
	if res.Routes[2].AuthBridge != nil {
		t.Errorf("route[2] auth_bridge=false 应为 nil")
	}
	if res.Routes[3].AuthBridge == nil || res.Routes[3].AuthBridge.Scheme != "Bearer" {
		t.Errorf("route[3] 配 scheme 应隐式启用：%+v", res.Routes[3].AuthBridge)
	}

	bads := []struct{ name, toml, want string }{
		{"布尔拼错", "[[route]]\nprefix = \"/x/\"\nauth_bridge = \"yes\"\n", "第 3 行"},
		{"scheme 带空格", "[[route]]\nprefix = \"/x/\"\nauth_bridge_scheme = \"Two Words\"\n", "第 3 行"},
		{"scheme 未加引号", "[[route]]\nprefix = \"/x/\"\nauth_bridge_scheme = Bearer\n", "第 3 行"},
		{"cookie 名带分号", "[[route]]\nprefix = \"/x/\"\nauth_bridge_cookie = \"a;b\"\n", "第 3 行"},
	}
	for _, tc := range bads {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRoutes([]byte(tc.toml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("应报致命错误（含 %q），得到 %v", tc.want, err)
			}
		})
	}
}

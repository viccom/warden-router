package main

// routes.toml 声明式路由 + 热加载（TDD 第二批 · 步骤6，F1-F8，
// IMPLEMENTATION-PLAN.md §2.3）。
//
// 定位：operator 面向的静态路由声明文件，与 config.go 的 staticRoutes()
// 合并，同前缀本文件优先。保存后 5s 内热加载；kill -HUP 立即重载；
// 语法错误整版拒绝并保留上一版。
//
// 解析器是**严格 TOML 子集**（刻意收窄，不做通用 TOML）：
//   - 仅 # 注释、[[route]] 数组表、key = value；
//   - 值为双引号字符串（\" \\ \n 转义）或裸整数；
//   - 子集外一律返回带行号的致命错误。
// 分界：值格式错误（引号/转义/数字/duration）= 致命，整版拒绝；
// 条目语义问题（缺字段/越界/mode 非法/重复 prefix）= 条目级跳过，
// 进 Warnings，其余条目保留。

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// parseResult 解析产物：Routes 为成功条目，Warnings 为被跳过条目的
// 带行号原因（不阻断加载）。
type parseResult struct {
	Routes   []*Route
	Warnings []string
}

// parseRoutesFile 读盘并解析。error 仅表示文件 IO 失败；
// 语法致命错误由 parseRoutes 返回（watcher 据此保留上一版）。
func parseRoutesFile(path string) (*parseResult, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseRoutes(blob)
}

// parseRoutes 解析 routes.toml 严格子集。
func parseRoutes(blob []byte) (*parseResult, error) {
	res := &parseResult{}
	var (
		cur     *Route
		curLine int
		seen    = map[string]bool{}
	)
	flush := func() {
		if cur == nil {
			return
		}
		if err := validateFileRoute(cur, curLine); err != nil {
			res.Warnings = append(res.Warnings, err.Error())
			cur = nil
			return
		}
		if seen[cur.Prefix] {
			res.Warnings = append(res.Warnings,
				fmt.Sprintf("第 %d 行：prefix %q 重复，后者已跳过", curLine, cur.Prefix))
			cur = nil
			return
		}
		seen[cur.Prefix] = true
		res.Routes = append(res.Routes, cur)
		cur = nil
	}

	for i, raw := range strings.Split(string(blob), "\n") {
		lineNo := i + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[[") {
			if line != "[[route]]" {
				return nil, fmt.Errorf("第 %d 行：仅支持 [[route]] 数组表，得到 %q", lineNo, line)
			}
			flush()
			cur = &Route{Mode: ModeStrip}
			curLine = lineNo
			continue
		}
		if strings.HasPrefix(line, "[") {
			return nil, fmt.Errorf("第 %d 行：不支持 [table] 语法（仅接受 [[route]]）：%q", lineNo, line)
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			return nil, fmt.Errorf("第 %d 行：缺少 '='：%q", lineNo, strings.TrimSpace(raw))
		}
		if cur == nil {
			return nil, fmt.Errorf("第 %d 行：key = value 出现在 [[route]] 之外", lineNo)
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if err := applyRouteField(cur, key, val, lineNo); err != nil {
			return nil, err
		}
	}
	flush()
	return res, nil
}

// applyRouteField 把单个 key = value 写进当前 Route。
func applyRouteField(rt *Route, key, val string, lineNo int) error {
	switch key {
	case "prefix", "host", "display", "desc", "icon", "mode":
		s, err := parseTomlString(val, lineNo, key)
		if err != nil {
			return err
		}
		switch key {
		case "prefix":
			rt.Prefix = s
		case "host":
			rt.Host = s
		case "display":
			rt.Display = s
		case "desc":
			rt.Desc = s
		case "icon":
			rt.Icon = s
		case "mode":
			rt.Mode = parseModeName(s) // 非法值留待 validateFileRoute 条目级拒绝
		}
	case "hidden":
		// 布尔裸字面量（true/false）；其他值按条目级 warning 跳过，
		// 避免拼错（如 "yes"）静默改变行为
		switch val {
		case "true":
			rt.Hidden = true
		case "false":
			rt.Hidden = false
		default:
			return fmt.Errorf("第 %d 行：hidden 必须是 true/false，得到 %q", lineNo, val)
		}
	case "port":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("第 %d 行：port 必须是整数，得到 %q", lineNo, val)
		}
		rt.Port = n
	case "response_header_timeout":
		s, err := parseTomlString(val, lineNo, key)
		if err != nil {
			return err
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return fmt.Errorf("第 %d 行：response_header_timeout 不是合法 duration：%q", lineNo, s)
		}
		rt.ResponseHeaderTimeout = Duration(d)
	case "auth_bridge":
		// 授权头桥接开关（布尔裸字面量，同 hidden 的严格性）
		switch val {
		case "true":
			rt.AuthBridge = &AuthBridge{}
		case "false":
			rt.AuthBridge = nil
		default:
			return fmt.Errorf("第 %d 行：auth_bridge 必须是 true/false，得到 %q", lineNo, val)
		}
	case "auth_bridge_scheme":
		// 恢复 Authorization 头的前缀："Bearer" 或 ""（原样 token）。
		// 隐式启用桥接（配了 scheme 即视为 auth_bridge = true），
		// 免得两个键必须成对出现。
		s, err := parseTomlString(val, lineNo, key)
		if err != nil {
			return err
		}
		if !validAuthBridgeScheme(s) {
			return fmt.Errorf("第 %d 行：auth_bridge_scheme 含非法字符（空格/控制字符/非 ASCII）：%q", lineNo, s)
		}
		if rt.AuthBridge == nil {
			rt.AuthBridge = &AuthBridge{}
		}
		rt.AuthBridge.Scheme = s
	case "auth_bridge_cookie":
		// 桥接 cookie 名。发布网关会把 Set-Cookie 的 Path 统一改成 "/"，
		// 多路由桥接时同名 cookie 互相覆盖，故按路由配不同名。
		// 同样隐式启用桥接。
		s, err := parseTomlString(val, lineNo, key)
		if err != nil {
			return err
		}
		if !validAuthBridgeCookieName(s) {
			return fmt.Errorf("第 %d 行：auth_bridge_cookie 含非法字符（分隔符/控制字符/非 ASCII）：%q", lineNo, s)
		}
		if rt.AuthBridge == nil {
			rt.AuthBridge = &AuthBridge{}
		}
		rt.AuthBridge.CookieName = s
	case "auth_bridge_token":
		// 静态注入的 token（warden 类无登录 API 的上游）。与
		// auth_bridge_gate/gate_key 成三件套，缺一由 validateFileRoute
		// 条目级拒绝。隐式启用桥接。
		s, err := parseTomlString(val, lineNo, key)
		if err != nil {
			return err
		}
		if !validStaticToken(s) {
			return fmt.Errorf("第 %d 行：auth_bridge_token 含非法字符（空格/控制字符/非 ASCII）或为空/超长：%q", lineNo, s)
		}
		if rt.AuthBridge == nil {
			rt.AuthBridge = &AuthBridge{}
		}
		rt.AuthBridge.Token = s
	case "auth_bridge_gate":
		// 门控路径（绝对路径，须落在本路由前缀内——语义校验在
		// validateFileRoute）。隐式启用桥接。
		s, err := parseTomlString(val, lineNo, key)
		if err != nil {
			return err
		}
		if !validGatePath(s) {
			return fmt.Errorf("第 %d 行：auth_bridge_gate 须为以 / 开头的绝对路径（可见 ASCII、不超过 %d 字符）：%q", lineNo, maxGatePathLen, s)
		}
		if rt.AuthBridge == nil {
			rt.AuthBridge = &AuthBridge{}
		}
		rt.AuthBridge.GatePath = s
	case "auth_bridge_gate_key":
		// 门控密钥（URL 安全字符集，16-128 位）。隐式启用桥接。
		s, err := parseTomlString(val, lineNo, key)
		if err != nil {
			return err
		}
		if !validGateKey(s) {
			return fmt.Errorf("第 %d 行：auth_bridge_gate_key 须为 %d-%d 位 URL 安全字符 [A-Za-z0-9_-]：%q", lineNo, minGateKeyLen, maxGateKeyLen, s)
		}
		if rt.AuthBridge == nil {
			rt.AuthBridge = &AuthBridge{}
		}
		rt.AuthBridge.GateKey = s
	case "public_host":
		// 对外 Host 修复目标（host_fix，见 hostfix.go）：入站 Host 为
		// 发布网关寻址形态时改写为此外域名（== 浏览器 Origin），让
		// 上游的 Origin 同源校验自然通过。合法 hostname，禁 URL 形态。
		s, err := parseTomlString(val, lineNo, key)
		if err != nil {
			return err
		}
		if !validPublicHost(s) {
			return fmt.Errorf("第 %d 行：public_host 不是合法 hostname（仅字母/数字/点/横线，禁 scheme/path/端口）：%q", lineNo, s)
		}
		rt.PublicHost = s
	case "host_fix_origin":
		// 以请求 Origin 头恢复上游 Host（host_fix 的 Trae 变体，见
		// hostfix.go）：入站 Host 被改写成对本机地址、公网域名每会话
		// 动态不可静态配置时，用浏览器 Origin（公网域名）还原上游 Host。
		// 布尔裸字面量，同 hidden 的严格性。
		switch val {
		case "true":
			rt.HostFixOrigin = true
		case "false":
			rt.HostFixOrigin = false
		default:
			return fmt.Errorf("第 %d 行：host_fix_origin 必须是 true/false，得到 %q", lineNo, val)
		}
	default:
		return fmt.Errorf("第 %d 行：未知字段 %q（允许：prefix/host/port/mode/display/desc/icon/hidden/response_header_timeout/auth_bridge/auth_bridge_scheme/auth_bridge_cookie/auth_bridge_token/auth_bridge_gate/auth_bridge_gate_key/public_host/host_fix_origin）", lineNo, key)
	}
	return nil
}

// parseModeName 把 "strip"/"keep" 映射为 Mode；非法值返回 Mode(-1)
// （既非 ModeStrip 也非 ModeKeep，validateFileRoute 会条目级拒绝）。
func parseModeName(s string) Mode {
	switch s {
	case "strip":
		return ModeStrip
	case "keep":
		return ModeKeep
	default:
		return Mode(-1)
	}
}

// validateFileRoute 条目级校验。返回的错误即 warning 文本（含行号）。
func validateFileRoute(rt *Route, lineNo int) error {
	if _, ok := normalizePrefix(rt.Prefix); !ok {
		return fmt.Errorf("第 %d 行：prefix 缺失或非法（须以 / 开头和结尾、不能为 /、无空段）", lineNo)
	}
	if rt.Host == "" {
		return fmt.Errorf("第 %d 行：host 缺失", lineNo)
	}
	if rt.Port <= 0 || rt.Port > 65535 {
		return fmt.Errorf("第 %d 行：port 越界（1-65535），得到 %d", lineNo, rt.Port)
	}
	if rt.Mode != ModeStrip && rt.Mode != ModeKeep {
		return fmt.Errorf("第 %d 行：mode 须为 \"strip\" 或 \"keep\"", lineNo)
	}
	if rt.ResponseHeaderTimeout < 0 || rt.ResponseHeaderTimeout > Duration(maxRouteTimeout) {
		return fmt.Errorf("第 %d 行：response_header_timeout 越界（0-5m）", lineNo)
	}
	if rt.AuthBridge != nil && !validAuthBridgeScheme(rt.AuthBridge.Scheme) {
		return fmt.Errorf("第 %d 行：auth_bridge_scheme 含非法字符（空格/控制字符/非 ASCII）", lineNo)
	}
	if rt.AuthBridge != nil && !validAuthBridgeCookieName(rt.AuthBridge.CookieName) {
		return fmt.Errorf("第 %d 行：auth_bridge_cookie 含非法字符（分隔符/控制字符/非 ASCII）", lineNo)
	}
	if rt.AuthBridge != nil {
		if reason := authBridgeStaticReason(rt.AuthBridge, rt.Prefix); reason != "" {
			return fmt.Errorf("第 %d 行：%s", lineNo, reason)
		}
	}
	if rt.PublicHost != "" && !validPublicHost(rt.PublicHost) {
		return fmt.Errorf("第 %d 行：public_host 不是合法 hostname", lineNo)
	}
	return nil
}

// parseTomlString 解析双引号字符串值（支持 \" \\ \n 转义）。
func parseTomlString(s string, lineNo int, key string) (string, error) {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", fmt.Errorf("第 %d 行：%s 的值必须是双引号字符串，得到 %q", lineNo, key, s)
	}
	inner := s[1 : len(s)-1]
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(inner) {
			return "", fmt.Errorf("第 %d 行：%s 的值以孤立反斜杠结尾", lineNo, key)
		}
		switch inner[i] {
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		case 'n':
			b.WriteByte('\n')
		default:
			return "", fmt.Errorf("第 %d 行：不支持的转义序列 \\%c", lineNo, inner[i])
		}
	}
	return b.String(), nil
}

// ---------------------------------------------------------------------------
// 合并与热加载
// ---------------------------------------------------------------------------

// MergeFileRoutes 把 routes.toml 的路由合并进静态层：同前缀 file 覆盖
// code static（部署者意图：文件是显式声明，压过代码默认）。
// 只增覆盖，不清空——清空/重建由 reload 流程的 SetStatic 负责（防漂移）。
func (t *RouteTable) MergeFileRoutes(file []*Route) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, r := range file {
		p, ok := normalizePrefix(r.Prefix)
		if !ok {
			log.Printf("[route] 忽略 file 路由的非法前缀 %q", r.Prefix)
			continue
		}
		r.Prefix = p
		r.Source = "static" // file 层是静态层的扩展，导航/快照语义一致
		t.static[p] = r
	}
}

// fileRoutes 管理 routes.toml 的加载与热加载。
//
// table 依赖注入（2026-10-16 审查）：reload 原先直接读包级全局 table，
// 而测试的 swapTable 会并发替换该全局 → data race（SIGHUP goroutine 与
// 测试收尾并发）。改为持有构造时注入的实例引用：消除全局耦合，也让
// reload 语义与"操作哪张表"显式绑定。
type fileRoutes struct {
	path  string
	table *RouteTable
}

// reload 重读文件并生效。返回值语义（watcher/SIGHUP 共用）：
//   - nil：已生效（含文件缺失→回退仅 code static、条目级跳过）；
//   - 非 nil：语法致命错误，**表保持上一版不动**（响铃由调用方记）。
func (fr *fileRoutes) reload() error {
	res, err := parseRoutesFile(fr.path)
	if err != nil {
		if os.IsNotExist(err) {
			// 文件被删：回退到仅 code static
			fr.table.SetStatic(staticRoutes())
			log.Printf("[route] routes 文件不存在，回退仅代码静态路由：%s", fr.path)
			return nil
		}
		return err // 损坏/语法错误：保留上一版
	}
	// 先按 code static 重建（抹掉上一版 file 路由，防漂移），再合并新版
	fr.table.SetStatic(staticRoutes())
	fr.table.MergeFileRoutes(res.Routes)
	for _, w := range res.Warnings {
		log.Printf("[route] routes 文件警告：%s", w)
	}
	for _, w := range fr.table.GateShadowWarnings() {
		log.Printf("[route] 门控遮蔽告警：%s", w)
	}
	log.Printf("[route] routes 文件已生效：%d 条", len(res.Routes))
	return nil
}

// handleSignals 响应 SIGHUP：立即重载（与 watch 的 reload 是同一函数，
// 信号只是手动触发通道）。stop 为 nil 时只服务信号（生产接线）；
// 测试传入 stop channel 以回收 goroutine。
//
// signal.Notify **同步执行后立即返回**——注册在调用方 goroutine 完成，
// 杜绝"信号已到达但 handler 未注册"的竞态（那会走 SIGHUP 默认行为
// 直接终止进程）。处理循环放内部 goroutine，调用方无需 go 包装。
func (fr *fileRoutes) handleSignals(stop <-chan struct{}) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		defer signal.Stop(ch)
		for {
			select {
			case <-ch:
				if err := fr.reload(); err != nil {
					log.Printf("[route] SIGHUP 重载失败，保留上一版：%v", err)
				}
			case <-stop:
				return
			}
		}
	}()
}

// watch 轮询 mtime+size，变化即 reload。interval 必须 > 0。
func (fr *fileRoutes) watch(interval time.Duration) {
	if err := fr.reload(); err != nil {
		log.Printf("[route] routes 文件首次加载失败（继续以代码静态路由运行）：%v", err)
	}
	var lastMod time.Time
	var lastSize int64
	if st, err := os.Stat(fr.path); err == nil {
		lastMod, lastSize = st.ModTime(), st.Size()
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for range tick.C {
		st, err := os.Stat(fr.path)
		if err != nil {
			continue
		}
		if st.ModTime().Equal(lastMod) && st.Size() == lastSize {
			continue
		}
		lastMod, lastSize = st.ModTime(), st.Size()
		if err := fr.reload(); err != nil {
			log.Printf("[route] routes 文件重载失败，保留上一版：%v", err)
			continue
		}
	}
}

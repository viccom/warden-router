package main

// 路由表：并发安全的内存态路由注册中心。
//
// 设计要点（对应 Python 版的三类语义 + 新增的动态层）：
//
//	source=static    来自 PASSTHROUGH / STATIC_MOUNTS / BASE_PATH_MOUNTS（代码内写死）
//	source=discovered 来自 warden API 的 ui_url 约定（前缀剥离）
//	source=dynamic   来自在线管理 API / 本地 JSON（**本次新增**）
//
// 三类共存且**互不覆盖**：动态层用独立 map 存放，warden 轮询只写 discovered
// 槽位。若动态与前两类前缀冲突，静态层优先——写死配置是部署者意图，应压过
// 在线临时添加；同层内最长前缀匹配。
//
// 并发模型：
//   - mu (RWMutex)   保护三张 map 与 services 快照
//   - persistMu      串行化落盘，且落盘时**重新读取最新快照**，
//                     杜绝"先快照后落盘"导致的丢更新与 .tmp 交错写损坏
//
// 不可变性约定：Route 一经插入不再被修改字段（Source 仅在插入前设置）。
// Lookup 返回共享指针，读侧只读。若未来需要运行时改字段，必须先 copy-on-write。

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Mode 描述转发时对 URL 前缀的处理方式。
type Mode int

const (
	// ModeStrip 前缀剥离：/speed/x → /x（librespeed、自动发现类）
	ModeStrip Mode = iota
	// ModeKeep 前缀保留：/terminal/x → /terminal/x（ttyd -b、kula base_path）
	ModeKeep
)

// 前缀与展示字段的长度上限，防止超大输入造成内存/渲染问题。
const (
	maxPrefixLen = 256
	maxTextField = 512
)

// Route 单条挂载路由。插入后字段不可变（见上方并发模型）。
type Route struct {
	Prefix  string `json:"prefix"`  // 形如 "/speed/"（带尾斜杠，非 "/"）
	Host    string `json:"host"`    // 上游主机
	Port    int    `json:"port"`    // 上游端口 1-65535
	Mode    Mode   `json:"mode"`    // 0=剥离 1=保留
	Name    string `json:"name"`    // 服务名（导航卡片去重与健康查找依据）
	Display string `json:"display"` // 导航卡片标题
	Desc    string `json:"desc"`    // 导航卡片描述
	Icon    string `json:"icon"`    // 导航卡片图标（渲染时转义）
	Source  string `json:"source"`  // static | discovered | dynamic
	Health  string `json:"health"`  // healthy | unhealthy | unknown
	// Hidden 不在导航宫格页展示（如 /api/v1/、/backend/ 这类裸 API 透传，
	// 与 Python 版 PASSTHROUGH 同样不进首页）。转发与 Lookup 不受影响。
	Hidden bool `json:"hidden,omitempty"`
	// ResponseHeaderTimeout 每路由响应头超时。0=不设（默认）。
	// 不能用 context deadline（会掐死 WS/流式），由 routingTransport
	// 按路由选带 ResponseHeaderTimeout 的 http.Transport 实现。
	ResponseHeaderTimeout Duration `json:"response_header_timeout,omitempty"`
	// AuthBridge 授权头桥接（nil=不启用）。应对发布网关剥离客户端
	// Authorization 头的 workaround：登录响应种 cookie、请求侧恢复头。
	// 详见 authbridge.go。与 Mode 正交（keep/strip 均可配置）。
	AuthBridge *AuthBridge `json:"auth_bridge,omitempty"`
}

// AuthBridge 授权头桥接配置（见 authbridge.go 的背景说明）。
type AuthBridge struct {
	// Scheme 恢复 Authorization 头时的前缀："Bearer"（vnts2 JWT）或
	// ""（OpenList：token 原样放入头，无 Bearer 前缀）。
	Scheme string `json:"scheme,omitempty"`
	// CookieName 桥接 cookie 名。发布网关会把 Set-Cookie 的 Path 统一
	// 改写成 "/"（实测），多路由桥接时同名 cookie 会互相覆盖，故
	// 按路由配不同名；缺省用 authBridgeCookieDefault。
	CookieName string `json:"cookie_name,omitempty"`
}

// Effective 返回上游看到的路径。
func (r *Route) Effective(reqPath string) string {
	if r.Mode == ModeKeep {
		return reqPath
	}
	// 前缀剥离：/speed/foo?x=1 → /foo
	// 必须保证前导斜杠：少了它上游会把 "foo" 当相对路径而 404。
	rest := strings.TrimPrefix(reqPath, r.Prefix)
	if rest == reqPath {
		// 请求路径恰好是前缀去掉尾斜杠（/dyna 命中 /dyna/）→ 视为根路径
		rest = "/"
	} else if !strings.HasPrefix(rest, "/") {
		rest = "/" + rest
	}
	return rest
}

// RouteTable 并发安全路由表。
type RouteTable struct {
	mu sync.RWMutex

	static     map[string]*Route // 写死配置（含 PASSTHROUGH/BASE_PATH）
	discovered map[string]*Route // warden 自动发现
	dynamic    map[string]*Route // 在线管理 + 本地 JSON

	// services 按**服务名**索引（不是 display_name），供 Cards() 查健康状态。
	services map[string]svcHealth

	// persistMu 串行化落盘。注意它必须比 mu"外层"：
	// 落盘时先在 persistMu 内重新取最新快照，避免先快照后落盘的丢更新。
	persistMu sync.Mutex
}

type svcHealth struct {
	Name    string // 服务名，map 的 key
	Display string
	Desc    string
	Health  string
}

func NewRouteTable() *RouteTable {
	return &RouteTable{
		static:     map[string]*Route{},
		discovered: map[string]*Route{},
		dynamic:    map[string]*Route{},
		services:   map[string]svcHealth{},
	}
}

// ---------------------------------------------------------------------------
// 前缀规范化与校验
// ---------------------------------------------------------------------------

// normalizePrefix 校验并规范化前缀。非法返回 ("", false)。
// 拒绝：非 / 开头结尾、根前缀 "/"、含空段（//a//）、超长。
func normalizePrefix(p string) (string, bool) {
	if len(p) > maxPrefixLen {
		return "", false
	}
	if !strings.HasPrefix(p, "/") || !strings.HasSuffix(p, "/") {
		return "", false
	}
	if p == "/" {
		// 根前缀会匹配所有路径并剥成 "/"，等于把全部流量指向单一上游
		return "", false
	}
	for _, seg := range strings.Split(strings.Trim(p, "/"), "/") {
		if seg == "" {
			return "", false
		}
	}
	return p, true
}

// validRoute 校验一条待插入的路由（在线 API 与磁盘加载共用）。
func validRoute(r *Route) bool {
	if _, ok := normalizePrefix(r.Prefix); !ok {
		return false
	}
	if r.Host == "" || r.Port <= 0 || r.Port > 65535 {
		return false
	}
	if r.Mode != ModeStrip && r.Mode != ModeKeep {
		return false
	}
	if len(r.Display) > maxTextField || len(r.Desc) > maxTextField || len(r.Icon) > maxTextField {
		return false
	}
	// 每路由响应头超时：0=不设；上界 5m（防误配把慢上游永久判死）
	if r.ResponseHeaderTimeout < 0 || r.ResponseHeaderTimeout > Duration(maxRouteTimeout) {
		return false
	}
	// auth_bridge scheme 非法（空格/CRLF/非 ASCII）会破坏上游收到的头结构
	if r.AuthBridge != nil && !validAuthBridgeScheme(r.AuthBridge.Scheme) {
		return false
	}
	// cookie 名含分隔符会破坏 Set-Cookie 结构
	if r.AuthBridge != nil && !validAuthBridgeCookieName(r.AuthBridge.CookieName) {
		return false
	}
	return true
}

// maxRouteTimeout 每路由响应头超时的上界（5 分钟）。
const maxRouteTimeout = 5 * time.Minute

// ---------------------------------------------------------------------------
// 写入
// ---------------------------------------------------------------------------

// SetStatic 替换写死路由集（仅启动时调用一次）。
func (t *RouteTable) SetStatic(rs []*Route) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.static = map[string]*Route{}
	for _, r := range rs {
		p, ok := normalizePrefix(r.Prefix)
		if !ok {
			log.Printf("[route] 忽略非法静态前缀 %q", r.Prefix)
			continue
		}
		r.Prefix = p
		r.Source = "static"
		t.static[p] = r
	}
}

// SetDiscovered 替换自动发现路由集（warden 轮询调用）。
// 只写 discovered 槽位，绝不触碰 static / dynamic。
func (t *RouteTable) SetDiscovered(rs []*Route, svcs []svcHealth) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.discovered = map[string]*Route{}
	for _, r := range rs {
		p, ok := normalizePrefix(r.Prefix)
		if !ok {
			continue
		}
		r.Prefix = p
		r.Source = "discovered"
		t.discovered[p] = r
	}
	// 按服务名索引 —— 此前误用 display_name 作 key，导致 Cards() 用 name 查找
	// 永远落空，所有自动发现服务的健康状态恒显示 unknown。
	t.services = map[string]svcHealth{}
	for _, s := range svcs {
		t.services[s.Name] = s
	}
}

// Upsert 在线新增/修改一条动态路由。已存在则覆盖。
func (t *RouteTable) Upsert(r *Route) error {
	if !validRoute(r) {
		return errInvalidRoute
	}
	t.mu.Lock()
	t.dynamic[r.Prefix] = r
	t.mu.Unlock()
	return t.persist()
}

// Delete 按前缀删除动态路由。
func (t *RouteTable) Delete(prefix string) bool {
	t.mu.Lock()
	if _, ok := t.dynamic[prefix]; !ok {
		t.mu.Unlock()
		return false
	}
	delete(t.dynamic, prefix)
	t.mu.Unlock()
	_ = t.persist()
	return true
}

// ---------------------------------------------------------------------------
// 读取
// ---------------------------------------------------------------------------

// GetDynamic 返回动态路由快照（深拷贝，调用方无法改到内部状态）。
func (t *RouteTable) GetDynamic() []*Route {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*Route, 0, len(t.dynamic))
	for _, r := range t.dynamic {
		c := *r
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out
}

// Lookup 按请求路径找路由。优先级：static > dynamic > discovered。
func (t *RouteTable) Lookup(path string) (*Route, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// 同一优先级内最长前缀匹配（/a/b/ 优先于 /a/）。
	match := func(m map[string]*Route) (*Route, bool) {
		best := ""
		var hit *Route
		for p := range m {
			if path == strings.TrimSuffix(p, "/") || strings.HasPrefix(path, p) {
				if len(p) > len(best) {
					best, hit = p, m[p]
				}
			}
		}
		return hit, hit != nil
	}

	if r, ok := match(t.static); ok {
		return r, true
	}
	if r, ok := match(t.dynamic); ok {
		return r, true
	}
	return match(t.discovered)
}

// Cards 供导航首页使用：合并三类路由，附带健康状态。返回深拷贝。
func (t *RouteTable) Cards() []*Route {
	t.mu.RLock()
	defer t.mu.RUnlock()

	merged := map[string]*Route{}
	// discovered → dynamic → static：后写的覆盖先写的，与 Lookup 优先级一致
	for _, m := range []map[string]*Route{t.discovered, t.dynamic, t.static} {
		for p, r := range m {
			merged[p] = r
		}
	}
	out := make([]*Route, 0, len(merged))
	for _, r := range merged {
		if r.Hidden {
			continue // 透传类端点不进宫格（与 Python 版 PASSTHROUGH 一致）
		}
		c := *r
		if h, ok := t.services[r.Name]; ok {
			c.Health = h.Health
			if c.Desc == "" {
				c.Desc = h.Desc
			}
			if c.Display == "" {
				c.Display = h.Display
			}
		}
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Prefix != out[j].Prefix {
			return out[i].Prefix < out[j].Prefix
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// Snapshot 供 /_health 展示的全量路由视图。
func (t *RouteTable) Snapshot() map[string]any {
	t.mu.RLock()
	defer t.mu.RUnlock()
	counts := map[string]int{
		"static": len(t.static), "discovered": len(t.discovered), "dynamic": len(t.dynamic),
	}
	all := map[string]*Route{}
	for _, m := range []map[string]*Route{t.static, t.dynamic, t.discovered} {
		for p, r := range m {
			all[p] = r
		}
	}
	prefixes := make([]string, 0, len(all))
	for p := range all {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)
	return map[string]any{"mounts": prefixes, "counts": counts}
}

// ---------------------------------------------------------------------------
// 持久化
// ---------------------------------------------------------------------------

type dynamicFile struct {
	Version int      `json:"version"`
	Routes  []*Route `json:"routes"`
}

// snapshotLocked 调用方须持有 t.mu（读或写）。
func (t *RouteTable) snapshotLocked() []*Route {
	out := make([]*Route, 0, len(t.dynamic))
	for _, r := range t.dynamic {
		c := *r
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out
}

// persist 落盘。在 persistMu 内**重新读取最新快照**再写，
// 因此并发 Upsert/Delete 不会互相覆盖，也不会交错写坏 .tmp。
func (t *RouteTable) persist() error {
	if persistPath == "" {
		return nil
	}
	t.persistMu.Lock()
	defer t.persistMu.Unlock()

	t.mu.RLock()
	snap := t.snapshotLocked()
	t.mu.RUnlock()

	blob, err := json.MarshalIndent(dynamicFile{Version: 1, Routes: snap}, "", "  ")
	if err != nil {
		return err
	}
	tmp := persistPath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		return err
	}
	// fsync 保证掉电时不至于留下空/半截文件（rename 只保证进程崩溃时的原子性）
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, persistPath)
}

// LoadDynamic 启动时从磁盘恢复动态路由。逐条校验，跳过非法项。
func (t *RouteTable) LoadDynamic() error {
	if persistPath == "" {
		return nil
	}
	blob, err := os.ReadFile(persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 首次启动，无历史动态路由
		}
		return err
	}
	var f dynamicFile
	if err := json.Unmarshal(blob, &f); err != nil {
		// 文件损坏时不清空、不退出：保留内存空表，让服务仍能起来，
		// 但必须响铃——否则运维不知道动态路由已全部丢失。
		log.Printf("[route] 动态路由文件损坏，已忽略（%v）：%s", err, persistPath)
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dynamic = map[string]*Route{}
	for _, r := range f.Routes {
		if !validRoute(r) {
			log.Printf("[route] 跳过非法动态路由 prefix=%q host=%q port=%d mode=%d",
				r.Prefix, r.Host, r.Port, r.Mode)
			continue
		}
		r.Source = "dynamic"
		t.dynamic[r.Prefix] = r
	}
	return nil
}

// errInvalidRoute 路由字段非法（在线 API 与 Upsert 共用）。
var errInvalidRoute = errors.New("invalid route")

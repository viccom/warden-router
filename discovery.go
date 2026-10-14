package main

// 服务发现：warden API 轮询 → discovered 层路由。
//
// 只写 discovered 槽位（SetDiscovered），绝不触碰 static/dynamic——
// 静态层是部署者意图，在线添加的动态路由优先于自动发现。
// 轮询间隔内新增/下线的服务自动生效/消失；ui_url 无前缀的服务
// 不参与挂载（仅导航引用）。

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// 服务发现
// ---------------------------------------------------------------------------

type wardenSvc struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
	UIURL       string `json:"ui_url"`
	Health      struct {
		Status string `json:"status"`
	} `json:"health"`
}

type wardenResp struct {
	Services []wardenSvc `json:"services"`
}

func discoveryLoop() {
	// 先立即跑一次，再按间隔轮询
	discover()
	tick := time.NewTicker(*refreshSecs)
	defer tick.Stop()
	for range tick.C {
		discover()
	}
}

func discover() {
	resolveTokens()
	req, err := http.NewRequest(http.MethodGet, *wardenAPI+"/api/v1/services", nil)
	if err != nil {
		log.Printf("[route] warden api request build: %v", err)
		return
	}
	if cachedWtok != "" {
		req.Header.Set("Authorization", "Bearer "+cachedWtok)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[route] warden api unreachable: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		log.Printf("[route] warden api 401：token 缺失或无效，服务发现已停摆（检查 /workspace/warden/.api-token）")
		return
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("[route] warden api status %d", resp.StatusCode)
		return
	}
	var wr wardenResp
	if err := json.NewDecoder(resp.Body).Decode(&wr); err != nil {
		log.Printf("[route] warden api decode: %v", err)
		return
	}
	if len(wr.Services) == 0 {
		return
	}
	var routes []*Route
	var svcs []svcHealth
	for _, s := range wr.Services {
		svcs = append(svcs, svcHealth{
			Name: s.Name, Display: s.DisplayName, Desc: s.Description, Health: s.Health.Status,
		})
		u, err := url.Parse(s.UIURL)
		if err != nil || u.Hostname() == "" || u.Port() == "" {
			continue // 无显式前缀的服务不参与挂载（仅导航引用）
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil || port <= 0 || port > 65535 {
			log.Printf("[route] 服务 %s 的 ui_url 端口非法: %q", s.Name, u.Port())
			continue
		}
		prefix := strings.Trim(u.Path, "/")
		if prefix == "" {
			continue
		}
		routes = append(routes, &Route{
			Prefix: "/" + prefix + "/", Host: u.Hostname(), Port: port,
			Mode: ModeStrip, Name: s.Name, Display: s.DisplayName, Desc: s.Description,
			Icon: "🌐",
		})
	}
	table.SetDiscovered(routes, svcs)
	log.Printf("[route] routes refreshed: %d discovered", len(routes))
}

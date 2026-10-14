package main

// 动态路由管理 API（写操作强制 Bearer token 鉴权）：
//
//	GET    /_routes          列出全部动态路由
//	POST   /_routes          新增或修改（body: Route JSON）
//	DELETE /_routes?prefix=  删除
//
// token 未配置时一律拒绝写操作，绝不退回"无鉴权可用"——
// 该端点可改写路由，暴露面等同于 warden 控制台。
// bearerOK 用常量时间比较，避免 token 时序侧信道。

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
)

// ---------------------------------------------------------------------------
// 动态路由管理 API（写操作强制鉴权）
//
//	GET    /_routes          列出全部动态路由
//	POST   /_routes          新增或修改（body: Route JSON）
//	DELETE /_routes?prefix=  删除
// ---------------------------------------------------------------------------

func handleRoutesAPI(w http.ResponseWriter, r *http.Request) {
	// 未配置 token 时一律拒绝写操作，绝不退回"无鉴权可用"——
	// 该端点可改写路由，暴露面等同于 warden 控制台。
	if r.Method != http.MethodGet && cachedAtok == "" {
		writeJSON(w, 503, map[string]string{
			"error": "admin token 未配置，写操作已禁用。请设置 -admin-token 或 ROUTE_ADMIN_TOKEN",
		})
		return
	}
	// GET 也校验（若配置了 token），避免拓扑信息裸奔
	if cachedAtok != "" && !bearerOK(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="warden-route admin"`)
		writeJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, 200, map[string]any{"routes": table.GetDynamic()})

	case http.MethodPost, http.MethodPut:
		var rt Route
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "read body: " + err.Error()})
			return
		}
		if err := json.Unmarshal(body, &rt); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid json: " + err.Error()})
			return
		}
		// 规范化前缀（补齐/拒绝），再校验其余字段
		p, ok := normalizePrefix(rt.Prefix)
		if !ok {
			writeJSON(w, 400, map[string]string{
				"error": "prefix 必须以 / 开头和结尾、不能为 /、不能含空段（如 //a//）",
			})
			return
		}
		rt.Prefix = p
		if !validRoute(&rt) {
			writeJSON(w, 400, map[string]string{
				"error": "host 非空、port 在 1-65535、mode 为 0 或 1、文本字段不超长",
			})
			return
		}
		if err := table.Upsert(&rt); err != nil {
			if errors.Is(err, errInvalidRoute) {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		log.Printf("[route] 动态路由已生效: %s -> %s:%d mode=%d", rt.Prefix, rt.Host, rt.Port, rt.Mode)
		writeJSON(w, 200, map[string]any{"ok": true, "route": rt})

	case http.MethodDelete:
		prefix := r.URL.Query().Get("prefix")
		if prefix == "" {
			writeJSON(w, 400, map[string]string{"error": "missing ?prefix="})
			return
		}
		if !table.Delete(prefix) {
			writeJSON(w, 404, map[string]string{"error": "no such dynamic route: " + prefix})
			return
		}
		log.Printf("[route] 动态路由已删除: %s", prefix)
		writeJSON(w, 200, map[string]any{"ok": true, "deleted": prefix})

	default:
		w.Header().Set("Allow", "GET, POST, PUT, DELETE")
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
	}
}

// bearerOK 常量时间比较，避免时序侧信道。
func bearerOK(r *http.Request) bool {
	const p = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, p) {
		return false
	}
	got := strings.TrimSpace(strings.TrimPrefix(h, p))
	return subtleEqual(got, cachedAtok)
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

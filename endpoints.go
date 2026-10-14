package main

// 内置只读端点：/_health（自检快照）与 /_metrics（见 metrics.go）。
// writeJSON 是全项目 JSON 响应的统一出口（禁 HTML 转义、显式 Content-Length）。

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// 内置端点
// ---------------------------------------------------------------------------

func handleHealth(w http.ResponseWriter, r *http.Request) {
	snap := table.Snapshot()
	snap["status"] = "ok"
	snap["dynamic"] = table.GetDynamic()
	snap["admin_auth"] = cachedAtok != ""
	writeJSON(w, 200, snap)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.WriteHeader(code)
	_, _ = io.WriteString(w, buf.String())
}

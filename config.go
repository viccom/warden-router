package main

// 写死路由配置：与 Python 版 router.py 的 PASSTHROUGH / STATIC_MOUNTS /
// BASE_PATH_MOUNTS 逐条对应，语义完全一致。
//
// ModeKeep   = BASE_PATH_MOUNTS（前缀保留，上游自行解析，如 ttyd -b /terminal）
// ModeStrip  = STATIC_MOUNTS / PASSTHROUGH（前缀剥离）

func staticRoutes() []*Route {
	return []*Route{
		// ---- PASSTHROUGH：保留前缀 ----
		// 这两条是裸 API 透传（warden 自身的 API 与 librespeed 后端），
		// 面向用户无意义，Hidden 使其不进导航宫格——与 Python 版
		// _nav_page 只遍历 STATIC/BASE_PATH/discovered 的行为一致。
		// Name 用 warden 真实注册名 web-gateway（端口 8789 即 warden 自身），
		// 健康查表因此能命中；Python 版此处写 "warden-ui" 配一条硬编码
		// 特判来打补丁，Go 版用真实服务名让通用查表自然工作。
		{Prefix: "/api/v1/", Host: "127.0.0.1", Port: 8789, Mode: ModeKeep,
			Name: "web-gateway", Display: "API 透传", Hidden: true},
		{Prefix: "/backend/", Host: "127.0.0.1", Port: 8800, Mode: ModeKeep,
			Name: "librespeed", Display: "后端透传", Hidden: true},

		// ---- STATIC_MOUNTS：前缀剥离 ----
		{Prefix: "/warden/", Host: "127.0.0.1", Port: 8789, Mode: ModeStrip,
			Name: "web-gateway", Display: "Warden 管理台",
			Desc: "进程监护控制台：服务启停、日志、指标", Icon: "🛠️"},

		// ---- BASE_PATH_MOUNTS：前缀保留 ----
		{Prefix: "/monitor/", Host: "127.0.0.1", Port: 27960, Mode: ModeKeep,
			Name: "kula", Display: "Kula 主机监控",
			Desc: "单二进制 Linux 监控：1s 采集 / 环形缓冲 / 磁盘用量 + 进程·网络监测",
			Icon: "📈"},
		{Prefix: "/terminal/", Host: "127.0.0.1", Port: 27970, Mode: ModeKeep,
			Name: "terminal", Display: "网页终端",
			Desc: "浏览器经 HTTPS 通道直连沙箱 shell（ttyd，需密码）", Icon: "⌨️"},
	}
}

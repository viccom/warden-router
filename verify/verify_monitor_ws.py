#!/usr/bin/env python3
"""Playwright 验证：kula 仪表盘经公网网关 + warden-route(go) 的 WS 数据流。

背景：2026-10-14 生产故障——Go router 曾把 Host 头改写为上游地址，kula 的
WS 同源校验（Origin.host == r.Host）误判跨站返回 403，仪表盘
"WebSocket connection failed"。本脚本守修复后的真实链路：
浏览器 → CloudStudio 网关 → router :9000 → kula :27960。

判定：页面无 WebSocket 报错 + /monitor/ws 收到数据帧（实时指标在流动）。
"""
import sys

from playwright.sync_api import sync_playwright

URL = ("https://webview.e2b.gz1.sandbox.cloudstudio.club/"
       "?x-cs-sandbox-id=ef2270897057479793c4368770007116&x-cs-sandbox-port=9000")
BASE = "https://webview.e2b.gz1.sandbox.cloudstudio.club"
SHOT = "/workspace/router-go/verify/go-monitor-verify.png"
fails = []


def check(name, cond, detail=""):
    print(("  [OK] " if cond else "  [!!] ") + name + ((" — " + detail) if detail and not cond else ""))
    if not cond:
        fails.append(name)


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context(viewport={"width": 1440, "height": 900})
    page = ctx.new_page()
    errors, ws_frames = [], []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)

    ws_events = []

    def on_ws(ws):
        ws_events.append(("open", ws.url))
        ws.on("framereceived", lambda _: ws_frames.append(ws.url))
        ws.on("close", lambda: ws_events.append(("close", ws.url)))

    page.on("websocket", on_ws)

    print("[1] 打开公网 /monitor/ 仪表盘")
    # 网关用 query 参数定位 sandbox+port，命中后种 cookie 再重定向到 /；
    # 之后同源下的 /monitor/ 由 cookie 携带路由信息（参数不能拼在路径后）
    page.goto(URL, wait_until="domcontentloaded", timeout=30000)
    page.goto(BASE + "/monitor/", wait_until="domcontentloaded", timeout=30000)
    page.wait_for_timeout(2000)

    print("[2] 等待 WS 数据帧（最多 15s）")
    deadline = 15000
    step = 500
    waited = 0
    while not ws_frames and waited < deadline:
        page.wait_for_timeout(step)
        waited += step
    check("WS 收到数据帧（实时指标流动）", bool(ws_frames), str(ws_events))
    check("WS 目标为 /monitor/ws",
          any("/monitor/ws" in u for _, u in ws_events), str(ws_events))

    print("[3] 页面错误扫描")
    # 已知平台噪声：CloudStudio 网关会在 CSP 的 frame-ancestors 后追加 "*"，
    # 使该 directive 被浏览器忽略并告警。直连 kula 与经 router 实测头部均为
    # 合法的 frame-ancestors 'none';——改写发生在网关侧，非 kula/router 缺陷。
    gateway_noise = "frame-ancestors"
    ws_err = [e for e in errors if "WebSocket" in e or "websocket" in e]
    other = [e for e in errors if gateway_noise not in e]
    check("无 WebSocket 相关报错", not ws_err, str(ws_err[:2]))
    check("无其他 JS 错误（已知网关 CSP 噪声已排除）", not other, str(other[:2]))

    print("[4] 仪表盘内容抽查（实时数据应已渲染）")
    page.wait_for_timeout(1500)
    body = page.inner_text("body")
    check("页面含监控要素（CPU/内存/负载等关键词）",
          any(k in body for k in ("CPU", "内存", "负载", "磁盘", "网络")), body[:120])
    page.screenshot(path=SHOT, full_page=False)
    print("[5] 截图已保存: %s" % SHOT)
    browser.close()

print()
if fails:
    print("失败 %d 项: %s" % (len(fails), fails))
    sys.exit(1)
print("全部通过 ✔ —— kula 仪表盘 WS 链路已恢复")

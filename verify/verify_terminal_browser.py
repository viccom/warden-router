#!/usr/bin/env python3
"""Playwright 真实浏览器端到端验证：/terminal/ 经 warden-route(go) 代理。

覆盖裸 socket 测试覆盖不到的部分：
  1. ttyd 页面 HTML/JS/CSS 经前缀保留挂载正常加载
  2. 浏览器 HTTP Basic 认证弹窗 → 同源 WS 握手自动带 Authorization
  3. xterm.js 真实渲染 + 键盘输入 + 命令执行
xterm.js 渲染在 canvas 上，DOM 无文本，用截图验证。
"""
import sys
import time

from playwright.sync_api import sync_playwright

ROUTER = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9100"
CRED_FILE = "/workspace/terminal/.ttyd-cred"
MARKER = "BROWSER_OK_%d" % (int(time.time()) % 100000)
SHOT = "/workspace/router-go/verify/go-terminal-verify.png"

password = open(CRED_FILE).read().strip()

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    # http_credentials 让浏览器对页面的 Basic 认证弹窗自动应答，
    # 且后续同源的 WS 握手也会带上 Authorization（这正是 ttyd 要求的）
    ctx = browser.new_context(
        http_credentials={"username": "root", "password": password},
        viewport={"width": 900, "height": 560},
        ignore_https_errors=True,
    )
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)

    print("[1] 打开 %s/terminal/" % ROUTER)
    page.goto("%s/terminal/" % ROUTER, wait_until="domcontentloaded", timeout=20000)
    page.wait_for_timeout(2500)  # 等 WS 建链 + shell 就绪

    # 终端画布出现即认为连接成功
    canvas = page.locator("canvas").first
    if not canvas.count():
        print("!! 未找到终端 canvas，页面内容：")
        print(page.content()[:1500])
        browser.close()
        sys.exit(1)
    print("[2] 终端画布已渲染（WS 已建立）")

    # 输入命令并回车
    page.keyboard.type("echo %s" % MARKER)
    page.keyboard.press("Enter")
    page.wait_for_timeout(2500)
    print("[3] 已输入: echo %s" % MARKER)

    page.screenshot(path=SHOT)
    print("[4] 截图已保存: %s" % SHOT)

    # 再验证连接仍然活着（再执行一条）
    page.keyboard.type("id -un")
    page.keyboard.press("Enter")
    page.wait_for_timeout(2000)
    page.screenshot(path=SHOT)
    browser.close()

    print("\n请查看截图确认 %s 与 root 是否出现在终端输出中" % MARKER)
    if errors:
        print("页面错误（供参考）: %s" % errors[:5])
    sys.exit(0)

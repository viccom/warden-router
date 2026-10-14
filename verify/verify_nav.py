#!/usr/bin/env python3
"""Playwright 真实浏览器验证：warden-route(go) 导航首页。

覆盖 SSR 单测覆盖不到的部分：
  1. 页面真实渲染：标题、统计行、卡片宫格、健康状态点
  2. 每张卡片链接都是 target=_blank + rel=noopener noreferrer（新标签页约定）
  3. 真实点击卡片 → 浏览器弹出新标签页且 URL 正确
  4. /_routes 动态增删 → 导航宫格实时出现/消失（含"动态"徽章）
  5. 后台拨测：动态路由指向真实活端口后，状态点由 unknown 翻转为 healthy
  6. /_api/nav JSON 端点可被页面 JS 正常消费
"""
import sys
import time

import requests
from playwright.sync_api import sync_playwright

ROUTER = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9100"
TOKEN = open("/workspace/warden/.api-token").read().strip()
SHOT = "/workspace/router-go/verify/go-nav-verify.png"
DYN_PREFIX = "/dyn-speed/"
fails = []


def check(name, cond, detail=""):
    print(("  [OK] " if cond else "  [!!] ") + name + ((" — " + detail) if detail and not cond else ""))
    if not cond:
        fails.append(name)


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    ctx = browser.new_context(viewport={"width": 1280, "height": 800})
    page = ctx.new_page()
    js_errors = []
    page.on("pageerror", lambda e: js_errors.append(str(e)))

    print("[1] 打开导航首页 %s/" % ROUTER)
    page.goto(ROUTER + "/", wait_until="domcontentloaded", timeout=20000)
    page.wait_for_timeout(600)
    check("页面标题", page.title() == "服务导航 · warden-route", page.title())
    check("H1 为「服务导航」", page.locator("h1").inner_text() == "服务导航")
    cards = page.locator("a.card")
    n = cards.count()
    check("卡片数量 >= 4", n >= 4, "实际 %d" % n)
    check("统计行存在且非空", page.locator("#stat").inner_text().strip() != "")
    print("     统计行: %s" % page.locator("#stat").inner_text())

    print("[2] 新标签页约定（target=_blank + rel）")
    bad = page.evaluate(
        """() => Array.from(document.querySelectorAll('a.card'))
             .filter(a => a.target !== '_blank' || !a.rel.includes('noopener'))
             .map(a => a.getAttribute('href'))"""
    )
    check("全部卡片新标签页打开", not bad, "违规: %s" % bad)

    print("[3] 健康状态点")
    dots = page.evaluate(
        """() => Array.from(document.querySelectorAll('.dot'))
             .map(d => d.className.replace('dot','').trim())"""
    )
    check("状态点数量与卡片一致", len(dots) == n, "%d vs %d" % (len(dots), n))
    check("状态点 class 均为合法三态",
          all(d in ("healthy", "unhealthy", "unknown") for d in dots), str(set(dots)))
    print("     状态点分布: %s" % {d: dots.count(d) for d in set(dots)})

    print("[4] 真实点击卡片 → 新标签页")
    with page.context.expect_page() as pop:
        page.locator("a.card", has_text="网络测速").first.click()
    newtab = pop.value
    check("弹出了新标签页", newtab is not None)
    if newtab:
        newtab.wait_for_load_state("domcontentloaded", timeout=15000)
        check("新标签页 URL 指向 /speed/", "/speed/" in newtab.url, newtab.url)
        newtab.close()

    print("[5] /_api/nav JSON 端点")
    nav_json = page.evaluate("async () => await (await fetch('/_api/nav',{cache:'no-store'})).json()")
    check("JSON 含 routes 数组", isinstance(nav_json.get("routes"), list) and len(nav_json["routes"]) == n)
    check("每条含 prefix/health 字段",
          all("prefix" in r and "health" in r for r in nav_json["routes"]))

    print("[6] 动态路由 CRUD → 导航实时联动")
    r = requests.post(ROUTER + "/_routes",
                      headers={"Authorization": "Bearer " + TOKEN},
                      json={"prefix": DYN_PREFIX, "host": "127.0.0.1", "port": 8800,
                            "mode": 0, "display": "动态测速台", "desc": "运行时添加的动态路由",
                            "icon": "🧪"}, timeout=10)
    check("POST /_routes 成功", r.status_code == 200 and r.json().get("ok"), r.text[:200])
    page.reload(wait_until="domcontentloaded")
    page.wait_for_timeout(400)
    dyn = page.locator("a.card", has_text="动态测速台")
    check("动态卡片出现在宫格", dyn.count() == 1)
    if dyn.count():
        check("动态卡片带「动态」徽章", "动态" in dyn.inner_text())
        check("动态卡片也是新标签页", dyn.get_attribute("target") == "_blank")
    check("统计行变为 5 项", "5 项服务" in page.locator("#stat").inner_text(),
          page.locator("#stat").inner_text())

    print("[7] 后台拨测翻转健康状态（等待最多 20s）")
    deadline = time.time() + 20
    h = ""
    while time.time() < deadline:
        h = page.evaluate(
            """() => {const c=document.querySelector('a.card[data-prefix="%s"]');
                    return c ? c.querySelector('.dot').className.replace('dot','').trim() : 'gone';}""" % DYN_PREFIX)
        if h == "healthy":
            break
        page.wait_for_timeout(1000)
    check("动态路由健康点翻转为 healthy", h == "healthy", "当前 %s" % h)

    print("[8] 删除动态路由 → 卡片消失")
    r = requests.delete(ROUTER + "/_routes?prefix=" + DYN_PREFIX,
                        headers={"Authorization": "Bearer " + TOKEN}, timeout=10)
    check("DELETE /_routes 成功", r.status_code == 200 and r.json().get("ok"), r.text[:200])
    page.reload(wait_until="domcontentloaded")
    page.wait_for_timeout(400)
    check("动态卡片已消失", page.locator("a.card", has_text="动态测速台").count() == 0)
    check("统计行回到 4 项", "4 项服务" in page.locator("#stat").inner_text(),
          page.locator("#stat").inner_text())

    page.screenshot(path=SHOT, full_page=True)
    print("[9] 截图已保存: %s" % SHOT)
    check("无 JS 运行时错误", not js_errors, str(js_errors[:3]))
    browser.close()

print()
if fails:
    print("失败 %d 项: %s" % (len(fails), fails))
    sys.exit(1)
print("全部通过 ✔")

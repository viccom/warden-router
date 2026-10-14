#!/usr/bin/env python3
"""WS 终端经 warden-route(go) 代理的端到端验证。

两层验证：
  1) 裸 socket WS 协议层：握手 → AuthToken 认证帧 → 执行命令 → 断言回显
  2) （由 verify_terminal_browser.py 负责）Playwright 真实浏览器

用法：python3 verify_terminal_ws.py [router_base_url]
"""
import base64
import json
import os
import socket
import ssl
import sys
import time

ROUTER = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9100"
CRED_FILE = "/workspace/terminal/.ttyd-cred"
MARKER = "GO_ROUTER_WS_OK_%d" % (int(time.time()) % 100000)


def parse_base(url):
    """返回 (host, port, use_tls)。"""
    if url.startswith("https://"):
        host, _, port = url[8:].partition(":")
        return host, int(port or 443), True
    host, _, port = url[7:].partition(":")
    return host, int(port or 80), False


def ws_connect(host, port, path, use_tls, basic_auth=None):
    """最小 WebSocket 握手，返回 (sock, leftover_bytes)。

    两个必需的头，缺一不可（ttyd 1.7.4 源码实测）：
      1) Sec-WebSocket-Protocol: tty —— lws 靠它把连接绑定到 ttyd 的
         "tty" 协议回调（前端 index.ts:239 `new WebSocket(wsUrl, ['tty'])`）。
         缺了它握手虽返回 101，但帧不会送达 callback_tty，表现为永远无数据。
      2) Authorization: Basic <base64(user:pass)> —— callback_tty 的
         LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION 里 check_auth() 要求握手
         即带 Basic 凭据（protocol.c:212）。浏览器能过是因为加载页面时已做
         HTTP Basic 认证，同源 WS 握手被浏览器自动带上该头。
    """
    key = base64.b64encode(os.urandom(16)).decode()
    headers = [
        f"GET {path} HTTP/1.1",
        f"Host: {host}:{port}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        "Sec-WebSocket-Protocol: tty",
    ]
    if basic_auth:
        headers.append("Authorization: Basic " + base64.b64encode(basic_auth.encode()).decode())
    req = "\r\n".join(headers) + "\r\n\r\n"
    sock = socket.create_connection((host, port), timeout=10)
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    sock.sendall(req.encode())
    # 读响应头
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("握手时连接关闭: %r" % buf)
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = lines[0].decode()
    if "101" not in status:
        raise RuntimeError("握手失败: %s | %s" % (status, head.decode(errors="replace")))
    return sock, rest


def send_frame(sock, payload, opcode=0x1):
    """客户端帧（必须 mask）。"""
    data = payload.encode() if isinstance(payload, str) else payload
    header = bytearray([0x80 | opcode])
    n = len(data)
    mask = os.urandom(4)
    if n < 126:
        header.append(0x80 | n)
    elif n < 65536:
        header.append(0x80 | 126)
        header += n.to_bytes(2, "big")
    else:
        header.append(0x80 | 127)
        header += n.to_bytes(8, "big")
    header += mask
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    sock.sendall(bytes(header) + masked)


def recv_frame(sock, leftover=b""):
    """读一个服务端帧，返回 (opcode, payload, leftover)。"""
    buf = bytearray(leftover)

    def need(n):
        while len(buf) < n:
            chunk = sock.recv(65536)
            if not chunk:
                raise RuntimeError("读帧时连接关闭")
            buf.extend(chunk)

    need(2)
    b0, b1 = buf[0], buf[1]
    opcode = b0 & 0x0F
    plen = b1 & 0x7F
    idx = 2
    if plen == 126:
        need(4)
        plen = int.from_bytes(buf[2:4], "big")
        idx = 4
    elif plen == 127:
        need(10)
        plen = int.from_bytes(buf[2:10], "big")
        idx = 10
    need(idx + plen)
    payload = bytes(buf[idx:idx + plen])
    return opcode, payload, bytes(buf[idx + plen:])


def main():
    cred = "root:" + open(CRED_FILE).read().strip()
    token = base64.b64encode(cred.encode()).decode()
    host, port, use_tls = parse_base(ROUTER)
    print("router=%s  marker=%s" % (ROUTER, MARKER))

    sock, leftover = ws_connect(host, port, "/terminal/ws", use_tls, basic_auth=cred)
    print("[1] WS 握手 101 OK（/terminal/ws 前缀保留）")

    # ttyd 首帧：终端尺寸 + AuthToken（与 html/src/components/terminal/xstem 一致）
    send_frame(sock, json.dumps({"columns": 100, "rows": 30, "AuthToken": token}))
    print("[2] 已发送 AuthToken 认证帧")

    # 等 shell 提示符就绪（收到输出即认为已 attach）
    deadline = time.time() + 15
    got_output = False
    while time.time() < deadline:
        sock.settimeout(3)
        try:
            op, payload, leftover = recv_frame(sock, leftover)
        except socket.timeout:
            continue
        if op == 0x1 and payload[:1] == b"{":
            # 服务端 JSON 控制消息（如 {"type": "..."}); 继续等
            continue
        if op in (0x2, 0x1) and payload:
            got_output = True
            break
        if op == 0x8:
            raise RuntimeError("服务端关闭 WS: %r" % payload[:120])
    if not got_output:
        raise RuntimeError("15s 内未收到终端输出（认证可能失败）")
    print("[3] 终端已 attach，收到输出")

    # 执行命令。ttyd 协议：客户端消息首字符是命令码，INPUT='0'
    # （src/server.h：#define INPUT '0'），其后是原始终端输入。
    cmd = "0echo %s\r\n" % MARKER
    send_frame(sock, cmd)
    print("[4] 已执行: echo %s" % MARKER)

    # 收集回显
    out = b""
    deadline = time.time() + 10
    while time.time() < deadline and MARKER.encode() not in out:
        sock.settimeout(3)
        try:
            op, payload, leftover = recv_frame(sock, leftover)
        except socket.timeout:
            continue
        if op == 0x8:
            break
        if op == 0x9:  # ping → 回 pong
            send_frame(sock, payload, opcode=0xA)
            continue
        out += payload
    sock.close()

    text = out.decode("utf-8", "replace")
    if MARKER in text:
        print("[5] 回显命中 marker：%s" % MARKER)
        print("\n--- 输出片段 ---")
        print(text[-600:])
        print("--- WS 终端验证通过 ---")
        return 0
    print("!! marker 未出现在回显中")
    print("\n--- 实际输出 ---")
    print(text[-1500:])
    return 1


if __name__ == "__main__":
    sys.exit(main())

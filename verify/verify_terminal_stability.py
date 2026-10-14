#!/usr/bin/env python3
"""WS 终端长连接稳定性：N 秒内不断线、ping/pong 正常。

背景：Python 版曾因建连超时污染长连接导致"每 15 秒必断"。Go 版用
httputil.ReverseProxy 原生处理升级 + 共享 Transport，需实证长连接存活。
"""
import base64
import json
import os
import socket
import sys
import time

ROUTER = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9100"
DURATION = int(sys.argv[2]) if len(sys.argv) > 2 else 75
CRED = "root:" + open("/workspace/terminal/.ttyd-cred").read().strip()
TOKEN = base64.b64encode(CRED.encode()).decode()
MARKER = "STAB_%d" % (int(time.time()) % 100000)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_terminal_ws import ws_connect, send_frame, recv_frame  # noqa: E402

host, port = ROUTER[7:].split(":")
port = int(port)
sock, leftover = ws_connect(host, port, "/terminal/ws", False, basic_auth=CRED)
send_frame(sock, json.dumps({"AuthToken": TOKEN, "columns": 100, "rows": 30}))
print("已连接，开始 %ds 稳定性观测（ttyd --ping-interval 30）..." % DURATION)

start = time.time()
pings = pongs_sent = frames = bytes_in = 0
closed_at = None
sock.settimeout(5)
while time.time() - start < DURATION:
    try:
        op, payload, leftover = recv_frame(sock, leftover)
    except socket.timeout:
        continue
    except (ConnectionError, OSError) as e:
        closed_at = time.time() - start
        print("!! %.1fs 连接异常：%r" % (closed_at, e))
        break
    if op == 0x8:
        closed_at = time.time() - start
        print("!! %.1fs 收到关闭帧：%r" % (closed_at, payload[:80]))
        break
    if op == 0x9:
        pings += 1
        send_frame(sock, payload, opcode=0xA)  # 回 pong
        pongs_sent += 1
        print("  %.1fs 收到 ping，已回 pong" % (time.time() - start))
        continue
    frames += 1
    bytes_in += len(payload)

# 结束时再执行一条命令，证明连接仍可用
alive = True
try:
    send_frame(sock, "0echo %s\r\n" % MARKER)
    deadline = time.time() + 8
    out = b""
    while time.time() < deadline and MARKER.encode() not in out:
        try:
            op, payload, leftover = recv_frame(sock, leftover)
        except socket.timeout:
            break
        if op == 0x8:
            alive = False
            break
        out += payload
    if MARKER.encode() not in out:
        alive = False
except OSError:
    alive = False
sock.close()

elapsed = time.time() - start
print("\n=== 结果 ===")
print("观测时长 : %.1fs（目标 %ds）" % (elapsed, DURATION))
print("数据帧   : %d 帧 / %d 字节" % (frames, bytes_in))
print("ping/pong: 收到 %d 个 ping，回复 %d 个 pong" % (pings, pongs_sent))
print("结束时可执行: %s" % ("是" if alive else "否"))
if closed_at is None and alive and pings >= 2:
    print("*** 长连接稳定：%ds 内未断线，命令仍可执行 ***" % DURATION)
    sys.exit(0)
print("*** 不满足稳定判据 ***")
sys.exit(1)

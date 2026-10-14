package main

// Duration 是可 JSON 序列化的时长（TDD 第二批 · 步骤5，T5）。
//
// 双面兼容：
//   - 输入接受 "10s" 字符串（routes.toml / 在线 API 的人读面）与
//     纳秒数字（time.Duration 的默认 JSON 行为，兼容旧数据）；
//   - 输出统一为 "10s" 字符串（人读友好，与配置文件一致）。
//
// 0 值 = 不设超时（默认关闭，显式开启才生效——WS 安全默认）。

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Duration 以纳秒存储，与 time.Duration 同基。
type Duration time.Duration

// String 实现 fmt.Stringer（日志与错误信息人读面）。
func (d Duration) String() string { return time.Duration(d).String() }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	// 裸数字按纳秒解析（兼容 time.Duration 既有 JSON 行为）
	if len(b) > 0 && b[0] != '"' {
		var ns int64
		if err := json.Unmarshal(b, &ns); err != nil {
			return err
		}
		*d = Duration(ns)
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("无效的 duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

package main

// 上报到 Linux 收款站（epay）。
//
// 协议就是 epay 的 POST /api/report：
//
//	body: {"amount":"10.01","ts":…,"nonce":"…","channel":"wechat","raw":"…"}
//	header: X-Sign = lower_hex(HMAC-SHA256(reportToken, body 原始字节))
//
// 响应：
//	{"code":1,"msg":"matched","trade_no":"…"}      匹配成功
//	{"code":0,"msg":"no matching order (recorded)"} 记录但没匹配
//	{"code":0,"msg":"duplicate ignored"}            重复
//	{"code":-1,"msg":"bad sign"}                    密钥不一致（401）
//	{"code":-1,"msg":"ts skew"}                    本机时间偏差 > 300 秒
//
// 为什么不经过中间的 gateway：
//   用户只有一台 Linux 服务器 + 若干台 Windows 挂机机器。
//   多一层网关就多一个要部署、要看护、要传令牌的东西，收益为零。
//   agent 直接打 epay，少一跳，也少一处故障点。

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"wxhook/internal/outbox"
)

// ── 上报体 ─────────────────────────────────────────────────────────

// reportBody 是 epay /api/report 的请求体。字段名必须和 epay 完全一致。
type reportBody struct {
	Amount  string `json:"amount"`
	TS      int64  `json:"ts"`
	Nonce   string `json:"nonce"`
	Channel string `json:"channel"`
	Raw     string `json:"raw"`
}

// reportResp 是 epay 的响应。
type reportResp struct {
	Code    int    `json:"code"`
	Msg     string `json:"msg"`
	TradeNo string `json:"trade_no"`
}

// ── 签名 ───────────────────────────────────────────────────────────

func hmacSign(token string, body []byte) string {
	m := hmac.New(sha256.New, []byte(token))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func newNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("n-%d", time.Now().UnixNano())
	}
	return "n-" + hex.EncodeToString(b)
}

// ── 转发循环 ───────────────────────────────────────────────────────

func (a *agent) forwardLoop(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.wake:
		}

		if a.cfg.ServerURL == "" || a.token == "" {
			a.connected.Store(false)
			continue
		}

		items, err := a.box.Due(time.Now().Unix(), 20)
		if err != nil {
			a.logger.Printf("[outbox] 读取失败: %v", err)
			continue
		}
		for _, it := range items {
			if ctx.Err() != nil {
				return
			}
			outcome, err := a.forwardOne(ctx, it)
			switch outcome {
			case outcomeDone:
				_ = a.box.Done(it.ID)
				a.connected.Store(true)
			case outcomePause:
				// 密钥错/时间偏差：重发也没用，留队等人工修
				a.connected.Store(false)
				a.setError(err.Error())
				return
			default: // outcomeRetry
				n := it.Attempts + 1
				_ = a.box.Retry(it.ID, n, time.Now().Add(outbox.Backoff(n)), err.Error())
				a.connected.Store(false)
				a.setError("上报失败：" + err.Error())
				if n == 1 || n%10 == 0 {
					a.logger.Printf("[report] #%d 第 %d 次失败：%v", it.ID, n, err)
				}
				// 服务器有问题时别把整批都试一遍
				return
			}
		}
	}
}

type outcome int

const (
	outcomeDone outcome = iota
	outcomeRetry
	outcomePause
)

// forwardOne 把 outbox 里的一条事件上报给 epay。
func (a *agent) forwardOne(ctx context.Context, it outbox.Item) (outcome, error) {
	var ev hookEvent
	if err := json.Unmarshal([]byte(it.Body), &ev); err != nil {
		// 入库前校验过；真坏了就丢掉，免得永远卡在队头
		a.logger.Printf("[report] #%d 事件体损坏，丢弃：%v", it.ID, err)
		return outcomeDone, nil
	}

	amount := strings.TrimSpace(ev.Amount)
	if amount == "" {
		a.logger.Printf("[report] #%d 没有金额，丢弃", it.ID)
		return outcomeDone, nil
	}

	body := reportBody{
		Amount:  amount,
		TS:      time.Now().Unix(),
		Nonce:   newNonce(),
		Channel: "wechat",
		Raw:     truncate(ev.Raw, 2000),
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return outcomeDone, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(a.cfg.ServerURL, "/")+"/api/report", bytes.NewReader(buf))
	if err != nil {
		return outcomePause, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sign", hmacSign(a.token, buf))
	req.Header.Set("User-Agent", "wxhook-agent/"+agentVersion)

	res, err := a.client.Do(req)
	if err != nil {
		return outcomeRetry, err
	}
	defer res.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))

	switch res.StatusCode {
	case http.StatusUnauthorized:
		return outcomePause, fmt.Errorf("密钥不一致（epay 的 reportToken 与本地 token 不同）：%s", truncate(string(raw), 160))
	case http.StatusTooManyRequests:
		return outcomeRetry, fmt.Errorf("收款站限流")
	}
	if res.StatusCode >= 500 {
		return outcomeRetry, fmt.Errorf("收款站 %d：%s", res.StatusCode, truncate(string(raw), 160))
	}

	var rr reportResp
	if err := json.Unmarshal(raw, &rr); err != nil {
		return outcomeRetry, fmt.Errorf("响应不是 JSON：%s", truncate(string(raw), 160))
	}

	// epay 用 code 表达结果
	switch {
	case rr.Code == 1:
		a.logger.Printf("[report] #%d 已匹配订单 %s amount=%s", it.ID, rr.TradeNo, amount)
		return outcomeDone, nil
	case strings.Contains(rr.Msg, "duplicate"):
		a.logger.Printf("[report] #%d 收款站已有这笔（去重命中）", it.ID)
		return outcomeDone, nil
	case strings.Contains(rr.Msg, "no matching order"):
		// 钱收到了但没对上订单：留给人工补单，不要无限重试
		a.logger.Printf("[report] #%d 到账 %s 未匹配订单（已在收款站记录）", it.ID, amount)
		return outcomeDone, nil
	case strings.Contains(rr.Msg, "bad sign"):
		return outcomePause, fmt.Errorf("密钥不一致：%s", rr.Msg)
	case strings.Contains(rr.Msg, "ts skew"):
		return outcomePause, fmt.Errorf("本机时间与服务器差超过 300 秒，请开 NTP 同步：%s", rr.Msg)
	case strings.Contains(rr.Msg, "bad amount"):
		a.logger.Printf("[report] #%d 金额 %q 被拒，丢弃", it.ID, amount)
		return outcomeDone, nil
	default:
		return outcomeRetry, fmt.Errorf("未预期响应 code=%d msg=%q", rr.Code, rr.Msg)
	}
}

// ── 心跳 ───────────────────────────────────────────────────────────
//
// epay 没有专门的心跳接口。这里打 /health（收款站的存活探针），
// 通了就算"连得上"，顺便把微信/Hook 状态记进本地日志，面板直接读本地。
//
// 为什么不加 /api/agent/heartbeat 到 epay：
//   那要给 epay 引入"代理"概念（注册表、令牌、在线判定），
//   而实际上用户只需要知道"我那台 Windows 还在上报吗"——
//   看收款站的到账记录里有没有新数据就够了。

func (a *agent) heartbeatLoop(ctx context.Context) {
	interval := time.Duration(a.cfg.HeartbeatSec) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	failing := false

	for {
		if a.cfg.ServerURL != "" && a.token != "" {
			err := a.ping(ctx)
			if err != nil {
				if !failing {
					a.logger.Printf("[heartbeat] 连不上收款站：%v", err)
					failing = true
					a.setError("连不上收款站：" + err.Error())
				}
			} else {
				if failing {
					a.logger.Printf("[heartbeat] 已恢复与收款站的连接")
					failing = false
					a.setError("")
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func (a *agent) ping(ctx context.Context) error {
	u, err := url.Parse(strings.TrimRight(a.cfg.ServerURL, "/") + "/health")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "wxhook-agent/"+agentVersion)

	res, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))

	// epay 的 /health 可能是 200；就算 404 也说明服务器活着、能连上
	if res.StatusCode >= 500 {
		return fmt.Errorf("服务器 %d", res.StatusCode)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

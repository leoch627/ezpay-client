package main

// agent 本地面板。
//
// 为什么需要它：agent 跑在装微信的 Windows 上，用户就在这台机器前面。
// 之前只有 /health 一个探针，用户看不到"注入的是哪个账号、hook 有没有命中、
// 日志在哪、上游地址填得对不对"——只能去翻 data\agent.json 和 logs\agent.log。
//
// 设计取舍：
//   - 只绑 cfg.ListenAddr（默认 127.0.0.1:29731），不对外开放
//   - 不做登录：本机能访问这个端口的人本来就能操作这台机器
//   - 面板和 /hook/payment 同一个端口，不额外占端口
//   - 页面内嵌进二进制，不依赖外部文件

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"wxhook/internal/secret"
	"wxhook/internal/version"
)

// ── 状态快照 ────────────────────────────────────────────────────────

type agentStat struct {
	Version   string `json:"version"`
	AgentID   string `json:"agentId"`
	Hostname  string `json:"hostname"`
	StartAt   int64  `json:"startAt"`
	UptimeSec int64  `json:"uptimeSec"`

	ServerURL string `json:"serverUrl"`
	HasToken  bool   `json:"hasToken"`
	Connected bool   `json:"connected"`
	LastErr   string `json:"lastErr"`

	ListenAddr string `json:"listenAddr"`

	WeChat struct {
		ExePath string `json:"exePath"`
		Version string `json:"version"`
		Running bool   `json:"running"`
		PID     uint32 `json:"pid"`
		Wxid    string `json:"wxid"`
	} `json:"wechat"`

	Hook struct {
		Attached    bool   `json:"attached"`
		State       string `json:"state"`
		StateCode   uint32 `json:"stateCode"`
		PatternID   string `json:"patternId"`
		Detail      string `json:"detail"`
		CallbackCnt uint64 `json:"callbackCount"`
		PaymentCnt  uint64 `json:"paymentCount"`
		PostOK      uint64 `json:"postOk"`
		PostFail    uint64 `json:"postFail"`
		DedupDrop   uint64 `json:"dedupDrop"`
		// 状态板声明的 PID，用来判断"这份状态是哪个进程写的"
		PID uint32 `json:"pid"`
		// WrongProcess 为 true 表示状态板指向的不是加载了 Weixin.dll 的主进程，
		// 典型场景：把 DLL 注进了微信的子进程（那里没有 Weixin.dll，钩不上）。
		WrongProcess bool `json:"wrongProcess"`
	} `json:"hook"`

	Injector struct {
		OK   bool   `json:"ok"`
		Note string `json:"note"`
		DLL  string `json:"dll"`
	} `json:"injector"`

	Outbox int `json:"outbox"`
}

func (a *agent) stat() agentStat {
	var s agentStat
	s.Version = agentVersion
	s.AgentID = a.cfg.AgentID
	s.Hostname, _ = os.Hostname()
	s.StartAt = a.startAt.Unix()
	s.UptimeSec = int64(time.Since(a.startAt).Seconds())

	s.ServerURL = a.cfg.ServerURL
	s.HasToken = a.token != ""
	s.Connected = a.connected.Load()

	a.mu.Lock()
	s.LastErr = a.lastError
	wxid := a.wxid
	a.mu.Unlock()
	s.WeChat.Wxid = wxid

	s.ListenAddr = a.cfg.ListenAddr

	wi := a.wechatInfo()
	s.WeChat.ExePath = wi.ExePath
	s.WeChat.Version = wi.Version
	s.WeChat.Running = wi.Running
	s.WeChat.PID = wi.PID

	if a.inj != nil && a.inj.Available() {
		if hs, err := a.inj.ReadHookStatus(); err == nil {
			s.Hook.Attached = hs.Attached
			s.Hook.State = hs.State
			s.Hook.StateCode = hs.StateCode
			s.Hook.PatternID = hs.PatternID
			s.Hook.Detail = hs.Detail
			s.Hook.CallbackCnt = hs.CallbackCnt
			s.Hook.PaymentCnt = hs.PaymentCnt
			s.Hook.PostOK = hs.PostOK
			s.Hook.PostFail = hs.PostFail
			s.Hook.DedupDrop = hs.DedupDrop
			s.Hook.PID = hs.PID
			// 注意：不要用 hs.Version 覆盖 s.WeChat.Version。
			// 状态板里的版本是 DLL 从注册表 DWORD 位运算出来的（242.84.28.53 这种），
			// 而 wi.Version 读的是 PE 版本资源，才是可信的。

			// 判断状态板是不是写错了进程：微信 4.x 有多个同名子进程，
			// 只有加载了 Weixin.dll 的那个才钩得上。注到子进程时状态会是
			// "Weixin.dll 未加载"，表现和"没注入"一模一样，用户很难分辨。
			if hs.PID != 0 && hs.PID != s.WeChat.PID {
				if a.inj != nil {
					if base, err := a.inj.GetModuleBase(hs.PID, "Weixin.dll"); err == nil && base == 0 {
						s.Hook.WrongProcess = true
					}
				}
			}
			if hs.StateCode == 1 { // MODULE_MISSING
				s.Hook.WrongProcess = true
			}
		}
	}

	s.Injector.OK = a.inj != nil && a.inj.Available()
	if s.Injector.OK {
		s.Injector.DLL = a.inj.DLLPath()
	} else if a.inj != nil {
		s.Injector.Note = fmt.Sprint(a.inj.Err())
	}

	s.Outbox = a.box.Count()
	return s
}

func (a *agent) handlePanelStat(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.stat())
}

// ── 设置读写 ────────────────────────────────────────────────────────

func (a *agent) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"serverUrl": a.cfg.ServerURL,
		"agentId":     a.cfg.AgentID,
		"hasToken":    a.token != "",
		"tokenMasked": maskToken(a.token),
		"listenAddr":  a.cfg.ListenAddr,
		"wechatExe":   a.cfg.WeChatExe,
		"hookDLL":     a.cfg.HookDLL,
		"injectDLL":   a.cfg.InjectDLL,
		"cfgPath":     a.cfgPath,
	})
}

func (a *agent) handleSaveSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerURL  *string `json:"serverUrl"`
		AgentToken *string `json:"agentToken"`
		AgentID    *string `json:"agentId"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求体不是合法 JSON"})
		return
	}

	var problems []string

	if req.ServerURL != nil {
		v := strings.TrimSpace(*req.ServerURL)
		if v != "" && !strings.HasPrefix(v, "http://") && !strings.HasPrefix(v, "https://") {
			problems = append(problems, "网关地址必须以 http:// 或 https:// 开头")
		}
	}
	if req.AgentID != nil {
		v := strings.TrimSpace(*req.AgentID)
		if v == "" {
			problems = append(problems, "代理名称不能为空")
		} else if len(v) > 64 {
			problems = append(problems, "代理名称太长")
		}
	}

	if len(problems) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "problems": problems})
		return
	}

	// 密钥是 epay 的 reportToken，形如 "RT-xxxx" 或任意长随机串，
	// 没有固定前缀——只要不是明显打码的值就接受。
	tokenVal := ""
	if req.AgentToken != nil {
		tokenVal = strings.TrimSpace(*req.AgentToken)
		if tokenVal != "" && strings.Contains(tokenVal, "****") {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok": false, "problems": []string{"填的是打码值，请输入完整的 reportToken"},
			})
			return
		}
		if len(tokenVal) > 200 {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"ok": false, "problems": []string{"令牌太长（最多 200 字符）"},
			})
			return
		}
	}

	a.mu.Lock()
	next := a.cfg
	if req.ServerURL != nil {
		next.ServerURL = strings.TrimRight(strings.TrimSpace(*req.ServerURL), "/")
	}
	if req.AgentID != nil {
		next.AgentID = strings.TrimSpace(*req.AgentID)
	}
	if tokenVal != "" {
		enc, err := secret.Protect(tokenVal)
		if err != nil {
			a.mu.Unlock()
			writeJSON(w, http.StatusInternalServerError, map[string]any{
				"ok": false, "error": "令牌加密失败: " + err.Error(),
			})
			return
		}
		next.ProtectedAgentToken = enc
		next.AgentToken = ""
	}
	a.mu.Unlock()

	if err := saveAgentConfigFile(a.cfgPath, &next); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok": false, "error": "写配置文件失败: " + err.Error(),
		})
		return
	}

	a.mu.Lock()
	a.cfg = next
	if tokenVal != "" {
		a.token = tokenVal
	}
	a.mu.Unlock()

	a.logger.Printf("[settings] 面板更新设置（收款站=%s）", next.ServerURL)

	// 唤醒心跳，立刻用新配置连一次
	select {
	case a.wake <- struct{}{}:
	default:
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ── 日志 ────────────────────────────────────────────────────────────

func (a *agent) handleLogs(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(a.dataDir, "logs", "agent.log")

	tail := 400
	if v := r.URL.Query().Get("tail"); v != "" {
		if n, err := fmt.Sscanf(v, "%d", &tail); n != 1 || err != nil || tail <= 0 || tail > 5000 {
			tail = 400
		}
	}

	lines, err := tailFile(path, tail)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "lines": []string{},
			"note": "日志文件还不存在（还没有日志输出）",
			"path": path, "dir": filepath.Dir(path),
		})
		return
	}

	switch strings.ToLower(r.URL.Query().Get("level")) {
	case "warn", "error":
		lv := strings.ToLower(r.URL.Query().Get("level"))
		kept := make([]string, 0, len(lines))
		for _, ln := range lines {
			low := strings.ToLower(ln)
			if strings.Contains(low, "失败") || strings.Contains(low, "错误") ||
				strings.Contains(low, "[error]") || strings.Contains(low, "异常") {
				kept = append(kept, ln)
			} else if lv == "warn" && (strings.Contains(low, "[warn]") || strings.Contains(low, "警告")) {
				kept = append(kept, ln)
			}
		}
		lines = kept
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "lines": lines, "path": path, "dir": filepath.Dir(path),
	})
}

// tailFile 读文件最后 n 行。大于 4MB 时只读尾部，避免整文件进内存。
func tailFile(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, err
	}

	const maxRead = 4 << 20
	size := st.Size()
	offset := int64(0)
	if size > maxRead {
		offset = size - maxRead
		size = maxRead
	}
	if size <= 0 {
		return []string{}, nil
	}

	buf := make([]byte, size)
	if _, err := f.ReadAt(buf, offset); err != nil && err != io.EOF {
		return nil, err
	}

	all := strings.Split(string(buf), "\n")
	if offset > 0 && len(all) > 0 {
		all = all[1:] // 首行可能是半行
	}
	for len(all) > 0 && strings.TrimSpace(all[len(all)-1]) == "" {
		all = all[:len(all)-1]
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all, nil
}

func (a *agent) handleOpenLogDir(w http.ResponseWriter, r *http.Request) {
	dir := filepath.Join(a.dataDir, "logs")
	_ = os.MkdirAll(dir, 0o755)
	openWithShell(dir)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "dir": dir})
}

// openWithShell 用资源管理器打开目录。失败不报错——前端会显示路径兜底。
func openWithShell(path string) {
	cmd := exec.Command("explorer", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Start()
}

// ── 手动注入 ────────────────────────────────────────────────────────

func (a *agent) handleInject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PID uint32 `json:"pid"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<10))
	_ = json.Unmarshal(body, &req)

	msg, err := a.injectNow(req.PID, "")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": msg})
}

// ── 微信进程列表 ────────────────────────────────────────────────────

func (a *agent) handleWeChatProcs(w http.ResponseWriter, r *http.Request) {
	type proc struct {
		PID     uint32 `json:"pid"`
		MemMB   int    `json:"memMb"`
		HasDLL  bool   `json:"hasDll"`
		Version string `json:"version"`
	}
	out := []proc{}

	if a.inj != nil && a.inj.Available() {
		pids, _ := a.inj.FindProcessByName("Weixin.exe")
		if len(pids) == 0 {
			pids, _ = a.inj.FindProcessByName("WeChat.exe")
		}
		ver := ""
		if v, _, err := version.WeChatVersion(""); err == nil {
			ver = v
		}
		for _, pid := range pids {
			p := proc{PID: pid, MemMB: processMemMB(pid), Version: ver}
			if base, err := a.inj.GetModuleBase(pid, "Weixin.dll"); err == nil && base != 0 {
				p.HasDLL = true
			}
			out = append(out, p)
		}
	}

	// 有 Weixin.dll 的排前面，其次按内存降序
	sort.Slice(out, func(i, j int) bool {
		if out[i].HasDLL != out[j].HasDLL {
			return out[i].HasDLL
		}
		return out[i].MemMB > out[j].MemMB
	})

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "procs": out})
}

// ── 小工具 ─────────────────────────────────────────────────────────

func maskToken(s string) string {
	if s == "" {
		return ""
	}
	if len(s) <= 12 {
		return "****"
	}
	return s[:8] + "****" + s[len(s)-4:]
}

// saveAgentConfigFile 原子写 agent.json（先写 .tmp 再 rename）。
func saveAgentConfigFile(path string, cfg *agentConfig) error {
	buf, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

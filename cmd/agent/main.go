// Command wxhook 是跑在挂微信的 Windows 机器上的便携程序（wxhook.exe）。
//
// 它只做两件事：
//
//  1. 抓：巡检 Weixin.exe，把 wxhook.dll 注进去，接住 DLL 投递到
//     127.0.0.1:29731/hook/payment 的到账事件，先落本地 outbox（SQLite）
//  2. 报：带 HMAC 签名 POST 到 Linux 收款站的 /api/report，送达才删
//
// 所有网页请求（下单、收银台、后台、对账）都由 Linux 那边的 epay 处理，
// 这个程序不提供任何对外的 HTTP 服务——只有一个本地面板给自己看。
//
// 首次使用：
//
//	wxhook.exe -server https://pay.example.com -token <收款站的 reportToken>
//
// 参数写进 data\config.json（令牌用 DPAPI 加密，不落明文），之后双击即可。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"wxhook/internal/inject"
	"wxhook/internal/outbox"
	"wxhook/internal/secret"
)

var agentVersion = "1.0.0"

var (
	flagServer = flag.String("server", "", "Linux 收款站地址，如 https://pay.example.com")
	flagToken  = flag.String("token", "", "上报密钥（收款站的 reportToken；写入配置时用 DPAPI 加密）")
	flagID     = flag.String("id", "", "挂机点名称，默认用计算机名")
	flagData   = flag.String("data", "", "数据目录，默认程序所在目录下的 data\\")
)

// hookListen 必须和 hook/src/DllMain.cpp 里的 kDefaultEndpoint 一致。
const hookListen = "127.0.0.1:29731"

// legacyHookListen 是旧版 DLL 的投递地址，读到就升级。
const legacyHookListen = "127.0.0.1:19089"

// defaultPanelAddr 是本地面板端口。刻意和 hookListen 分开，
// 这样即使 29731 被别的程序占了，面板仍然能打开告诉用户原因。
const defaultPanelAddr = "127.0.0.1:29732"

// ── 配置 ───────────────────────────────────────────────────────────

type agentConfig struct {
	ServerURL string `json:"serverUrl"`
	// AgentToken 只在手工填写时出现，启动后自动加密并清空
	AgentToken          string `json:"agentToken,omitempty"`
	ProtectedAgentToken string `json:"protectedAgentToken,omitempty"`
	AgentID             string `json:"agentId"`
	ListenAddr          string `json:"listenAddr"`
	PanelAddr           string `json:"panelAddr"`
	WeChatExe           string `json:"wechatExe"`
	HookDLL             string `json:"hookDLL"`
	InjectDLL           string `json:"injectDLL"`
	HeartbeatSec        int    `json:"heartbeatSec"`
}

// ── 运行时 ─────────────────────────────────────────────────────────

type agent struct {
	cfg     agentConfig
	token   string
	logger  *log.Logger
	box     *outbox.Box
	inj     *inject.Manager
	client  *http.Client
	wake    chan struct{}
	cfgPath string
	dataDir string
	startAt time.Time

	injMu sync.Mutex

	mu        sync.Mutex
	lastError string
	wxid      string
	connected atomic.Bool
	hookPortOK atomic.Bool
}

// hookEvent 是 wxhook.dll 投递过来的 JSON，字段与 hook/src/Sender.cpp 一致。
type hookEvent struct {
	Provider   string `json:"provider"`
	Amount     string `json:"amount"`
	TransNo    string `json:"transNo"`
	Sender     string `json:"sender"`
	AccountID  string `json:"accountId"`
	ReceivedAt int64  `json:"receivedAt"`
	Raw        string `json:"raw"`
	MsgID      string `json:"msgId"`
	MchID      string `json:"mchId"`
	ShopID     string `json:"shopId"`
	SourceType string `json:"sourceType"`
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "启动失败:", err)
		os.Exit(1)
	}
}

var idSanitize = regexp.MustCompile(`[^\p{L}\p{N}._-]+`)

func run() error {
	dataDir, err := resolveDataDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "logs"), 0o755); err != nil {
		return err
	}

	logFile, err := os.OpenFile(filepath.Join(dataDir, "logs", "agent.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer logFile.Close()
	logger := log.New(io.MultiWriter(os.Stdout, logFile), "", log.LstdFlags)

	// 非 Windows 调试时用 key 文件；Windows 上走 DPAPI
	secret.UseKeyFile(filepath.Join(dataDir, "secret.key"))

	cfgPath := filepath.Join(dataDir, "agent.json")
	cfg, token, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}

	box, err := outbox.Open(filepath.Join(dataDir, "outbox.db"))
	if err != nil {
		return fmt.Errorf("打开本地队列失败: %w", err)
	}
	defer box.Close()

	inj := inject.New(cfg.InjectDLL)

	a := &agent{
		cfg:     cfg,
		token:   token,
		logger:  logger,
		box:     box,
		inj:     inj,
		client:  &http.Client{Timeout: 45 * time.Second},
		wake:    make(chan struct{}, 1),
		cfgPath: cfgPath,
		dataDir: dataDir,
		startAt: time.Now(),
	}
	defer inj.Close()

	logger.Printf("===== wxhook %s 启动 =====", agentVersion)
	logger.Printf("[config] %s | 收款站 %s | 名称 %s", cfgPath, orDash(cfg.ServerURL), cfg.AgentID)
	if cfg.ServerURL == "" || token == "" {
		logger.Printf("[config] 还没配置收款站地址或上报密钥：事件会先存本地，配好后自动补发")
		logger.Printf("[config] 运行一次：wxhook.exe -server https://你的收款站 -token <reportToken>")
	}

	// ── hook 接收端口 ──
	var hookSrv *http.Server
	if ln, err := net.Listen("tcp", cfg.ListenAddr); err != nil {
		logger.Printf("[http] ⚠ 监听 %s 失败：%v", cfg.ListenAddr, err)
		logger.Printf("[http] ⚠ 本机可能已有别的程序占用。hook 事件收不到，"+
			"但面板仍可用：http://%s/", cfg.PanelAddr)
		a.setError("hook 端口 " + cfg.ListenAddr + " 被占用，到账事件收不到")
	} else {
		a.hookPortOK.Store(true)
		mux := http.NewServeMux()
		mux.HandleFunc("POST /hook/payment", a.handleHook)
		mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]any{
				"ok": true, "outbox": box.Count(), "version": agentVersion,
			})
		})
		hookSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second}
		logger.Printf("[http] 接收 wxhook 投递：http://%s/hook/payment", cfg.ListenAddr)
		go func() {
			if e := hookSrv.Serve(ln); e != nil && !errors.Is(e, http.ErrServerClosed) {
				logger.Printf("[http] 服务异常: %v", e)
			}
		}()
	}

	// ── 本地面板 ──
	panelSrv, panelErr := a.startPanel()
	if panelErr != nil {
		logger.Printf("[panel] ⚠ 面板端口 %s 绑不上：%v", cfg.PanelAddr, panelErr)
	}

	if hookSrv == nil && panelSrv == nil {
		return fmt.Errorf("hook 端口 %s 与面板端口 %s 都监听失败", cfg.ListenAddr, cfg.PanelAddr)
	}

	// ── 后台循环 ──
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	for _, f := range []func(context.Context){a.forwardLoop, a.heartbeatLoop, a.injectLoop} {
		wg.Add(1)
		go func(fn func(context.Context)) { defer wg.Done(); fn(ctx) }(f)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		logger.Printf("[main] 收到 %v，退出", s)
	case <-ctx.Done():
	}
	cancel()

	shutCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if hookSrv != nil {
		_ = hookSrv.Shutdown(shutCtx)
	}
	if panelSrv != nil {
		_ = panelSrv.Shutdown(shutCtx)
	}
	wg.Wait()
	logger.Printf("===== wxhook 已退出 =====")
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "（未配置）"
	}
	return s
}

// ── hook 事件入口 ──────────────────────────────────────────────────

func (a *agent) handleHook(w http.ResponseWriter, r *http.Request) {
	// DLL 只往本机投递；反向代理来的不算
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err != nil || (host != "127.0.0.1" && host != "::1") {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "只接受本机投递"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	var ev hookEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		a.logger.Printf("[hook] 投递 JSON 解析失败：%v｜%.200s", err, body)
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "JSON 解析失败"})
		return
	}

	id, err := a.box.Add(string(body))
	if err != nil {
		a.logger.Printf("[outbox] 落盘失败：%v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	a.logger.Printf("[hook] 收到收款 amount=%s msgId=%s，已存入队列 #%d", ev.Amount, ev.MsgID, id)

	if ev.AccountID != "" {
		a.mu.Lock()
		a.wxid = ev.AccountID
		a.mu.Unlock()
	}

	select {
	case a.wake <- struct{}{}:
	default:
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "queued": true, "id": id})
}

// ── 注入巡检 ───────────────────────────────────────────────────────

func (a *agent) injectLoop(ctx context.Context) {
	for {
		if a.inj != nil && a.inj.Available() {
			if msg, err := a.injectNow(0, ""); err != nil &&
				!errors.Is(err, errNoWeChat) && !errors.Is(err, errAlready) {
				a.logger.Printf("[inject] %v", err)
				a.setError("注入失败：" + err.Error())
			} else if err == nil {
				a.logger.Printf("[inject] %s", msg)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
}

var (
	errNoWeChat = errors.New("微信没有运行")
	errAlready  = errors.New("已经注入过")
)

// injectNow 注入一次。pid=0 时按进程名找。
func (a *agent) injectNow(pid uint32, exe string) (string, error) {
	a.injMu.Lock()
	defer a.injMu.Unlock()

	if a.inj == nil || !a.inj.Available() {
		return "", fmt.Errorf("注入能力不可用")
	}

	// 指定了 PID 就只注这个；否则找加载了 Weixin.dll 的主进程
	if pid == 0 {
		pids, err := a.findWeChat("")
		if err != nil || len(pids) == 0 {
			return "", errNoWeChat
		}
		// 优先挑加载了 Weixin.dll 的（微信 4.x 有多个同名子进程）
		primary := pids[0]
		for _, p := range pids {
			if base, err := a.inj.GetModuleBase(p, "Weixin.dll"); err == nil && base != 0 {
				primary = p
				break
			}
		}
		pid = primary
	}

	// 已经加载过就跳过
	if base, err := a.inj.GetModuleBase(pid, "wxhook.dll"); err == nil && base != 0 {
		return "", errAlready
	}

	dllPath := a.cfg.HookDLL
	if dllPath == "" {
		base, _ := exeDir()
		dllPath = filepath.Join(base, "wxhook.dll")
	}

	if err := a.inj.InjectDLL(pid, dllPath); err != nil {
		return "", err
	}
	return fmt.Sprintf("已注入 PID %d（%s）", pid, filepath.Base(dllPath)), nil
}

// findWeChat 找微信进程。返回按"像主进程"程度排序的 PID 列表。
func (a *agent) findWeChat(exe string) ([]uint32, error) {
	if a.inj == nil || !a.inj.Available() {
		return nil, errNoWeChat
	}
	name := exe
	if name == "" {
		name = a.cfg.WeChatExe
	}
	if name == "" {
		name = "Weixin.exe"
	}
	pids, err := a.inj.FindProcessByName(name)
	if err != nil {
		return nil, err
	}
	if len(pids) == 0 && name == "Weixin.exe" {
		return a.inj.FindProcessByName("WeChat.exe")
	}
	return pids, nil
}

// ── 配置读写 ───────────────────────────────────────────────────────

func resolveDataDir() (string, error) {
	if v := strings.TrimSpace(*flagData); v != "" {
		return filepath.Abs(v)
	}
	base, err := exeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "data"), nil
}

func exeDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

// loadConfig 读 agent.json，合并命令行参数，令牌加密后回写。
func loadConfig(path string) (agentConfig, string, error) {
	cfg := agentConfig{ListenAddr: hookListen, PanelAddr: defaultPanelAddr, HeartbeatSec: 5}

	if raw, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return cfg, "", fmt.Errorf("解析 %s 失败: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return cfg, "", err
	}

	dirty := false

	// 老配置里叫 gatewayUrl，迁移到 serverUrl
	if cfg.ServerURL == "" {
		var legacy struct {
			GatewayURL string `json:"gatewayUrl"`
		}
		if raw, err := os.ReadFile(path); err == nil {
			if json.Unmarshal(raw, &legacy) == nil && legacy.GatewayURL != "" {
				cfg.ServerURL = legacy.GatewayURL
				dirty = true
			}
		}
	}

	if v := strings.TrimSpace(*flagServer); v != "" {
		cfg.ServerURL, dirty = strings.TrimRight(v, "/"), true
	}
	if v := strings.TrimSpace(*flagID); v != "" {
		cfg.AgentID, dirty = v, true
	}
	if v := strings.TrimSpace(*flagToken); v != "" {
		cfg.AgentToken, dirty = v, true
	}

	if cfg.AgentID == "" {
		host, _ := os.Hostname()
		cfg.AgentID = idSanitize.ReplaceAllString(host, "-")
		if cfg.AgentID == "" {
			cfg.AgentID = "wxhook"
		}
		dirty = true
	}
	if len(cfg.AgentID) > 64 {
		cfg.AgentID = cfg.AgentID[:64]
	}

	if cfg.ListenAddr == "" || cfg.ListenAddr == legacyHookListen {
		cfg.ListenAddr, dirty = hookListen, true
	}
	if cfg.PanelAddr == "" || cfg.PanelAddr == cfg.ListenAddr {
		cfg.PanelAddr, dirty = defaultPanelAddr, true
	}
	if cfg.HeartbeatSec <= 0 {
		cfg.HeartbeatSec, dirty = 5, true
	}
	if cfg.ServerURL != "" && !strings.HasPrefix(cfg.ServerURL, "http://") &&
		!strings.HasPrefix(cfg.ServerURL, "https://") {
		return cfg, "", fmt.Errorf("收款站地址 %q 不对，应形如 https://pay.example.com", cfg.ServerURL)
	}

	token := cfg.AgentToken
	if token != "" {
		if enc, err := secret.Protect(token); err == nil {
			cfg.ProtectedAgentToken, cfg.AgentToken, dirty = enc, "", true
		}
	} else if cfg.ProtectedAgentToken != "" {
		plain, err := secret.Unprotect(cfg.ProtectedAgentToken)
		if err != nil {
			return cfg, "", fmt.Errorf("解不开配置里的令牌（换了 Windows 用户或机器？用 -token 重新填）：%w", err)
		}
		token = plain
	}

	if dirty {
		if err := saveAgentConfigFile(path, &cfg); err != nil {
			return cfg, "", err
		}
	}
	return cfg, token, nil
}

// ── 小工具 ─────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func (a *agent) setError(s string) {
	a.mu.Lock()
	a.lastError = s
	a.mu.Unlock()
}

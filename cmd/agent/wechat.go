package main

// 微信信息采集与面板启动。
//
// 拆成独立文件，避免和主流程混在一起。

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"wxhook/internal/version"
)

// weChatInfo 采集微信安装信息。面板用它显示"版本 / 路径 / 是否运行 / PID"。
type weChatInfo struct {
	ExePath  string
	Version  string
	ExeExists bool
	Running  bool
	PID      uint32
}

func (a *agent) wechatInfo() weChatInfo {
	var info weChatInfo

	if a.inj != nil && a.inj.Available() {
		if p, err := a.inj.FindWeChatExe(); err == nil && p != "" {
			info.ExePath = p
		}
	}

	dir := ""
	if info.ExePath != "" {
		dir = filepathDir(info.ExePath)
	}

	// 版本读 PE 版本资源。
	// 不要用注册表的 Version DWORD 做位运算 —— 那是微信自定义编码，
	// 0xF2541C35 按常规位运算会解成 242.84.28.53，真实是 4.1.12.53。
	if v, p, err := version.WeChatVersion(dir); err == nil {
		info.Version = v
		if info.ExePath == "" {
			info.ExePath = p
		}
	}

	if info.ExePath != "" {
		if _, err := os.Stat(info.ExePath); err == nil {
			info.ExeExists = true
		}
	}

	// 运行状态：优先取加载了 Weixin.dll 的主进程
	if a.inj != nil && a.inj.Available() {
		if pids, err := a.findWeChat(""); err == nil && len(pids) > 0 {
			info.Running = true
			info.PID = pids[0]
			for _, p := range pids {
				if base, e := a.inj.GetModuleBase(p, "Weixin.dll"); e == nil && base != 0 {
					info.PID = p
					break
				}
			}
		}
	}
	return info
}

// startPanel 在 cfg.PanelAddr 起本地面板。返回可 Shutdown 的 server。
func (a *agent) startPanel() (*http.Server, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.handlePanelIndex)
	mux.HandleFunc("GET /panel", a.handlePanelIndex)
	mux.HandleFunc("GET /api/stat", a.handlePanelStat)
	mux.HandleFunc("GET /api/settings", a.handleGetSettings)
	mux.HandleFunc("POST /api/settings", a.handleSaveSettings)
	mux.HandleFunc("GET /api/logs", a.handleLogs)
	mux.HandleFunc("POST /api/open-logs", a.handleOpenLogDir)
	mux.HandleFunc("POST /api/inject", a.handleInject)
	mux.HandleFunc("GET /api/wechat-procs", a.handleWeChatProcs)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
	}

	ln, err := net.Listen("tcp", a.cfg.PanelAddr)
	if err != nil {
		return nil, err
	}

	a.logger.Printf("[panel] 本地面板：http://%s/", a.cfg.PanelAddr)
	go func() {
		if e := srv.Serve(ln); e != nil && !errors.Is(e, http.ErrServerClosed) {
			a.logger.Printf("[panel] 服务异常: %v", e)
		}
	}()
	return srv, nil
}

// filepathDir 是 filepath.Dir 的薄封装，避免在这个文件重复 import。
func filepathDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' || p[i] == '/' {
			return p[:i]
		}
	}
	return ""
}

var _ = fmt.Sprintf

// Package inject 是 wxinject.dll 的纯 Go 绑定，外加 wxhook 状态板的读取。
//
// 设计取舍（重要）：
//
//	任务书原本写的是 cgo 绑定，但 cgo 会带来两个硬伤：
//	  1. 链接期就要拿到 .a / .lib，DLL 缺失时 go build 直接失败；
//	  2. CGO_ENABLED=0 的机器（绝大多数 CI / 干净的 Windows）编不过。
//
//	改成 syscall.NewLazyDLL 运行时加载后：
//	  - go build ./... 在没有任何 DLL 的情况下照过；
//	  - CGO_ENABLED=0 也能编译（本项目最终就产出纯 Go 单文件）；
//	  - DLL 缺失 / 导出缺失时返回"明确 error"，上层降级而不是崩溃。
//
//	所以本包只有 inject_windows.go + inject_stub.go 两个文件，用 build tag 分离，
//	DLL 符号名与 hook/include/Inject.h 逐一对应。
package inject

import (
	"errors"
	"fmt"

	"wxhook/internal/model"
)

// ErrUnsupported 表示当前构建目标不是 Windows，注入能力整体不可用。
var ErrUnsupported = errors.New("inject: 当前平台不支持 DLL 注入（需要 windows/amd64）")

// ErrDLLMissing 表示 wxinject.dll 找不到或加载不了。
// 这是一个"正常"的降级态：只跑 mock/HTTP 事件源时本来就不需要它。
var ErrDLLMissing = errors.New("inject: wxinject.dll 不可用")

// ErrHookStateMissing 表示 shared memory 状态板没创建 —— 说明 wxhook.dll 还没注入过。
var ErrHookStateMissing = errors.New("inject: 未找到 wxhook 状态板（Hook 未注入或微信未运行）")

// DLL 导出的四个函数签名，对齐 hook/include/Inject.h：
//
//	int __stdcall WxInjectDLL(DWORD pid, const wchar_t* dllPath, char* errOut, int errCap);
//	int __stdcall WxFindProcessByName(const wchar_t* exeName, DWORD* pids, int cap);
//	unsigned long long __stdcall WxGetModuleBase(DWORD pid, const wchar_t* moduleName);
//	int __stdcall WxFindWeChatExe(wchar_t* out, int cap);
type Injector interface {
	// Available 报告 DLL 是否已成功加载。false 时下面所有方法都会返回 ErrDLLMissing。
	Available() bool
	// DLLPath 返回实际加载的 DLL 路径（空表示没配置/没找到）。
	DLLPath() string

	// InjectDLL 向 pid 注入 dllPath。返回 nil 表示成功；
	// 失败时 error 里带 Win32 错误码与 DLL 自己写的中文原因。
	InjectDLL(pid uint32, dllPath string) error

	// FindProcessByName 按 exe 名枚举 PID（DLL 侧已过滤掉自身与已退出进程）。
	FindProcessByName(exeName string) ([]uint32, error)

	// GetModuleBase 读目标进程某模块的基址；未加载返回 0, nil。
	GetModuleBase(pid uint32, moduleName string) (uint64, error)

	// FindWeChatExe 从注册表 Software\Tencent\Weixin 的 InstallPath 找 Weixin.exe。
	FindWeChatExe() (string, error)

	// ReadHookStatus 读共享内存 Local\WxPayHookStatus_v1，转成 model.HookStatus。
	ReadHookStatus() (model.HookStatus, error)
}

// Manager 负责把 DLL 路径、加载状态和错误原因统一收起来，
// 让 cmd/gateway 可以"cascade"地使用：没 DLL 就只打日志，不影响其它功能。
type Manager struct {
	dllPath string
	impl    Injector
	loadErr error
}

// New 尝试加载 dllPath 指向的 wxinject.dll。
//
// dllPath 为空时按「可执行文件同目录 wxinject.dll」处理。
// 无论如何都返回一个非 nil 的 *Manager：加载失败只是把它标记成不可用，
// 由调用方决定是否告警 —— 这满足"缺失优雅降级"。
func New(dllPath string) *Manager {
	m := &Manager{dllPath: dllPath}
	impl, err := open(dllPath)
	if err != nil {
		m.loadErr = err
		m.impl = unavailable{err: err}
		return m
	}
	m.impl = impl
	m.dllPath = impl.DLLPath()
	return m
}

// Available 报告注入能力是否可用。
func (m *Manager) Available() bool { return m.impl.Available() }

// DLLPath 返回实际 DLL 路径。
func (m *Manager) DLLPath() string { return m.impl.DLLPath() }

// Err 返回"为什么不可用"，给日志和面板用；可用时返回 nil。
func (m *Manager) Err() error {
	if m.impl.Available() {
		return nil
	}
	if m.loadErr != nil {
		return m.loadErr
	}
	return ErrDLLMissing
}

func (m *Manager) InjectDLL(pid uint32, dllPath string) error {
	return m.impl.InjectDLL(pid, dllPath)
}

func (m *Manager) FindProcessByName(exeName string) ([]uint32, error) {
	return m.impl.FindProcessByName(exeName)
}

func (m *Manager) GetModuleBase(pid uint32, moduleName string) (uint64, error) {
	return m.impl.GetModuleBase(pid, moduleName)
}

func (m *Manager) FindWeChatExe() (string, error) { return m.impl.FindWeChatExe() }

func (m *Manager) ReadHookStatus() (model.HookStatus, error) { return m.impl.ReadHookStatus() }

// Close 释放底层资源（Windows 上会 FreeLibrary）。可重复调用。
// 不放进 Injector 接口是因为只有 Windows 实现持有真实句柄。
func (m *Manager) Close() {
	if c, ok := m.impl.(interface{ Close() }); ok {
		c.Close()
	}
}

// unavailable 是"没有 DLL"时的空实现，每个方法都返回明确错误，
// 绝不返回零值假装成功 —— 上层能靠 error 判断该降级还是该告警。
type unavailable struct{ err error }

func (u unavailable) Available() bool { return false }
func (u unavailable) DLLPath() string { return "" }

func (u unavailable) InjectDLL(uint32, string) error {
	return fmt.Errorf("inject: %w", u.err)
}
func (u unavailable) FindProcessByName(string) ([]uint32, error) {
	return nil, fmt.Errorf("inject: %w", u.err)
}
func (u unavailable) GetModuleBase(uint32, string) (uint64, error) {
	return 0, fmt.Errorf("inject: %w", u.err)
}
func (u unavailable) FindWeChatExe() (string, error) {
	return "", fmt.Errorf("inject: %w", u.err)
}
func (u unavailable) ReadHookStatus() (model.HookStatus, error) {
	return model.HookStatus{}, fmt.Errorf("inject: %w", u.err)
}

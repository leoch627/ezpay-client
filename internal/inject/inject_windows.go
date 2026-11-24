//go:build windows

package inject

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"wxhook/internal/model"
)

// wxinject.dll 的运行时绑定。
//
// 用 syscall.NewLazyDLL + NewProc 在**运行时**取导出符号，而不是链接期绑定：
// DLL 不存在时构造不会失败（惰性），显式 Load() 才报错，
// 这样 go build / go vet 在没有 DLL 的机器上也完全干净，CGO_ENABLED=0 同样能编。
const (
	// 状态板名字与 magic 必须和 hook/include/wxhook_abi.h 完全一致
	statusName  = `Local\WxPayHookStatus_v1`
	statusMagic = 0x57584853 // 'WXHS'

	// WxInjectDLL 的错误缓冲
	errCap = 512
	// 进程枚举上限
	maxPIDs = 64
	// 微信 exe 路径缓冲（宽字符数）
	pathCap = 1024
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procOpenFileMappingW = kernel32.NewProc("OpenFileMappingW")
	procMapViewOfFile    = kernel32.NewProc("MapViewOfFile")
	procUnmapViewOfFile  = kernel32.NewProc("UnmapViewOfFile")
	procCloseHandle      = kernel32.NewProc("CloseHandle")
)

const (
	fileMapRead     = 0x0004 // FILE_MAP_READ
	fileMappingRead = 0x0004 // FILE_MAP_READ
)

// ── 共享内存结构体 ────────────────────────────────────────────────────
//
// 逐字段对齐 hook/include/wxhook_abi.h 的 wxhook_status：
//
//	 0  uint32_t magic
//	 4  uint32_t abi_version
//	 8  uint32_t state
//	12  uint32_t pid
//	16  uint64_t module_base
//	24  uint64_t module_size
//	32  uint64_t hook_target
//	40  uint64_t hook_rva
//	48  uint64_t trampoline
//	56  uint32_t wechat_version
//	60  uint32_t required_version
//	64  uint64_t callback_count
//	72  uint64_t payment_count
//	80  uint64_t post_ok
//	88  uint64_t post_fail
//	96  uint64_t dedup_drop
//	104 uint64_t last_hit_at
//	112 uint64_t started_at
//	120 char     pattern_id[64]
//	184 char     detail[256]
//	440 = sizeof
//
// Go 与 MSVC 的 uint64 都是 8 字节对齐，因为前 4 个 uint32 正好占满 16 字节，
// 第二个 uint32 对（56..63）也是 8 字节宽，所以整个布局天然无填充，
// Go 结构体与 C 结构体等价，不需要手写 padding。
type rawHookStatus struct {
	Magic      uint32 // 0
	ABIVersion uint32 // 4
	State      uint32 // 8
	PID        uint32 // 12

	ModuleBase uint64 // 16
	ModuleSize uint64 // 24
	HookTarget uint64 // 32
	HookRVA    uint64 // 40
	Trampoline uint64 // 48

	WeChatVersion   uint32 // 56
	RequiredVersion uint32 // 60

	CallbackCount uint64 // 64
	PaymentCount  uint64 // 72
	PostOK        uint64 // 80
	PostFail      uint64 // 88
	DedupDrop     uint64 // 96

	LastHitAt uint64 // 104
	StartedAt uint64 // 112

	PatternID [64]byte  // 120
	Detail    [256]byte // 184
}

const sizeofRawHookStatus = 440

// 双向静态断言：Go 侧结构体大小必须与 C 侧完全一致，否则读写共享内存就是错的。
// 长度表达式为负会直接编译失败，两个都通过说明正好相等。
var _ [sizeofRawHookStatus - int(unsafe.Sizeof(rawHookStatus{}))]byte
var _ [int(unsafe.Sizeof(rawHookStatus{})) - sizeofRawHookStatus]byte

// winInjector 是 Injector 的 Windows 实现。
type winInjector struct {
	path string
	dll  *syscall.LazyDLL

	procInject     *syscall.LazyProc
	procFindProc   *syscall.LazyProc
	procModuleBase *syscall.LazyProc
	procFindWeChat *syscall.LazyProc

	mu sync.Mutex
}

// open 加载 dllPath 并确认四个导出都存在。
// 路径解析顺序：显式给定 → 可执行文件同目录 → 交给系统 DLL 搜索路径。
func open(dllPath string) (Injector, error) {
	var candidates []string
	if strings.TrimSpace(dllPath) != "" {
		candidates = append(candidates, dllPath)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "wxinject.dll"))
	}
	candidates = append(candidates, "wxinject.dll")

	var lastErr error
	seen := map[string]bool{}
	for _, c := range candidates {
		abs := c
		if a, err := filepath.Abs(c); err == nil {
			abs = a
		}
		if seen[abs] {
			continue
		}
		seen[abs] = true

		// 带路径的先判存在性，给出比 "The specified module could not be found" 更能用的提示
		if strings.ContainsRune(c, os.PathSeparator) || strings.ContainsRune(c, '/') {
			if _, err := os.Stat(abs); err != nil {
				lastErr = fmt.Errorf("%w: %s 不存在", ErrDLLMissing, abs)
				continue
			}
		}

		dll := syscall.NewLazyDLL(abs)
		// 显式 Load 一次，把"找不到/架构不匹配"提前到构造期
		if err := dll.Load(); err != nil {
			lastErr = fmt.Errorf("%w: LoadLibrary(%s) 失败: %v", ErrDLLMissing, abs, err)
			continue
		}

		w := &winInjector{
			path:           abs,
			dll:            dll,
			procInject:     dll.NewProc("WxInjectDLL"),
			procFindProc:   dll.NewProc("WxFindProcessByName"),
			procModuleBase: dll.NewProc("WxGetModuleBase"),
			procFindWeChat: dll.NewProc("WxFindWeChatExe"),
		}
		if err := w.resolve(); err != nil {
			lastErr = err
			continue
		}
		return w, nil
	}

	if lastErr == nil {
		lastErr = ErrDLLMissing
	}
	return nil, lastErr
}

// resolve 确认四个导出都在；缺一个就整体判不可用 —— 半残的 DLL 比没有更危险。
func (w *winInjector) resolve() error {
	for name, p := range map[string]*syscall.LazyProc{
		"WxInjectDLL":         w.procInject,
		"WxFindProcessByName": w.procFindProc,
		"WxGetModuleBase":     w.procModuleBase,
		"WxFindWeChatExe":     w.procFindWeChat,
	} {
		if err := p.Find(); err != nil {
			return fmt.Errorf("%w: %s 缺少导出 %s: %v", ErrDLLMissing, w.path, name, err)
		}
	}
	return nil
}

func (w *winInjector) Available() bool { return true }
func (w *winInjector) DLLPath() string { return w.path }

// InjectDLL 调 WxInjectDLL(pid, dllPath, errOut, errCap)。
//
// ABI：C 侧是 const wchar_t*，所以 Go string 要转 UTF-16。
// syscall.Call 期间这些 Go 内存必须存活，调用后补 runtime.KeepAlive。
func (w *winInjector) InjectDLL(pid uint32, dllPath string) error {
	if pid == 0 {
		return errors.New("inject: pid 为 0")
	}
	wPath, err := syscall.UTF16PtrFromString(dllPath)
	if err != nil {
		return fmt.Errorf("inject: DLL 路径转 UTF-16 失败: %w", err)
	}

	errBuf := make([]byte, errCap)
	rc, _, callErr := w.procInject.Call(
		uintptr(pid),
		uintptr(unsafe.Pointer(wPath)),
		uintptr(unsafe.Pointer(&errBuf[0])),
		uintptr(errCap),
	)
	runtime.KeepAlive(wPath)
	runtime.KeepAlive(errBuf)

	msg := cString(errBuf)
	if rc != 0 {
		// rc 是 Win32 错误码；DLL 自己写的中文原因在 errOut 里
		if callErr != syscall.Errno(0) {
			return fmt.Errorf("inject: WxInjectDLL(pid=%d) 失败 rc=%d: %s (%v)", pid, rc, msg, callErr)
		}
		return fmt.Errorf("inject: WxInjectDLL(pid=%d) 失败 rc=%d: %s", pid, rc, msg)
	}
	return nil
}

// FindProcessByName 调 WxFindProcessByName(exeName, pids, cap)，返回存活的 PID 列表。
// DLL 侧已过滤掉自身与已退出进程，返回 0 就是真的没有。
func (w *winInjector) FindProcessByName(exeName string) ([]uint32, error) {
	if exeName == "" {
		return nil, errors.New("inject: exeName 为空")
	}
	wName, err := syscall.UTF16PtrFromString(exeName)
	if err != nil {
		return nil, fmt.Errorf("inject: exe 名转 UTF-16 失败: %w", err)
	}

	pids := make([]uint32, maxPIDs)
	n, _, callErr := w.procFindProc.Call(
		uintptr(unsafe.Pointer(wName)),
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids)),
	)
	runtime.KeepAlive(wName)
	runtime.KeepAlive(pids)

	// DLL 侧把"快照失败"和"没有进程"都返回 0，取不到 syscall 硬错误就当没有。
	if callErr != syscall.Errno(0) && n == 0 {
		return nil, fmt.Errorf("inject: WxFindProcessByName(%s): %v", exeName, callErr)
	}
	if n > uintptr(len(pids)) {
		n = uintptr(len(pids))
	}
	out := make([]uint32, 0, n)
	for i := uintptr(0); i < n; i++ {
		if pids[i] != 0 {
			out = append(out, pids[i])
		}
	}
	return out, nil
}

// GetModuleBase 调 WxGetModuleBase(pid, moduleName)。模块未加载返回 (0, nil)，不是错误。
func (w *winInjector) GetModuleBase(pid uint32, moduleName string) (uint64, error) {
	if pid == 0 {
		return 0, errors.New("inject: pid 为 0")
	}
	wName, err := syscall.UTF16PtrFromString(moduleName)
	if err != nil {
		return 0, fmt.Errorf("inject: 模块名转 UTF-16 失败: %w", err)
	}
	base, _, callErr := w.procModuleBase.Call(uintptr(pid), uintptr(unsafe.Pointer(wName)))
	runtime.KeepAlive(wName)
	if base == 0 && callErr != syscall.Errno(0) {
		return 0, fmt.Errorf("inject: WxGetModuleBase(pid=%d, %s): %v", pid, moduleName, callErr)
	}
	return uint64(base), nil
}

// FindWeChatExe 调 WxFindWeChatExe(out, cap)。
func (w *winInjector) FindWeChatExe() (string, error) {
	buf := make([]uint16, pathCap)
	rc, _, callErr := w.procFindWeChat.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	runtime.KeepAlive(buf)
	if rc == 0 {
		if callErr != syscall.Errno(0) {
			return "", fmt.Errorf("inject: WxFindWeChatExe: %v", callErr)
		}
		return "", errors.New("inject: 注册表里没找到微信安装路径（Software\\Tencent\\Weixin → InstallPath）")
	}
	return syscall.UTF16ToString(buf), nil
}

// ReadHookStatus 映射共享内存 Local\WxPayHookStatus_v1 并读取状态块。
//
// 用 OpenFileMappingW（读）而不是 CreateFileMapping：
// 状态板由 wxhook.dll 在微信进程内创建，网关只是读者。
// 用 Create 会在 Hook 不在时凭空造出一个全零的假状态板，
// 面板就会显示"已注入 false"但其实 DLL 都没加载 —— 语义错误。
//
// 每次读都重新 Open/Map/Unmap：微信重启后状态板会重建，
// 缓存句柄会读到已死进程留下的旧数据。
func (w *winInjector) ReadHookStatus() (model.HookStatus, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	name, err := syscall.UTF16PtrFromString(statusName)
	if err != nil {
		return model.HookStatus{}, err
	}
	h, _, callErr := procOpenFileMappingW.Call(
		uintptr(fileMappingRead),
		0,
		uintptr(unsafe.Pointer(name)),
	)
	runtime.KeepAlive(name)
	if h == 0 {
		return model.HookStatus{}, fmt.Errorf("%w: OpenFileMapping(%s): %v",
			ErrHookStateMissing, statusName, callErr)
	}
	defer procCloseHandle.Call(h)

	view, _, mapErr := procMapViewOfFile.Call(h, fileMapRead, 0, 0, sizeofRawHookStatus)
	if view == 0 {
		return model.HookStatus{}, fmt.Errorf("%w: MapViewOfFile: %v", ErrHookStateMissing, mapErr)
	}
	defer procUnmapViewOfFile.Call(view)

	var raw rawHookStatus

	// view 是 uintptr（MapViewOfFile 的返回值），直接 unsafe.Pointer(view) 会触发 vet 的
	// possible-misuse 告警，所以按位重解释成指针。
	// 别改回 unsafe.Add(nil, view)：Go 1.25.x 编 windows/amd64 时会在这里
	// internal compiler error（ssa.disjointTypes: one of arguments is not a pointer）。
	// 这块内存由 MapViewOfFile 映射、defer UnmapViewOfFile 释放，不涉及 GC 堆。
	base := *(*unsafe.Pointer)(unsafe.Pointer(&view))
	src := unsafe.Slice((*byte)(base), sizeofRawHookStatus)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(&raw)), sizeofRawHookStatus)
	copy(dst, src)

	if raw.Magic != statusMagic {
		return model.HookStatus{}, fmt.Errorf("%w: magic=0x%08X（期望 0x%08X）",
			ErrHookStateMissing, raw.Magic, statusMagic)
	}

	return toHookStatus(&raw), nil
}

// Close 释放 DLL 句柄。main 的 defer 会调用它；不是 Injector 接口的一部分。
//
// syscall.LazyDLL 没有 Unload，但暴露了 Handle()，直接交给 FreeLibrary 即可。
// 只在我们自己 Load() 成功过的前提下调用（open 里保证了这点）。
func (w *winInjector) Close() {
	if w.dll == nil {
		return
	}
	if h := w.dll.Handle(); h != 0 {
		_ = syscall.FreeLibrary(syscall.Handle(h))
	}
}

// toHookStatus 把 C 结构体转成面板模型。
func toHookStatus(raw *rawHookStatus) model.HookStatus {
	return model.HookStatus{
		Attached:    raw.State == stateInstalled,
		State:       stateName(raw.State),
		StateCode:   raw.State,
		PID:         raw.PID,
		ModuleBase:  raw.ModuleBase,
		Version:     PackVersionString(raw.WeChatVersion),
		Required:    PackVersionString(raw.RequiredVersion),
		PatternID:   cString(raw.PatternID[:]),
		Detail:      cString(raw.Detail[:]),
		CallbackCnt: raw.CallbackCount,
		PaymentCnt:  raw.PaymentCount,
		PostOK:      raw.PostOK,
		PostFail:    raw.PostFail,
		DedupDrop:   raw.DedupDrop,
		LastHitAt:   int64(raw.LastHitAt),
	}
}

// stateInstalled 对应 wxhook_abi.h 的 WXHOOK_STATE_INSTALLED
const stateInstalled = 7

// stateName 是 wxhook_state 枚举的中文名，面板直接展示。
func stateName(s uint32) string {
	switch s {
	case 0:
		return "初始化"
	case 1:
		return "Weixin.dll 未加载"
	case 2:
		return "扫描特征码"
	case 3:
		return "特征码全部未命中"
	case 4:
		return "目标前导字节不安全"
	case 5:
		return "trampoline 失败"
	case 6:
		return "内存补丁失败"
	case 7:
		return "已注入"
	case 8:
		return "已卸载"
	case 9:
		return "微信版本不支持"
	default:
		return fmt.Sprintf("未知状态 %d", s)
	}
}

// PackVersionString 把 wxhook_abi.h 的 WxPackVersion 编码还原成 "4.1.10.31"。
//
//	((major&0xFF)<<24) | ((minor&0xFF)<<16) | ((build&0xFF)<<8) | (rev&0xFF)
func PackVersionString(v uint32) string {
	if v == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		(v>>24)&0xFF, (v>>16)&0xFF, (v>>8)&0xFF, v&0xFF)
}

// cString 读 C 侧 NUL 结尾的 char[]（UTF-8）。
func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

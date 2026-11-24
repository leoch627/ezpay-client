//go:build windows

package version

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

var (
	versionDLL = syscall.NewLazyDLL("version.dll")

	procGetFileVersionInfoSizeW = versionDLL.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfoW     = versionDLL.NewProc("GetFileVersionInfoW")
	procVerQueryValueW          = versionDLL.NewProc("VerQueryValueW")
)

// FileVersion 读取 PE 文件的版本号字符串，如 "4.1.12.53"。
//
// 为什么不用注册表里的 Version DWORD：
// 那个值是微信自定义打包的（0xF254200D 对应 4.1.48.13），
// 逆向报告也没解出位运算规律 —— 每组字节都套了固定偏移且规则不一致。
// 而文件版本信息是标准 VS_VERSIONINFO，直接给出 "4.1.12.53"，稳定可靠。
func FileVersion(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("version: 路径为空")
	}
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("version: %w", err)
	}

	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}

	// 先问需要多大缓冲
	size, _, callErr := procGetFileVersionInfoSizeW.Call(uintptr(unsafe.Pointer(p)), 0)
	if size == 0 {
		return "", fmt.Errorf("version: GetFileVersionInfoSizeW 失败（不是 PE 或没有版本资源）: %v", callErr)
	}

	buf := make([]byte, size)
	r, _, callErr := procGetFileVersionInfoW.Call(
		uintptr(unsafe.Pointer(p)),
		0,
		size,
		uintptr(unsafe.Pointer(&buf[0])),
	)
	if r == 0 {
		return "", fmt.Errorf("version: GetFileVersionInfoW 失败: %v", callErr)
	}

	// 取固定版本信息（VS_FIXEDFILEINFO），自己拼 "a.b.c.d"
	const subBlock = `\`
	sub, err := syscall.UTF16PtrFromString(subBlock)
	if err != nil {
		return "", err
	}

	var ptr unsafe.Pointer
	var length uint32
	r, _, callErr = procVerQueryValueW.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(sub)),
		uintptr(unsafe.Pointer(&ptr)),
		uintptr(unsafe.Pointer(&length)),
	)
	if r == 0 || ptr == nil || length < 52 {
		return "", fmt.Errorf("version: VerQueryValueW 取根块失败: %v", callErr)
	}

	// VS_FIXEDFILEINFO 布局：
	//   0  dwSignature
	//   4  dwStrucVersion
	//   8  dwFileVersionMS   (hi = major, lo = minor)
	//   12 dwFileVersionLS   (hi = build, lo = revision)
	ms := *(*uint32)(unsafe.Add(ptr, 8))
	ls := *(*uint32)(unsafe.Add(ptr, 12))

	out := fmt.Sprintf("%d.%d.%d.%d",
		ms>>16, ms&0xFFFF, ls>>16, ls&0xFFFF)

	// 全零说明没填版本资源
	if out == "0.0.0.0" {
		return "", fmt.Errorf("version: 文件没有填写版本号")
	}
	return out, nil
}

// WeChatVersion 找到微信主程序并读它的版本。
// 优先 Weixin.exe（4.x），其次 WeChat.exe（3.x）。
func WeChatVersion(installDir string) (version string, exePath string, err error) {
	candidates := []string{}

	if installDir != "" {
		candidates = append(candidates,
			filepath.Join(installDir, "Weixin.exe"),
			filepath.Join(installDir, "WeChat.exe"))
	}

	// 常见安装位置兜底
	for _, base := range []string{
		`C:\Program Files\Tencent\Weixin`,
		`C:\Program Files (x86)\Tencent\Weixin`,
		`C:\Program Files\Tencent\WeChat`,
		`C:\Program Files (x86)\Tencent\WeChat`,
	} {
		candidates = append(candidates,
			filepath.Join(base, "Weixin.exe"),
			filepath.Join(base, "WeChat.exe"))
	}

	for _, p := range candidates {
		if _, statErr := os.Stat(p); statErr != nil {
			continue
		}
		v, verr := FileVersion(p)
		if verr != nil {
			continue
		}
		return v, p, nil
	}

	return "", "", fmt.Errorf("version: 没找到微信主程序")
}

// Compare 比较两个 "a.b.c.d" 版本号。返回 -1 / 0 / 1。
func Compare(a, b string) int {
	pa, pb := splitVer(a), splitVer(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}

func splitVer(s string) []int {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return out
		}
		out = append(out, n)
	}
	return out
}

//go:build !windows

package secret

// 非 Windows 平台的桩：直接报错，绝不静默降级成明文
// （静默降级会让"加密"变成假象，比不加密更危险）

func dpapiProtect([]byte) ([]byte, error) {
	return nil, ErrPlatform
}

func dpapiUnprotect([]byte) ([]byte, error) {
	return nil, ErrPlatform
}

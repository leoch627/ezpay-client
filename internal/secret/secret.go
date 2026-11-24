// Package secret 提供与 Windows DPAPI 的互操作。
//
// 为什么需要它：真实运行数据里，商户密钥不是明文存的，而是
//
//	settings.json -> "protectedMerchantSecret": "AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA..."
//
// 那串 base64 的头部 01 00 00 00 D0 8C 9D DF 正是 CryptProtectData 的输出魔数。
// 作用域是 CurrentUser，所以同一 Windows 用户下可直接解开。
//
// 我们的实现同时支持两种模式：
//   - protected*（DPAPI blob）：与真实程序行为一致，换机器解不开（更安全）
//   - 明文：方便调试与迁移，启动时若检测到明文会自动加密并清空明文
package secret

import (
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"
)

// Prefix 与真实程序的加密前缀保持一致，便于直接读它的配置
const Prefix = "enc:v1:"

var (
	ErrEmpty    = errors.New("secret: 输入为空")
	ErrNotBlob  = errors.New("secret: 不是有效的 DPAPI blob")
	ErrPlatform = errors.New("secret: 当前平台不支持 DPAPI（需要 Windows）")
)

// IsProtected 判断一个字符串是否已是 DPAPI blob（裸 base64 或带 enc:v1: 前缀）
func IsProtected(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, FilePrefix) {
		return true
	}
	raw := strings.TrimPrefix(s, Prefix)
	// DPAPI blob 至少 200 字节，base64 后 270+ 字符
	if len(raw) < 100 {
		return false
	}
	// 前缀特征：AQAAANCM (base64 of 01000000D08C...)
	return strings.HasPrefix(raw, "AQAAANCM")
}

// Protect 明文 -> 密文。
//
//	Windows：enc:v1:base64(DPAPI blob)，与真实程序一致
//	其它平台：enc:fk1:base64(AES-GCM)，密钥在 UseKeyFile 指定的文件里
func Protect(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	if runtime.GOOS != "windows" {
		return fileProtect([]byte(plain))
	}
	blob, err := dpapiProtect([]byte(plain))
	if err != nil {
		return "", err
	}
	return Prefix + base64.StdEncoding.EncodeToString(blob), nil
}

// Unprotect 支持三种输入：空、明文、enc:v1:密文
// 明文原样返回，不报错 —— 这样迁移期两种格式都能用。
func Unprotect(s string) (string, error) {
	if s == "" {
		return "", nil
	}
	if !IsProtected(s) {
		return s, nil // 明文
	}
	if strings.HasPrefix(s, FilePrefix) {
		return fileUnprotect(s)
	}
	raw := strings.TrimPrefix(s, Prefix)
	blob, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("%w: base64 解码失败: %v", ErrNotBlob, err)
	}
	out, err := dpapiUnprotect(blob)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// dpapiProtect / dpapiUnprotect 在 dpapi_windows.go 与 dpapi_stub.go 里实现
var _ = unsafe.Pointer(nil) // 保持 unsafe 导入（两个平台文件都会用到）

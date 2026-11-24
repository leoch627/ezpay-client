//go:build windows

package secret

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var (
	crypt32            = syscall.NewLazyDLL("crypt32.dll")
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procCryptProtect   = crypt32.NewProc("CryptProtectData")
	procCryptUnprotect = crypt32.NewProc("CryptUnprotectData")
	procLocalFree      = kernel32.NewProc("LocalFree")
)

// DATA_BLOB 对应 Windows 的 DATA_BLOB 结构
type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(d []byte) *dataBlob {
	if len(d) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{cbData: uint32(len(d)), pbData: &d[0]}
}

func (b *dataBlob) bytes() []byte {
	if b.pbData == nil || b.cbData == 0 {
		return nil
	}
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

func (b *dataBlob) free() {
	if b.pbData != nil {
		procLocalFree.Call(uintptr(unsafe.Pointer(b.pbData)))
		b.pbData = nil
		b.cbData = 0
	}
}

func dpapiProtect(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, ErrEmpty
	}

	in := newBlob(plain)
	var out dataBlob

	// CryptProtectData(pDataIn, szDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut)
	r, _, err := procCryptProtect.Call(
		uintptr(unsafe.Pointer(in)),
		0, // 描述
		0, // entropy
		0, // reserved
		0, // prompt
		0, // flags: 0 = CurrentUser 作用域（默认）
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("secret: CryptProtectData 失败: %v", err)
	}
	defer out.free()

	return out.bytes(), nil
}

func dpapiUnprotect(blob []byte) ([]byte, error) {
	if len(blob) < 16 {
		return nil, ErrNotBlob
	}

	in := newBlob(blob)
	var out dataBlob

	r, _, err := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(in)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("secret: CryptUnprotectData 失败（blob 属于其他用户/机器？）: %v", err)
	}
	defer out.free()

	if out.cbData == 0 {
		return nil, errors.New("secret: 解密结果为空")
	}
	return out.bytes(), nil
}

package secret

// 非 Windows 平台（Linux 网关）的密钥保护：本机密钥文件 + AES-256-GCM。
//
// 为什么不是 DPAPI：Linux 没有 DPAPI。为什么不是明文：config.json 常被备份、
// 拷贝、贴进工单，明文密钥在这些路径上会泄露；拆成"密文在 config.json、
// 密钥在 secret.key（0600）"后，单独泄露任何一个文件都拿不到密钥。
//
// 它和 DPAPI 的安全模型一样：防的是"配置文件外流"，不防拿到本机 root 的人。

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FilePrefix 是密钥文件方案的密文前缀，和 DPAPI 的 enc:v1: 区分开。
const FilePrefix = "enc:fk1:"

const keyLen = 32

var (
	keyMu   sync.Mutex
	keyPath string
	keyData []byte
)

// UseKeyFile 指定密钥文件位置（网关启动时传 data/secret.key）。
// 文件不存在时在第一次加密时生成。Windows 上不调用也没关系，继续走 DPAPI。
func UseKeyFile(path string) {
	keyMu.Lock()
	defer keyMu.Unlock()
	keyPath = path
	keyData = nil
}

// loadKey 读或生成密钥。create=false 时文件不存在直接报错（解密场景）。
func loadKey(create bool) ([]byte, error) {
	keyMu.Lock()
	defer keyMu.Unlock()
	if keyData != nil {
		return keyData, nil
	}
	if keyPath == "" {
		return nil, ErrPlatform
	}
	k, err := readKeyFile(keyPath)
	switch {
	case err == nil:
		keyData = k
		return k, nil
	case errors.Is(err, os.ErrNotExist) && create:
		k := make([]byte, keyLen)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
			return nil, err
		}
		// O_EXCL：两个进程同时首启时只有一个能写成功，另一个回头读
		f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				if k, rerr := readKeyFile(keyPath); rerr == nil {
					keyData = k
					return k, nil
				}
			}
			return nil, err
		}
		_, werr := f.WriteString(base64.StdEncoding.EncodeToString(k) + "\n")
		cerr := f.Close()
		if werr != nil || cerr != nil {
			return nil, fmt.Errorf("secret: 写密钥文件失败: %v %v", werr, cerr)
		}
		keyData = k
		return k, nil
	case errors.Is(err, os.ErrNotExist):
		return nil, fmt.Errorf("secret: 密钥文件 %s 不存在（换机器或被删除了？需要重新填写密钥）", keyPath)
	default:
		return nil, err
	}
}

func readKeyFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(k) != keyLen {
		return nil, fmt.Errorf("secret: 密钥文件 %s 已损坏", path)
	}
	return k, nil
}

func fileProtect(plain []byte) (string, error) {
	k, err := loadKey(true)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out := gcm.Seal(nonce, nonce, plain, []byte(FilePrefix))
	return FilePrefix + base64.StdEncoding.EncodeToString(out), nil
}

func fileUnprotect(s string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, FilePrefix))
	if err != nil {
		return "", fmt.Errorf("%w: base64 解码失败: %v", ErrNotBlob, err)
	}
	k, err := loadKey(false)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", ErrNotBlob
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], []byte(FilePrefix))
	if err != nil {
		return "", fmt.Errorf("%w: 解密失败（密钥文件不匹配或密文被改过）", ErrNotBlob)
	}
	return string(plain), nil
}

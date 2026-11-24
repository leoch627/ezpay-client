//go:build !windows

package version

import "errors"

var ErrUnsupported = errors.New("version: 仅 Windows 支持读取 PE 版本信息")

func FileVersion(string) (string, error) { return "", ErrUnsupported }

func WeChatVersion(string) (string, string, error) { return "", "", ErrUnsupported }

// Compare 跨平台纯字符串比较，非 Windows 下也能用
func Compare(a, b string) int { return 0 }

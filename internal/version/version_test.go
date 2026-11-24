//go:build windows

package version

import (
	"os"
	"testing"
)

const weixinExe = `C:\Program Files\Tencent\Weixin\Weixin.exe`

func TestWeChatVersion(t *testing.T) {
	if _, err := os.Stat(weixinExe); err != nil {
		t.Skip("本机没有安装微信，跳过")
	}

	ver, path, err := WeChatVersion(`C:\Program Files\Tencent\Weixin`)
	if err != nil {
		t.Fatalf("WeChatVersion: %v", err)
	}

	t.Logf("版本=%s  路径=%s", ver, path)

	if ver == "" {
		t.Error("版本为空")
	}

	// 必须是 a.b.c.d 四段数字，不能是 0.0.0.0
	if Compare(ver, "0.0.0.0") == 0 {
		t.Errorf("版本是全零: %s", ver)
	}

	// 4.x 的 major 必须是 3 或 4（防止又出现 242.84 那种解码错误）
	parts := splitVer(ver)
	if len(parts) < 2 {
		t.Fatalf("版本格式不合法: %s", ver)
	}
	if parts[0] < 3 || parts[0] > 4 {
		t.Errorf("major 异常: %d（期望 3 或 4，实际版本 %s）", parts[0], ver)
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"4.1.12.53", "4.1.10.31", 1},
		{"4.1.10.31", "4.1.12.53", -1},
		{"4.1.12.53", "4.1.12.53", 0},
		{"4.1", "4.1.0.0", 0},
		{"5.0.0.0", "4.9.9.9", 1},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q,%q)=%d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestFileVersionMissing(t *testing.T) {
	if _, err := FileVersion(`C:\definitely\not\here.exe`); err == nil {
		t.Error("不存在的文件应报错")
	}
	if _, err := FileVersion(""); err == nil {
		t.Error("空路径应报错")
	}
}

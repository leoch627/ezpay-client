package secret

import (
	"runtime"
	"strings"
	"testing"
)

func TestIsProtected(t *testing.T) {
	cases := map[string]bool{
		"":                    false,
		"plain-text-token":    false,
		"test-token-abc123":   false,
		Prefix + "AQAAANCM":   false, // 太短
		"enc:v1:" + strings.Repeat("AQAAANCM", 40): true,
		strings.Repeat("AQAAANCM", 40):             true, // 裸 blob 也认
	}
	for in, want := range cases {
		if got := IsProtected(in); got != want {
			t.Errorf("IsProtected(%q) = %v, want %v", trunc(in), got, want)
		}
	}
}

// 明文必须原样返回 —— 迁移期兼容旧配置
func TestUnprotectPassThrough(t *testing.T) {
	for _, s := range []string{"", "my-plain-token", "test-token-abc123"} {
		got, err := Unprotect(s)
		if err != nil {
			t.Errorf("Unprotect(%q) 明文不应报错: %v", s, err)
			continue
		}
		if got != s {
			t.Errorf("Unprotect(%q) = %q，明文应原样返回", s, got)
		}
	}
}

// DPAPI 往返：加密后能解回原文
func TestProtectRoundTrip(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("DPAPI 仅 Windows")
	}

	plain := "a-very-secret-report-token-0123456789"
	enc, err := Protect(plain)
	if err != nil {
		t.Fatalf("Protect 失败: %v", err)
	}
	if !strings.HasPrefix(enc, Prefix) {
		t.Errorf("密文缺少前缀 %q: %s", Prefix, trunc(enc))
	}
	if !IsProtected(enc) {
		t.Errorf("IsProtected 未识别自己生成的密文")
	}

	back, err := Unprotect(enc)
	if err != nil {
		t.Fatalf("Unprotect 失败: %v", err)
	}
	if back != plain {
		t.Errorf("往返不一致: %q != %q", back, plain)
	}
}

// 空串加密应返回空串（不需要保护，也不该产生垃圾 blob）
func TestProtectEmpty(t *testing.T) {
	enc, err := Protect("")
	if err != nil {
		t.Fatalf("Protect(\"\") 报错: %v", err)
	}
	if enc != "" {
		t.Errorf("空串应返回空串，实际: %q", enc)
	}
}

// 篡改的 blob 必须报错，不能静默返回垃圾
func TestUnprotectTampered(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("DPAPI 仅 Windows")
	}
	enc, err := Protect("hello")
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}
	// 破坏中间一段
	bad := enc[:len(Prefix)+20] + "XXXXXXXXXXXXXXXXXXXX" + enc[len(Prefix)+40:]
	if _, err := Unprotect(bad); err == nil {
		t.Error("篡改后的 blob 应报错")
	}
}

func trunc(s string) string {
	if len(s) <= 40 {
		return s
	}
	return s[:40] + "..."
}

// 密钥文件方案：非 Windows 平台的默认实现，任何平台都能直接测
func TestFileKeyRoundTrip(t *testing.T) {
	UseKeyFile(t.TempDir() + "/secret.key")
	defer UseKeyFile("")

	enc, err := fileProtect([]byte("linux-gateway-secret"))
	if err != nil {
		t.Fatalf("fileProtect: %v", err)
	}
	if !strings.HasPrefix(enc, FilePrefix) || !IsProtected(enc) {
		t.Fatalf("密文格式不对: %s", trunc(enc))
	}
	back, err := Unprotect(enc)
	if err != nil || back != "linux-gateway-secret" {
		t.Fatalf("往返失败: %q %v", back, err)
	}

	// 换一把密钥（模拟换机器）必须解不开，而不是返回垃圾
	UseKeyFile(t.TempDir() + "/other.key")
	if _, err := fileProtect([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := Unprotect(enc); err == nil {
		t.Error("密钥不匹配时应报错")
	}
}

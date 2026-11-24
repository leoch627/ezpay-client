package auth

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

// RFC 7914 §11 给出的 PBKDF2-HMAC-SHA256 测试向量
func TestPBKDF2Vector(t *testing.T) {
	got := hex.EncodeToString(pbkdf2([]byte("passwd"), []byte("salt"), 1, 64))
	want := "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
	if got != want {
		t.Fatalf("pbkdf2 向量不符:\n got %s\nwant %s", got, want)
	}
}

func TestPasswordRoundTrip(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Error("太短的密码应拒绝")
	}
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "correct horse") || CheckPassword(h, "wrong horse") || CheckPassword("garbage", "x") {
		t.Error("密码校验结果不对")
	}
}

func TestBearer(t *testing.T) {
	plain, hash, err := NewAgentToken()
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/agent/heartbeat", nil)
	if CheckBearer(r, hash) {
		t.Error("没带令牌不应通过")
	}
	r.Header.Set("Authorization", "Bearer "+plain)
	if !CheckBearer(r, hash) || CheckBearer(r, "") {
		t.Error("令牌校验结果不对")
	}
}

func TestDirectLoopback(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/snapshot", nil)
	r.RemoteAddr = "127.0.0.1:50000"
	if !IsDirectLoopback(r) {
		t.Error("本机直连应放行")
	}
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	if IsDirectLoopback(r) {
		t.Error("经过反向代理的请求不能当成本机")
	}
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "10.0.0.8:1234"
	if IsDirectLoopback(r2) {
		t.Error("局域网地址不是本机")
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:50000"
	r.Header.Set("X-Real-Ip", "203.0.113.9")
	if got := ClientIP(r); got != "203.0.113.9" {
		t.Errorf("本机反代转进来的请求应取 X-Real-Ip，得到 %s", got)
	}
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.RemoteAddr = "198.51.100.7:1234"
	r2.Header.Set("X-Real-Ip", "127.0.0.1")
	if got := ClientIP(r2); got != "198.51.100.7" {
		t.Errorf("外网直连伪造的 X-Real-Ip 不能采信，得到 %s", got)
	}
}

func TestSessionCookie(t *testing.T) {
	s := NewSessions()
	h, _ := HashPassword("correct horse")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/auth/login", nil)
	s.Issue(rec, req, h)

	r := httptest.NewRequest("GET", "/api/snapshot", nil)
	for _, c := range rec.Result().Cookies() {
		r.AddCookie(c)
	}
	if !s.Valid(r, h) {
		t.Fatal("刚签发的会话应有效")
	}
	h2, _ := HashPassword("another password")
	if s.Valid(r, h2) {
		t.Error("改密码后旧会话应失效")
	}
	if NewSessions().Valid(r, h) {
		t.Error("网关重启（新进程密钥）后旧会话应失效")
	}
	_ = http.StatusOK
}

// Package auth 是网关的两道门：
//
//   - 面板：浏览器用密码登录，拿 HttpOnly 会话 cookie。
//     没设密码时只放行"直连本机"的请求 —— 网关一旦监听 0.0.0.0，
//     任何人都能改上游地址把钱导走，所以没有密码就绝不对外开放。
//   - 代理：Windows 代理带 Authorization: Bearer <接入令牌>。
//     网关只存令牌的 SHA-256，明文只在生成那一刻显示一次。
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CookieName 是面板会话 cookie 名。
const CookieName = "wxpay_session"

// SessionTTL 会话有效期。本工具是运维面板，一周足够，过期重登即可。
const SessionTTL = 7 * 24 * time.Hour

const pbkdf2Iter = 210_000

// ── 密码 ───────────────────────────────────────────────────────────

// HashPassword 产出 "pbkdf2-sha256$iter$salt$hash"（salt/hash 为 base64）。
func HashPassword(pw string) (string, error) {
	if len(pw) < 8 {
		return "", errors.New("密码至少 8 位")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	dk := pbkdf2([]byte(pw), salt, pbkdf2Iter, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdf2Iter,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk)), nil
}

// CheckPassword 常数时间比较。格式不对一律返回 false。
func CheckPassword(stored, pw string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[2])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got := pbkdf2([]byte(pw), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// pbkdf2 是 RFC 8018 的 PBKDF2-HMAC-SHA256。手写是为了不把 go.mod 抬到 1.24。
func pbkdf2(pw, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, pw)
	hLen := prf.Size()
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	buf := make([]byte, 4)
	for b := 1; b <= blocks; b++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(b))
		prf.Write(buf)
		u := prf.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// ── 代理令牌 ───────────────────────────────────────────────────────

// NewAgentToken 生成接入令牌明文（给人看一次）和它的哈希（存配置）。
func NewAgentToken() (plain, hash string, err error) {
	b := make([]byte, 24)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	plain = "wxa_" + base64.RawURLEncoding.EncodeToString(b)
	return plain, HashToken(plain), nil
}

// HashToken 令牌是高熵随机串，单次 SHA-256 足够，不需要慢哈希。
func HashToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// CheckBearer 校验 Authorization: Bearer xxx。hash 为空表示还没生成令牌，一律拒绝。
func CheckBearer(r *http.Request, hash string) bool {
	if hash == "" {
		return false
	}
	h := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(h, "Bearer ")
	if !ok || tok == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(HashToken(strings.TrimSpace(tok))), []byte(hash)) == 1
}

// ── 会话 ───────────────────────────────────────────────────────────

// Sessions 签发与校验会话 cookie。
//
// cookie = 过期时间 . HMAC(key, 过期时间)。key 由进程随机数 + 当前密码哈希派生，
// 所以改密码或重启网关后所有旧会话立刻失效，不需要服务端存会话表。
type Sessions struct {
	procKey []byte

	mu       sync.Mutex
	failures map[string][]time.Time
}

func NewSessions() *Sessions {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return &Sessions{procKey: k, failures: map[string][]time.Time{}}
}

func (s *Sessions) mac(passHash string, exp int64) string {
	m := hmac.New(sha256.New, s.procKey)
	m.Write([]byte(passHash))
	m.Write([]byte{0})
	m.Write([]byte(strconv.FormatInt(exp, 10)))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// Issue 写会话 cookie。
func (s *Sessions) Issue(w http.ResponseWriter, r *http.Request, passHash string) {
	exp := time.Now().Add(SessionTTL).Unix()
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    strconv.FormatInt(exp, 10) + "." + s.mac(passHash, exp),
		Path:     "/",
		Expires:  time.Unix(exp, 0),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   IsHTTPS(r),
	})
}

// Clear 删除会话 cookie。
func (s *Sessions) Clear(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: IsHTTPS(r),
	})
}

// Valid 校验请求里的会话 cookie。
func (s *Sessions) Valid(r *http.Request, passHash string) bool {
	if passHash == "" {
		return false
	}
	c, err := r.Cookie(CookieName)
	if err != nil {
		return false
	}
	expStr, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	return hmac.Equal([]byte(sig), []byte(s.mac(passHash, exp)))
}

// 登录限速：每个来源 IP 15 分钟内最多失败 10 次。
const (
	failWindow = 15 * time.Minute
	failLimit  = 10
)

// Throttled 报告该来源是否因失败过多被暂时锁定。
func (s *Sessions) Throttled(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.recentLocked(ip)) >= failLimit
}

// Fail 记一次失败。
func (s *Sessions) Fail(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failures[ip] = append(s.recentLocked(ip), time.Now())
}

// Succeed 清掉该来源的失败记录。
func (s *Sessions) Succeed(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.failures, ip)
}

func (s *Sessions) recentLocked(ip string) []time.Time {
	cut := time.Now().Add(-failWindow)
	l := s.failures[ip]
	i := 0
	for i < len(l) && l[i].Before(cut) {
		i++
	}
	l = l[i:]
	if len(l) == 0 {
		delete(s.failures, ip)
		return nil
	}
	s.failures[ip] = l
	return l
}

// ── 来源判断 ───────────────────────────────────────────────────────

// proxyHeaders 出现任意一个，就说明请求经过了反向代理：
// 此时 RemoteAddr 是代理自己的 127.0.0.1，绝不能当成本机直连放行。
var proxyHeaders = []string{"X-Forwarded-For", "X-Real-Ip", "Forwarded", "X-Forwarded-Host"}

// IsDirectLoopback 报告请求是否来自本机且没经过反向代理。
func IsDirectLoopback(r *http.Request) bool {
	for _, h := range proxyHeaders {
		if r.Header.Get(h) != "" {
			return false
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ClientIP 给限速和日志用。
//
// 只有 RemoteAddr 是回环地址时才信 X-Real-IP：那说明请求是本机反代（nginx）转进来的，
// 而外网来的连接 RemoteAddr 不可能是 127.0.0.1，伪造这个头也不会被采信。
// 不这样做的话，放在 nginx 后面所有人都是 127.0.0.1：
// 一个人输错 10 次密码，所有人一起被锁 15 分钟。
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if real := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-Ip"))); real != nil {
			return real.String()
		}
	}
	return host
}

// IsHTTPS 判断浏览器看到的是不是 https（直连 TLS 或反代声明）。
func IsHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// SameOrigin 防 CSRF：带 Origin 头的写请求必须与 Host 一致。
// 没有 Origin（curl、旧浏览器的同源 GET）放行，配合 SameSite=Strict 已足够。
func SameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return true
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	o = strings.TrimPrefix(strings.TrimPrefix(o, "https://"), "http://")
	return strings.EqualFold(o, host)
}

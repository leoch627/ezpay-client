// Package outbox 是 Windows 代理的本地发件箱。
//
// wxhook.dll 只投递一次、不重试（见 hook/src/Sender.cpp），所以代理必须
// "先落盘、再回 200"：网关不在线、网络断了、代理重启，收款都不会丢。
// 送达网关后才删除；网关按 msgId/指纹去重，重复送达是安全的。
package outbox

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS outbox (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	body       TEXT    NOT NULL,
	created_at INTEGER NOT NULL,
	attempts   INTEGER NOT NULL DEFAULT 0,
	next_try   INTEGER NOT NULL DEFAULT 0,
	last_err   TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_outbox_next ON outbox(next_try);
`

// Item 是一笔待转发的原始 Hook 事件。
type Item struct {
	ID       int64
	Body     string // wxhook 投递的 JSON 原文
	Attempts int
}

type Box struct {
	mu sync.Mutex
	db *sql.DB
}

func Open(path string) (*Box, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("建表失败: %w", err)
	}
	return &Box{db: db}, nil
}

func (b *Box) Close() error { return b.db.Close() }

// Add 落盘一笔事件，返回 id。synchronous=FULL：返回即已写到磁盘。
func (b *Box) Add(body string) (int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	res, err := b.db.Exec(`INSERT INTO outbox(body, created_at, next_try) VALUES(?, ?, 0)`, body, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Due 取到期的事件，按入库顺序。
func (b *Box) Due(now int64, limit int) ([]Item, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	rows, err := b.db.Query(`SELECT id, body, attempts FROM outbox WHERE next_try <= ? ORDER BY id LIMIT ?`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.Body, &it.Attempts); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// Done 送达后删除。
func (b *Box) Done(id int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, err := b.db.Exec(`DELETE FROM outbox WHERE id=?`, id)
	return err
}

// Retry 记一次失败并推迟。
func (b *Box) Retry(id int64, attempts int, next time.Time, msg string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, err := b.db.Exec(`UPDATE outbox SET attempts=?, next_try=?, last_err=? WHERE id=?`, attempts, next.Unix(), msg, id)
	return err
}

// Count 返回还没送达的事件数，随心跳报给网关，面板上能看到"积压"。
func (b *Box) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	var n int
	_ = b.db.QueryRow(`SELECT COUNT(*) FROM outbox`).Scan(&n)
	return n
}

// Backoff：2s 起翻倍，封顶 60s。网关恢复后最多一分钟内全部补发。
func Backoff(attempts int) time.Duration {
	d := 2 * time.Second
	for i := 1; i < attempts && d < 60*time.Second; i++ {
		d *= 2
	}
	if d > 60*time.Second {
		d = 60 * time.Second
	}
	return d
}

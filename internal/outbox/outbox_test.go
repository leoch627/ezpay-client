package outbox

import (
	"path/filepath"
	"testing"
	"time"
)

func TestOutboxLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "outbox.db")
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id1, _ := b.Add(`{"amount":"1.00"}`)
	id2, _ := b.Add(`{"amount":"2.00"}`)

	now := time.Now()
	if err := b.Retry(id1, 1, now.Add(time.Minute), "网关不可达"); err != nil {
		t.Fatal(err)
	}
	due, err := b.Due(now.Unix(), 10)
	if err != nil || len(due) != 1 || due[0].ID != id2 {
		t.Fatalf("推迟的那笔不应到期: %+v %v", due, err)
	}
	_ = b.Done(id2)
	b.Close()

	// 重启后积压还在
	b, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if n := b.Count(); n != 1 {
		t.Fatalf("重启后应还剩 1 笔，实际 %d", n)
	}
}

func TestBackoff(t *testing.T) {
	cases := map[int]time.Duration{1: 2 * time.Second, 2: 4 * time.Second, 5: 32 * time.Second, 6: 60 * time.Second, 50: 60 * time.Second}
	for n, want := range cases {
		if got := Backoff(n); got != want {
			t.Errorf("Backoff(%d) = %v, want %v", n, got, want)
		}
	}
}

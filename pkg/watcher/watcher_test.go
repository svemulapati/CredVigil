package watcher

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func tempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "credvigil-watcher-*")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return p
}

func waitFor(t *testing.T, d time.Duration, msg string, fn func() bool) {
	t.Helper()
	dl := time.Now().Add(d)
	for time.Now().Before(dl) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", msg)
}

func TestNewWatcher_NilHandler(t *testing.T) {
	_, err := New(Config{Paths: []string{"/tmp"}}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewWatcher_NoPaths(t *testing.T) {
	_, err := New(Config{}, func(e Event) {})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNewWatcher_Valid(t *testing.T) {
	dir := tempDir(t)
	w, err := New(Config{Paths: []string{dir}}, func(e Event) {})
	if err != nil {
		t.Fatal(err)
	}
	_ = w.fsw.Close()
}

func TestNewWatcher_DefaultDebounce(t *testing.T) {
	dir := tempDir(t)
	w, err := New(Config{Paths: []string{dir}, DebounceInterval: 0}, func(e Event) {})
	if err != nil {
		t.Fatal(err)
	}
	if w.config.DebounceInterval != 500*time.Millisecond {
		t.Fatalf("got %v, want 500ms", w.config.DebounceInterval)
	}
	_ = w.fsw.Close()
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.Recursive {
		t.Error("Recursive should be true")
	}
	if cfg.DebounceInterval != 500*time.Millisecond {
		t.Errorf("DebounceInterval = %v", cfg.DebounceInterval)
	}
	if len(cfg.ExcludeDirs) == 0 {
		t.Error("ExcludeDirs empty")
	}
	if len(cfg.ExcludeExtensions) == 0 {
		t.Error("ExcludeExtensions empty")
	}
}

func TestEventTypeString(t *testing.T) {
	cases := map[EventType]string{
		EventCreated:  "CREATED",
		EventModified: "MODIFIED",
		EventDeleted:  "DELETED",
		EventRenamed:  "RENAMED",
		EventType(99): "UNKNOWN",
	}
	for ev, want := range cases {
		if got := ev.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", ev, got, want)
		}
	}
}

func TestShouldSkip(t *testing.T) {
	dir := tempDir(t)
	w, _ := New(Config{
		Paths:             []string{dir},
		ExcludeDirs:       []string{".git", "node_modules"},
		ExcludeExtensions: []string{".exe", ".png"},
		ExcludeFiles:      []string{"package-lock.json"},
	}, func(e Event) {})
	defer func() { _ = w.fsw.Close() }()

	tests := []struct {
		path string
		skip bool
	}{
		{"/project/src/main.go", false},
		{"/project/.git/config", true},
		{"/project/node_modules/foo/index.js", true},
		{"/project/app.exe", true},
		{"/project/icon.png", true},
		{"/project/package-lock.json", true},
		{"/project/src/app.py", false},
	}
	for _, tc := range tests {
		if got := w.shouldSkip(tc.path); got != tc.skip {
			t.Errorf("shouldSkip(%q) = %v, want %v", tc.path, got, tc.skip)
		}
	}
}

func TestShouldSkip_IncludeExtensions(t *testing.T) {
	dir := tempDir(t)
	w, _ := New(Config{
		Paths:             []string{dir},
		IncludeExtensions: []string{".go", ".py"},
	}, func(e Event) {})
	defer func() { _ = w.fsw.Close() }()

	if w.shouldSkip("/p/main.go") {
		t.Error(".go should not skip")
	}
	if !w.shouldSkip("/p/data.json") {
		t.Error(".json should skip")
	}
}

func TestShouldSkipDir(t *testing.T) {
	dir := tempDir(t)
	w, _ := New(Config{
		Paths:       []string{dir},
		ExcludeDirs: []string{".git", "vendor"},
	}, func(e Event) {})
	defer func() { _ = w.fsw.Close() }()

	if !w.shouldSkipDir(".git") {
		t.Error(".git should skip")
	}
	if w.shouldSkipDir("src") {
		t.Error("src should not skip")
	}
}

func TestPath2Components(t *testing.T) {
	parts := path2Components("/project/.git/config")
	found := false
	for _, p := range parts {
		if p == ".git" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected .git in %v", parts)
	}
}

func TestMapEventType(t *testing.T) {
	if mapEventType(fsnotify.Create) != EventCreated {
		t.Error("Create")
	}
	if mapEventType(fsnotify.Write) != EventModified {
		t.Error("Write")
	}
	if mapEventType(fsnotify.Remove) != EventDeleted {
		t.Error("Remove")
	}
	if mapEventType(fsnotify.Rename) != EventRenamed {
		t.Error("Rename")
	}
}

func TestWatcher_StartStop(t *testing.T) {
	dir := tempDir(t)
	w, err := New(Config{
		Paths:            []string{dir},
		DebounceInterval: 50 * time.Millisecond,
	}, func(e Event) {})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan error, 1)
	go func() { ch <- w.Start(ctx) }()

	waitFor(t, 2*time.Second, "start", func() bool { return w.IsRunning() })
	w.Stop()

	select {
	case err := <-ch:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout stopping")
	}
	if w.IsRunning() {
		t.Fatal("still running")
	}
}

func TestWatcher_DetectsCreate(t *testing.T) {
	dir := tempDir(t)
	var mu sync.Mutex
	var evts []Event
	w, _ := New(Config{
		Paths:            []string{dir},
		DebounceInterval: 50 * time.Millisecond,
	}, func(e Event) {
		mu.Lock()
		evts = append(evts, e)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan error, 1)
	go func() { ch <- w.Start(ctx) }()
	waitFor(t, 2*time.Second, "start", func() bool { return w.IsRunning() })

	writeFile(t, dir, "secret.txt", "AKIA1234567890ABCDEF")
	waitFor(t, 3*time.Second, "create event", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(evts) > 0
	})

	mu.Lock()
	found := false
	for _, e := range evts {
		if filepath.Base(e.Path) == "secret.txt" {
			found = true
		}
	}
	mu.Unlock()
	if !found {
		t.Error("no event for secret.txt")
	}
	cancel()
	<-ch
}

func TestWatcher_DetectsModify(t *testing.T) {
	dir := tempDir(t)
	writeFile(t, dir, "cfg.yml", "old")
	var mu sync.Mutex
	var evts []Event
	w, _ := New(Config{
		Paths:            []string{dir},
		DebounceInterval: 50 * time.Millisecond,
	}, func(e Event) {
		mu.Lock()
		evts = append(evts, e)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan error, 1)
	go func() { ch <- w.Start(ctx) }()
	waitFor(t, 2*time.Second, "start", func() bool { return w.IsRunning() })

	writeFile(t, dir, "cfg.yml", "password: secret123")
	waitFor(t, 3*time.Second, "modify event", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(evts) > 0
	})

	mu.Lock()
	found := false
	for _, e := range evts {
		if filepath.Base(e.Path) == "cfg.yml" {
			found = true
		}
	}
	mu.Unlock()
	if !found {
		t.Error("no event for cfg.yml")
	}
	cancel()
	<-ch
}

func TestWatcher_Debounce(t *testing.T) {
	dir := tempDir(t)
	var count atomic.Int64
	w, _ := New(Config{
		Paths:            []string{dir},
		DebounceInterval: 200 * time.Millisecond,
	}, func(e Event) { count.Add(1) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan error, 1)
	go func() { ch <- w.Start(ctx) }()
	waitFor(t, 2*time.Second, "start", func() bool { return w.IsRunning() })

	for i := 0; i < 10; i++ {
		writeFile(t, dir, "rapid.txt", "w"+string(rune('0'+i)))
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(400 * time.Millisecond)

	if c := count.Load(); c >= 10 {
		t.Errorf("debounce failed: %d events", c)
	}
	cancel()
	<-ch
}

func TestWatcher_ExcludesFiltered(t *testing.T) {
	dir := tempDir(t)
	var mu sync.Mutex
	var evts []Event
	w, _ := New(Config{
		Paths:             []string{dir},
		DebounceInterval:  50 * time.Millisecond,
		ExcludeExtensions: []string{".png"},
		ExcludeFiles:      []string{"go.sum"},
	}, func(e Event) {
		mu.Lock()
		evts = append(evts, e)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan error, 1)
	go func() { ch <- w.Start(ctx) }()
	waitFor(t, 2*time.Second, "start", func() bool { return w.IsRunning() })

	writeFile(t, dir, "icon.png", "png")
	writeFile(t, dir, "go.sum", "sum")
	writeFile(t, dir, "main.go", "package main")

	waitFor(t, 3*time.Second, "main.go", func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, e := range evts {
			if filepath.Base(e.Path) == "main.go" {
				return true
			}
		}
		return false
	})

	mu.Lock()
	for _, e := range evts {
		b := filepath.Base(e.Path)
		if b == "icon.png" || b == "go.sum" {
			t.Errorf("got event for excluded: %s", b)
		}
	}
	mu.Unlock()
	cancel()
	<-ch
}

func TestWatcher_Recursive(t *testing.T) {
	dir := tempDir(t)
	sub := filepath.Join(dir, "sub")
	os.Mkdir(sub, 0755)
	var mu sync.Mutex
	var evts []Event
	w, _ := New(Config{
		Paths:            []string{dir},
		Recursive:        true,
		DebounceInterval: 50 * time.Millisecond,
	}, func(e Event) {
		mu.Lock()
		evts = append(evts, e)
		mu.Unlock()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan error, 1)
	go func() { ch <- w.Start(ctx) }()
	waitFor(t, 2*time.Second, "start", func() bool { return w.IsRunning() })

	writeFile(t, sub, "nested.txt", "secret")
	waitFor(t, 3*time.Second, "nested", func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, e := range evts {
			if filepath.Base(e.Path) == "nested.txt" {
				return true
			}
		}
		return false
	})

	mu.Lock()
	found := false
	for _, e := range evts {
		if filepath.Base(e.Path) == "nested.txt" {
			found = true
		}
	}
	mu.Unlock()
	if !found {
		t.Error("no nested.txt event")
	}
	cancel()
	<-ch
}

func TestWatcher_Stats(t *testing.T) {
	dir := tempDir(t)
	w, _ := New(Config{
		Paths:            []string{dir},
		DebounceInterval: 50 * time.Millisecond,
	}, func(e Event) {})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan error, 1)
	go func() { ch <- w.Start(ctx) }()
	waitFor(t, 2*time.Second, "start", func() bool { return w.IsRunning() })

	writeFile(t, dir, "s.txt", "d")
	time.Sleep(200 * time.Millisecond)

	s := w.GetStats()
	if s.StartedAt.IsZero() {
		t.Error("StartedAt zero")
	}
	if s.DirsWatched == 0 {
		t.Error("DirsWatched zero")
	}
	cancel()
	<-ch
}

func TestWatcher_DoubleStart(t *testing.T) {
	dir := tempDir(t)
	w, _ := New(Config{
		Paths:            []string{dir},
		DebounceInterval: 50 * time.Millisecond,
	}, func(e Event) {})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan error, 1)
	go func() { ch <- w.Start(ctx) }()
	waitFor(t, 2*time.Second, "start", func() bool { return w.IsRunning() })

	if err := w.Start(context.Background()); err == nil {
		t.Fatal("double start should fail")
	}
	cancel()
	<-ch
}

func TestWatcher_WatchedDirs(t *testing.T) {
	dir := tempDir(t)
	w, _ := New(Config{
		Paths:            []string{dir},
		DebounceInterval: 50 * time.Millisecond,
	}, func(e Event) {})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan error, 1)
	go func() { ch <- w.Start(ctx) }()
	waitFor(t, 2*time.Second, "start", func() bool { return w.IsRunning() })

	dirs := w.WatchedDirs()
	if len(dirs) == 0 {
		t.Error("no watched dirs")
	}
	found := false
	for _, d := range dirs {
		if d == dir {
			found = true
		}
	}
	if !found {
		t.Errorf("missing %q in %v", dir, dirs)
	}
	cancel()
	<-ch
}

func TestWatcher_ExcludedDir(t *testing.T) {
	dir := tempDir(t)
	os.Mkdir(filepath.Join(dir, ".git"), 0755)
	w, _ := New(Config{
		Paths:            []string{dir},
		Recursive:        true,
		DebounceInterval: 50 * time.Millisecond,
		ExcludeDirs:      []string{".git"},
	}, func(e Event) {})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan error, 1)
	go func() { ch <- w.Start(ctx) }()
	waitFor(t, 2*time.Second, "start", func() bool { return w.IsRunning() })

	for _, d := range w.WatchedDirs() {
		if filepath.Base(d) == ".git" {
			t.Error(".git should not be watched")
		}
	}
	cancel()
	<-ch
}

func TestStats_Snapshot(t *testing.T) {
	s := &Stats{
		EventsReceived: 10,
		EventsEmitted:  7,
		EventsDropped:  3,
		DirsWatched:    5,
		StartedAt:      time.Now(),
	}
	snap := s.Snapshot()
	if snap.EventsReceived != 10 {
		t.Error("EventsReceived")
	}
	if snap.EventsEmitted != 7 {
		t.Error("EventsEmitted")
	}
	if snap.EventsDropped != 3 {
		t.Error("EventsDropped")
	}
	if snap.DirsWatched != 5 {
		t.Error("DirsWatched")
	}
}

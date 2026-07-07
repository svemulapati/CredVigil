// Package watcher provides real-time file system monitoring for CredVigil.
// It watches directories and files for changes (create, write, rename, chmod)
// and triggers secret scanning on modified files. Uses fsnotify for cross-platform
// support (Linux inotify, macOS FSEvents/kqueue, Windows ReadDirectoryChanges).
//
// Key features:
//   - Recursive directory watching
//   - Event debouncing to avoid scanning the same file multiple times
//   - Configurable file/directory exclusions (reuses detector patterns)
//   - Graceful shutdown via context cancellation
//   - Callback-based architecture for flexible integration
package watcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// EventType represents the kind of file system event.
type EventType int

const (
	EventCreated  EventType = iota // File or directory was created
	EventModified                  // File was written to
	EventDeleted                   // File or directory was removed
	EventRenamed                   // File or directory was renamed
)

func (e EventType) String() string {
	switch e {
	case EventCreated:
		return "CREATED"
	case EventModified:
		return "MODIFIED"
	case EventDeleted:
		return "DELETED"
	case EventRenamed:
		return "RENAMED"
	default:
		return "UNKNOWN"
	}
}

// Event represents a debounced file system event ready for processing.
type Event struct {
	// Path is the absolute path to the changed file.
	Path string

	// Type is the kind of change that occurred.
	Type EventType

	// Timestamp records when the event was captured.
	Timestamp time.Time
}

// Handler is the callback function invoked when a file change is detected.
// It receives the debounced event. Implementations should be safe for
// concurrent invocation.
type Handler func(event Event)

// Config holds configuration for the file system watcher.
type Config struct {
	// Paths to watch (files or directories).
	Paths []string

	// Recursive enables recursive directory watching.
	// When true, all subdirectories are automatically watched.
	Recursive bool

	// DebounceInterval is the minimum time between events for the same file.
	// Events within this window are collapsed into one. Default: 500ms.
	DebounceInterval time.Duration

	// ExcludeDirs are directory names to skip (e.g., ".git", "node_modules").
	ExcludeDirs []string

	// ExcludeExtensions are file extensions to ignore (e.g., ".exe", ".png").
	ExcludeExtensions []string

	// ExcludeFiles are exact filenames to ignore.
	ExcludeFiles []string

	// IncludeExtensions limits watching to only these extensions (empty = all).
	IncludeExtensions []string
}

// DefaultConfig returns a sensible default watcher configuration.
func DefaultConfig() Config {
	return Config{
		Recursive:        true,
		DebounceInterval: 500 * time.Millisecond,
		ExcludeDirs: []string{
			".git", "node_modules", "vendor", ".venv", "__pycache__",
			".idea", ".vscode", ".vs", "dist", "build", "target",
			".terraform", ".next", ".nuxt", "coverage", "bin", "obj",
		},
		ExcludeExtensions: []string{
			".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
			".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
			".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
			".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
			".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
			".woff", ".woff2", ".ttf", ".eot", ".otf",
			".lock", ".sum",
		},
		ExcludeFiles: []string{
			"package-lock.json", "yarn.lock", "go.sum", "Cargo.lock",
			"poetry.lock", "Gemfile.lock", "composer.lock",
		},
	}
}

// Stats holds runtime statistics for the watcher.
type Stats struct {
	mu             sync.RWMutex
	EventsReceived uint64
	EventsEmitted  uint64
	EventsDropped  uint64
	DirsWatched    int
	StartedAt      time.Time
}

// Snapshot returns a copy of the current stats (safe for concurrent use).
func (s *Stats) Snapshot() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Stats{
		EventsReceived: s.EventsReceived,
		EventsEmitted:  s.EventsEmitted,
		EventsDropped:  s.EventsDropped,
		DirsWatched:    s.DirsWatched,
		StartedAt:      s.StartedAt,
	}
}

// Watcher monitors the file system for changes and triggers callbacks.
type Watcher struct {
	config   Config
	handler  Handler
	fsw      *fsnotify.Watcher
	stats    Stats
	mu       sync.RWMutex
	running  bool
	cancelFn context.CancelFunc
}

// New creates a new Watcher with the given configuration and event handler.
// The handler is called for each debounced file event.
func New(cfg Config, handler Handler) (*Watcher, error) {
	if handler == nil {
		return nil, fmt.Errorf("watcher: handler must not be nil")
	}
	if len(cfg.Paths) == 0 {
		return nil, fmt.Errorf("watcher: at least one path is required")
	}
	if cfg.DebounceInterval <= 0 {
		cfg.DebounceInterval = 500 * time.Millisecond
	}

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("watcher: failed to create fsnotify watcher: %w", err)
	}

	return &Watcher{
		config:  cfg,
		handler: handler,
		fsw:     fsw,
	}, nil
}

// Start begins watching configured paths. It blocks until the context is
// canceled or Stop is called. Returns nil on graceful shutdown.
func (w *Watcher) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return fmt.Errorf("watcher: already running")
	}
	w.running = true
	ctx, w.cancelFn = context.WithCancel(ctx)
	w.stats.StartedAt = time.Now()
	w.mu.Unlock()

	// Add initial watches
	for _, path := range w.config.Paths {
		if err := w.addPath(path); err != nil {
			w.cleanup()
			return fmt.Errorf("watcher: failed to watch %q: %w", path, err)
		}
	}

	// Run event loop
	return w.eventLoop(ctx)
}

// Stop signals the watcher to shut down gracefully.
func (w *Watcher) Stop() {
	w.mu.RLock()
	cancel := w.cancelFn
	w.mu.RUnlock()
	if cancel != nil {
		cancel()
	}
}

// Close releases all resources held by the watcher. If the watcher was started,
// it is stopped first. Safe to call if Start() was never called — this ensures
// the underlying fsnotify watcher is properly closed.
func (w *Watcher) Close() {
	w.Stop()
	w.cleanup()
}

// IsRunning returns whether the watcher is currently active.
func (w *Watcher) IsRunning() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.running
}

// GetStats returns a snapshot of the watcher's runtime statistics.
func (w *Watcher) GetStats() Stats {
	return w.stats.Snapshot()
}

// WatchedDirs returns the list of directories currently being watched.
func (w *Watcher) WatchedDirs() []string {
	if w.fsw == nil {
		return nil
	}
	return w.fsw.WatchList()
}

// eventLoop is the core loop: reads fsnotify events, debounces, and dispatches.
func (w *Watcher) eventLoop(ctx context.Context) error {
	debounce := make(map[string]time.Time)
	debounceMu := sync.Mutex{}

	// Periodically prune old debounce entries to prevent memory leaks
	// in long-running watchers monitoring active codebases.
	pruneTicker := time.NewTicker(30 * time.Second)
	defer pruneTicker.Stop()

	defer w.cleanup()

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-pruneTicker.C:
			// Prune debounce entries older than 2x debounce interval
			cutoff := time.Now().Add(-2 * w.config.DebounceInterval)
			debounceMu.Lock()
			for path, last := range debounce {
				if last.Before(cutoff) {
					delete(debounce, path)
				}
			}
			debounceMu.Unlock()

		case fsEvent, ok := <-w.fsw.Events:
			if !ok {
				return nil
			}

			w.stats.mu.Lock()
			w.stats.EventsReceived++
			w.stats.mu.Unlock()

			// Skip files/dirs we don't care about
			if w.shouldSkip(fsEvent.Name) {
				w.stats.mu.Lock()
				w.stats.EventsDropped++
				w.stats.mu.Unlock()
				continue
			}

			// If a new directory is created, watch it recursively
			if fsEvent.Has(fsnotify.Create) {
				if info, err := os.Stat(fsEvent.Name); err == nil && info.IsDir() {
					_ = w.addPath(fsEvent.Name)
					continue
				}
			}

			// Debounce: skip if we saw this file recently
			debounceMu.Lock()
			if last, exists := debounce[fsEvent.Name]; exists {
				if time.Since(last) < w.config.DebounceInterval {
					debounceMu.Unlock()
					w.stats.mu.Lock()
					w.stats.EventsDropped++
					w.stats.mu.Unlock()
					continue
				}
			}
			debounce[fsEvent.Name] = time.Now()
			debounceMu.Unlock()

			// Convert to our event type
			event := Event{
				Path:      fsEvent.Name,
				Type:      mapEventType(fsEvent.Op),
				Timestamp: time.Now(),
			}

			w.stats.mu.Lock()
			w.stats.EventsEmitted++
			w.stats.mu.Unlock()

			// Dispatch to handler (non-blocking)
			go w.handler(event)

		case err, ok := <-w.fsw.Errors:
			if !ok {
				return nil
			}
			// Log errors to stderr but don't crash
			fmt.Fprintf(os.Stderr, "credvigil watcher error: %v\n", err)
		}
	}
}

// addPath adds a single file or directory to the watcher.
// If recursive is enabled and the path is a directory, it walks subdirectories.
func (w *Watcher) addPath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("cannot stat %q: %w", path, err)
	}

	if !info.IsDir() {
		// Single file — just watch it
		return w.fsw.Add(path)
	}

	if !w.config.Recursive {
		if err := w.fsw.Add(path); err != nil {
			return err
		}
		w.stats.mu.Lock()
		w.stats.DirsWatched++
		w.stats.mu.Unlock()
		return nil
	}

	// Recursive: walk and add all subdirectories
	return filepath.Walk(path, func(p string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil // skip inaccessible paths
		}
		if fi.IsDir() {
			if w.shouldSkipDir(fi.Name()) && p != path {
				return filepath.SkipDir
			}
			if err := w.fsw.Add(p); err != nil {
				return nil // best-effort; skip dirs we can't watch
			}
			w.stats.mu.Lock()
			w.stats.DirsWatched++
			w.stats.mu.Unlock()
		}
		return nil
	})
}

// cleanup closes the fsnotify watcher and marks us as not running.
func (w *Watcher) cleanup() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.running = false
	if w.fsw != nil {
		_ = w.fsw.Close()
	}
}

// shouldSkip returns true if the given path should be ignored.
func (w *Watcher) shouldSkip(path string) bool {
	base := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(path))

	// Check excluded directories (any component)
	for _, dir := range path2Components(path) {
		if w.shouldSkipDir(dir) {
			return true
		}
	}

	// Check excluded files
	for _, excl := range w.config.ExcludeFiles {
		if strings.EqualFold(base, excl) {
			return true
		}
	}

	// Check excluded extensions
	for _, excl := range w.config.ExcludeExtensions {
		if strings.EqualFold(ext, excl) {
			return true
		}
	}

	// If include extensions are set, only allow those
	if len(w.config.IncludeExtensions) > 0 {
		found := false
		for _, incl := range w.config.IncludeExtensions {
			if strings.EqualFold(ext, incl) {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}

	return false
}

// shouldSkipDir returns true if a directory name is in the exclude list.
func (w *Watcher) shouldSkipDir(name string) bool {
	for _, excl := range w.config.ExcludeDirs {
		if strings.EqualFold(name, excl) {
			return true
		}
	}
	return false
}

// path2Components splits a path into its directory components.
func path2Components(path string) []string {
	var parts []string
	dir := filepath.Dir(path)
	for dir != "." && dir != "/" && dir != "" {
		parts = append(parts, filepath.Base(dir))
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return parts
}

// mapEventType converts an fsnotify Op bitmask to our EventType.
func mapEventType(op fsnotify.Op) EventType {
	switch {
	case op.Has(fsnotify.Create):
		return EventCreated
	case op.Has(fsnotify.Write):
		return EventModified
	case op.Has(fsnotify.Remove):
		return EventDeleted
	case op.Has(fsnotify.Rename):
		return EventRenamed
	default:
		return EventModified
	}
}

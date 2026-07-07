// Package detector provides the file scanning functionality.
// This file implements scanning of files and directories.
package detector

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/svemulapati/CredVigil/pkg/models"
)

// FileScanner scans files and directories for secrets.
type FileScanner struct {
	engine *Engine
	config FileScanConfig
}

// FileScanConfig configures file scanning behavior.
type FileScanConfig struct {
	// File extensions to scan (empty = scan all text files)
	IncludeExtensions []string

	// File extensions to skip
	ExcludeExtensions []string

	// Directory names to skip
	ExcludeDirs []string

	// File name patterns to skip
	ExcludeFiles []string

	// Maximum file size in bytes (0 = use engine default)
	MaxFileSize int64

	// Number of concurrent file scanners
	Workers int

	// Follow symlinks
	FollowSymlinks bool
}

// DefaultFileScanConfig returns a sensible default file scan configuration.
func DefaultFileScanConfig() FileScanConfig {
	return FileScanConfig{
		ExcludeExtensions: []string{
			".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
			".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
			".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
			".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
			".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
			".woff", ".woff2", ".ttf", ".eot", ".otf",
			".lock", ".sum",
		},
		ExcludeDirs: []string{
			".git", "node_modules", "vendor", ".venv", "__pycache__",
			".idea", ".vscode", ".vs", "dist", "build", "target",
			".terraform", ".next", ".nuxt", "coverage",
			"bin", "obj",
		},
		ExcludeFiles: []string{
			"package-lock.json", "yarn.lock", "go.sum", "Cargo.lock",
			"poetry.lock", "Gemfile.lock", "composer.lock",
		},
		MaxFileSize: 5 * 1024 * 1024, // 5 MB
		Workers:     4,
	}
}

// NewFileScanner creates a new FileScanner with the given engine and config.
func NewFileScanner(engine *Engine, cfg FileScanConfig) *FileScanner {
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	return &FileScanner{
		engine: engine,
		config: cfg,
	}
}

// ScanFile scans a single file for secrets.
func (fs *FileScanner) ScanFile(filePath string) (models.ScanResult, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return models.ScanResult{}, fmt.Errorf("cannot stat file %s: %w", filePath, err)
	}

	maxSize := fs.config.MaxFileSize
	if maxSize <= 0 {
		maxSize = 5 * 1024 * 1024
	}
	if info.Size() > maxSize {
		return models.ScanResult{}, fmt.Errorf("file %s exceeds size limit (%d > %d bytes)", filePath, info.Size(), maxSize)
	}

	if fs.shouldSkipFile(filePath) {
		return models.ScanResult{}, nil
	}

	content, err := os.ReadFile(filePath)
	if err != nil {
		return models.ScanResult{}, fmt.Errorf("cannot read file %s: %w", filePath, err)
	}

	// Check if content is binary
	if isBinaryContent(content) {
		return models.ScanResult{}, nil
	}

	req := models.ScanRequest{
		Content: string(content),
		Source: models.Source{
			Type:     "file",
			Location: filePath,
		},
	}

	result := fs.engine.ScanContent(req)
	return result, nil
}

// ScanDirectory recursively scans a directory for secrets.
func (fs *FileScanner) ScanDirectory(dirPath string) ([]models.ScanResult, error) {
	var filePaths []string

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip files we can't access
		}

		if info.IsDir() {
			if fs.shouldSkipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip symlinks unless configured to follow
		if info.Mode()&os.ModeSymlink != 0 && !fs.config.FollowSymlinks {
			return nil
		}

		if !fs.shouldSkipFile(path) {
			filePaths = append(filePaths, path)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking directory %s: %w", dirPath, err)
	}

	return fs.scanFiles(filePaths)
}

// ScanStdin reads from stdin and scans for secrets.
func (fs *FileScanner) ScanStdin() (models.ScanResult, error) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // 10 MB buffer

	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return models.ScanResult{}, fmt.Errorf("error reading stdin: %w", err)
	}

	content := strings.Join(lines, "\n")
	req := models.ScanRequest{
		Content: content,
		Source: models.Source{
			Type:     "stdin",
			Location: "stdin",
		},
	}
	return fs.engine.ScanContent(req), nil
}

// scanFiles scans multiple files concurrently.
func (fs *FileScanner) scanFiles(paths []string) ([]models.ScanResult, error) {
	var (
		results []models.ScanResult
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	// Create worker pool
	sem := make(chan struct{}, fs.config.Workers)

	for _, path := range paths {
		wg.Add(1)
		sem <- struct{}{}

		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			result, err := fs.ScanFile(p)
			if err != nil {
				// Log error but continue scanning
				mu.Lock()
				results = append(results, models.ScanResult{
					Source: models.Source{Type: "file", Location: p},
					Errors: []string{err.Error()},
				})
				mu.Unlock()
				return
			}

			if result.TotalFindings > 0 {
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}(path)
	}

	wg.Wait()
	return results, nil
}

// shouldSkipFile checks if a file should be excluded from scanning.
func (fs *FileScanner) shouldSkipFile(path string) bool {
	name := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(path))

	// Check excluded files
	for _, excl := range fs.config.ExcludeFiles {
		if strings.EqualFold(name, excl) {
			return true
		}
	}

	// Check excluded extensions
	for _, excl := range fs.config.ExcludeExtensions {
		if strings.EqualFold(ext, excl) {
			return true
		}
	}

	// If include extensions specified, only scan those
	if len(fs.config.IncludeExtensions) > 0 {
		found := false
		for _, incl := range fs.config.IncludeExtensions {
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

// shouldSkipDir checks if a directory should be excluded from scanning.
func (fs *FileScanner) shouldSkipDir(name string) bool {
	for _, excl := range fs.config.ExcludeDirs {
		if strings.EqualFold(name, excl) {
			return true
		}
	}
	return false
}

// isBinaryContent checks if content appears to be binary.
func isBinaryContent(content []byte) bool {
	// Check first 512 bytes for null bytes (common binary indicator)
	checkLen := len(content)
	if checkLen > 512 {
		checkLen = 512
	}
	for i := 0; i < checkLen; i++ {
		if content[i] == 0 {
			return true
		}
	}
	return false
}

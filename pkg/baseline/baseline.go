// Package baseline implements finding suppression so teams can adopt CredVigil
// on an existing codebase without drowning in pre-existing findings. It reads a
// .credvigilignore file whose lines are either:
//
//   - a finding fingerprint (the stable hash printed in scan output), or
//   - a path glob (anything containing '/', '*', '?', or a file extension),
//     matched against a finding's file location.
//
// This mirrors the baseline/allowlist workflow every mainstream secret scanner
// provides. Blank lines and lines beginning with '#' are ignored.
package baseline

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/svemulapati/CredVigil/pkg/models"
)

// DefaultFileName is the conventional baseline file discovered at a repo root.
const DefaultFileName = ".credvigilignore"

// Baseline holds compiled suppression rules.
type Baseline struct {
	fingerprints map[string]struct{}
	pathGlobs    []string
}

// Empty reports whether the baseline has no rules (nothing to suppress).
func (b *Baseline) Empty() bool {
	if b == nil {
		return true
	}
	return len(b.fingerprints) == 0 && len(b.pathGlobs) == 0
}

// Load reads a baseline file from disk. A missing file is not an error — it
// returns an empty baseline so callers can invoke this unconditionally.
func Load(path string) (*Baseline, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Baseline{fingerprints: map[string]struct{}{}}, nil
		}
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Discover looks for DefaultFileName in the given directory and loads it if
// present. root may be a file path, in which case its directory is used.
func Discover(root string) (*Baseline, error) {
	info, err := os.Stat(root)
	dir := root
	if err == nil && !info.IsDir() {
		dir = filepath.Dir(root)
	}
	return Load(filepath.Join(dir, DefaultFileName))
}

// Parse reads baseline rules from r.
func Parse(r io.Reader) (*Baseline, error) {
	b := &Baseline{fingerprints: map[string]struct{}{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip an optional trailing "# comment".
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if looksLikePath(line) {
			b.pathGlobs = append(b.pathGlobs, line)
		} else {
			b.fingerprints[line] = struct{}{}
		}
	}
	return b, sc.Err()
}

// looksLikePath distinguishes a path glob from a fingerprint hash. Fingerprints
// are hex-ish tokens with no path separators, wildcards, or dots.
func looksLikePath(s string) bool {
	return strings.ContainsAny(s, "/*?.")
}

// Suppressed reports whether a finding is silenced by the baseline. A finding
// matches when its fingerprint is listed, or its location matches any path glob.
func (b *Baseline) Suppressed(f *models.Finding) bool {
	if b.Empty() {
		return false
	}
	if f.Fingerprint != "" {
		if _, ok := b.fingerprints[f.Fingerprint]; ok {
			return true
		}
	}
	loc := normalize(f.Source.Location)
	for _, g := range b.pathGlobs {
		if matchPath(g, loc) {
			return true
		}
	}
	return false
}

// Apply removes suppressed findings from every result in-place, recomputing
// each result's TotalFindings and CountBySeverity. It returns the number of
// findings suppressed across all results.
func (b *Baseline) Apply(results []models.ScanResult) int {
	if b.Empty() {
		return 0
	}
	suppressed := 0
	for i := range results {
		r := &results[i]
		kept := r.Findings[:0]
		counts := make(map[models.Severity]int)
		for j := range r.Findings {
			if b.Suppressed(&r.Findings[j]) {
				suppressed++
				continue
			}
			counts[r.Findings[j].Severity]++
			kept = append(kept, r.Findings[j])
		}
		r.Findings = kept
		r.TotalFindings = len(kept)
		r.CountBySeverity = counts
	}
	return suppressed
}

func normalize(p string) string {
	return strings.TrimPrefix(filepath.ToSlash(p), "./")
}

// matchPath supports both filepath.Match glob semantics and a plain substring
// directory prefix (e.g. "testdata/" suppresses everything under it).
func matchPath(glob, path string) bool {
	glob = normalize(glob)
	if strings.HasSuffix(glob, "/") {
		return strings.HasPrefix(path, glob) || strings.Contains(path, "/"+glob)
	}
	if ok, _ := filepath.Match(glob, path); ok {
		return true
	}
	// Match against the base name too, so "*.env" catches nested files.
	if ok, _ := filepath.Match(glob, filepath.Base(path)); ok {
		return true
	}
	return path == glob
}

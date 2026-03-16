package git

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/credvigil/credvigil/pkg/detector"
	"github.com/credvigil/credvigil/pkg/models"
	"github.com/credvigil/credvigil/pkg/pipeline"
)

// GitScanner orchestrates scanning a git repository's commit history
// for secrets. It integrates the commit walker with the detection engine
// and the post-processing pipeline.
type GitScanner struct {
	engine   *detector.Engine
	pipe     *pipeline.Pipeline
	opts     ScanOptions
	mu       sync.RWMutex // protects progress
	progress ScanProgress
}

// NewGitScanner creates a new GitScanner with the given detection engine
// and scan options. It uses the default post-processing pipeline.
func NewGitScanner(engine *detector.Engine, opts ScanOptions) *GitScanner {
	return &GitScanner{
		engine: engine,
		pipe:   pipeline.NewDefault(),
		opts:   opts,
	}
}

// NewGitScannerWithPipeline creates a GitScanner with a custom pipeline.
func NewGitScannerWithPipeline(engine *detector.Engine, pipe *pipeline.Pipeline, opts ScanOptions) *GitScanner {
	return &GitScanner{
		engine: engine,
		pipe:   pipe,
		opts:   opts,
	}
}

// ScanRepository scans a repository's commit history for secrets.
// It walks through commits, extracts diffs, and runs the detection engine
// on every added line. Returns aggregated scan results.
func (gs *GitScanner) ScanRepository(ctx context.Context, repo *Repository) (*GitScanResult, error) {
	startTime := time.Now()

	walker := NewCommitWalker(repo, gs.opts)

	// Count total commits for progress
	totalCommits, err := walker.CountCommits()
	if err != nil {
		return nil, fmt.Errorf("failed to count commits: %w", err)
	}

	gs.mu.Lock()
	gs.progress = ScanProgress{
		TotalCommits: totalCommits,
	}
	gs.mu.Unlock()

	result := &GitScanResult{
		Repository:    repo.Path,
		RemoteURL:     repo.RemoteURL(),
		StartedAt:     startTime,
		TotalCommits:  totalCommits,
		CommitResults: make(map[string]*CommitScanResult),
	}

	meta := &models.ScanMetadata{
		ScannerVersion: "0.1.0",
		StartedAt:      startTime,
		SourceType:     "git",
		SourcePath:     repo.Path,
		RuleCount:      gs.engine.RuleCount(),
	}

	// Walk commits and scan each one
	scanned, err := walker.WalkCommits(func(commit Commit, entries []DiffEntry, idx int) error {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		gs.mu.Lock()
		gs.progress.ScannedCommits = idx + 1
		gs.progress.CurrentCommit = commit.ShortHash
		gs.mu.Unlock()

		commitResult := gs.scanCommitDiff(ctx, commit, entries, meta)

		if commitResult.TotalFindings > 0 {
			result.CommitResults[commit.Hash] = commitResult
			result.TotalFindings += commitResult.TotalFindings
			gs.mu.Lock()
			gs.progress.FindingsCount = result.TotalFindings
			gs.mu.Unlock()
		}

		result.ScannedCommits++
		return nil
	})

	if err != nil && err != context.Canceled {
		result.Errors = append(result.Errors, err.Error())
	}

	result.ScannedCommits = scanned
	result.Duration = time.Since(startTime)
	result.FinishedAt = time.Now()

	return result, nil
}

// ScanLocalRepo is a convenience function that opens a local repo and scans it.
func (gs *GitScanner) ScanLocalRepo(ctx context.Context, path string) (*GitScanResult, error) {
	repo, err := OpenRepository(path)
	if err != nil {
		return nil, err
	}
	return gs.ScanRepository(ctx, repo)
}

// ScanRemoteRepo clones a remote repo, scans it, and cleans up.
func (gs *GitScanner) ScanRemoteRepo(ctx context.Context, url string) (*GitScanResult, error) {
	repo, err := CloneRepository(url, gs.opts)
	if err != nil {
		return nil, err
	}
	defer repo.Cleanup()

	return gs.ScanRepository(ctx, repo)
}

// Progress returns the current scan progress.
func (gs *GitScanner) Progress() ScanProgress {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	return gs.progress
}

// scanCommitDiff scans all diff entries in a commit for secrets.
func (gs *GitScanner) scanCommitDiff(ctx context.Context, commit Commit, entries []DiffEntry, meta *models.ScanMetadata) *CommitScanResult {
	result := &CommitScanResult{
		Commit:   commit,
		Findings: make([]models.Finding, 0),
	}

	for _, entry := range entries {
		// Skip deleted files — nothing new was introduced
		if entry.ChangeType == "D" {
			continue
		}

		// Skip files with no added lines
		if len(entry.AddedLines) == 0 {
			continue
		}

		findings := gs.scanDiffEntry(ctx, commit, entry, meta)
		result.Findings = append(result.Findings, findings...)
	}

	result.TotalFindings = len(result.Findings)
	return result
}

// scanDiffEntry scans a single diff entry (one changed file) for secrets.
func (gs *GitScanner) scanDiffEntry(ctx context.Context, commit Commit, entry DiffEntry, meta *models.ScanMetadata) []models.Finding {
	// Build content from added lines for scanning
	content := buildScanContent(entry)
	if content == "" {
		return nil
	}

	// Create a scan request with git-specific source info
	req := models.ScanRequest{
		Content: content,
		Source: models.Source{
			Type:       "git-commit",
			Location:   entry.FilePath,
			CommitHash: commit.Hash,
			Author:     fmt.Sprintf("%s <%s>", commit.AuthorName, commit.AuthorEmail),
			Branch:     gs.opts.Branch,
		},
	}

	// Run the detection engine
	scanResult := gs.engine.ScanContent(req)

	if scanResult.TotalFindings == 0 {
		return nil
	}

	// Adjust line numbers to reflect the actual file lines (not the diff content lines)
	adjustLineNumbers(scanResult.Findings, entry)

	// Run the post-processing pipeline on findings
	pipeResult := models.ScanResult{
		Findings:        scanResult.Findings,
		TotalFindings:   scanResult.TotalFindings,
		CountBySeverity: scanResult.CountBySeverity,
		Source:          req.Source,
	}
	if errs := gs.pipe.ProcessResult(ctx, &pipeResult, meta); len(errs) > 0 {
		// Pipeline errors are non-fatal — findings that failed are dropped
		for _, e := range errs {
			_ = e // Logged internally by the pipeline
		}
	}

	return pipeResult.Findings
}

// buildScanContent combines the added lines from a diff entry into
// scannable content. It sorts lines by their original line number so that
// content order is deterministic and multi-line patterns (e.g., PEM keys)
// are preserved correctly.
func buildScanContent(entry DiffEntry) string {
	if len(entry.AddedLines) == 0 {
		return ""
	}

	// Sort line numbers to ensure deterministic ordering
	orderedLineNums := make([]int, 0, len(entry.AddedLines))
	for lineNum := range entry.AddedLines {
		orderedLineNums = append(orderedLineNums, lineNum)
	}
	sortInts(orderedLineNums)

	lines := make([]string, 0, len(orderedLineNums))
	for _, lineNum := range orderedLineNums {
		lines = append(lines, entry.AddedLines[lineNum])
	}
	return strings.Join(lines, "\n")
}

// adjustLineNumbers maps detection engine line numbers (relative to the
// scanned content) back to actual file line numbers in the diff.
func adjustLineNumbers(findings []models.Finding, entry DiffEntry) {
	// Build an ordered list of actual line numbers
	orderedLines := make([]int, 0, len(entry.AddedLines))
	for lineNum := range entry.AddedLines {
		orderedLines = append(orderedLines, lineNum)
	}
	sortInts(orderedLines)

	for i := range findings {
		scanLine := findings[i].Source.Line
		if scanLine > 0 && scanLine <= len(orderedLines) {
			findings[i].Source.Line = orderedLines[scanLine-1]
		}
	}
}

// sortInts sorts a slice of ints in ascending order (insertion sort for small slices).
func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		key := a[i]
		j := i - 1
		for j >= 0 && a[j] > key {
			a[j+1] = a[j]
			j--
		}
		a[j+1] = key
	}
}

// GitScanResult contains the aggregated results of scanning a git repository.
type GitScanResult struct {
	// Path to the scanned repository
	Repository string `json:"repository"`

	// Remote URL if cloned
	RemoteURL string `json:"remote_url,omitempty"`

	// When the scan started and finished
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt time.Time     `json:"finished_at"`
	Duration   time.Duration `json:"duration"`

	// Commit statistics
	TotalCommits   int `json:"total_commits"`
	ScannedCommits int `json:"scanned_commits"`

	// Total findings across all commits
	TotalFindings int `json:"total_findings"`

	// Results per commit (keyed by commit hash)
	CommitResults map[string]*CommitScanResult `json:"commit_results,omitempty"`

	// Non-fatal errors during scanning
	Errors []string `json:"errors,omitempty"`
}

// CommitScanResult contains findings from a single commit.
type CommitScanResult struct {
	// The commit that was scanned
	Commit Commit `json:"commit"`

	// Findings in this commit
	Findings []models.Finding `json:"findings"`

	// Total findings in this commit
	TotalFindings int `json:"total_findings"`
}

// AllFindings returns all findings across all commits, flattened.
func (r *GitScanResult) AllFindings() []models.Finding {
	var all []models.Finding
	for _, cr := range r.CommitResults {
		all = append(all, cr.Findings...)
	}
	return all
}

// CommitHashes returns the hashes of commits that had findings.
func (r *GitScanResult) CommitHashes() []string {
	hashes := make([]string, 0, len(r.CommitResults))
	for hash := range r.CommitResults {
		hashes = append(hashes, hash)
	}
	return hashes
}

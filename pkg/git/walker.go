package git

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CommitWalker iterates through git commit history and yields commits
// with their diffs. It processes only added lines — the lines where
// new secrets could have been introduced.
type CommitWalker struct {
	repo *Repository
	opts ScanOptions
}

// NewCommitWalker creates a new walker for the given repository.
func NewCommitWalker(repo *Repository, opts ScanOptions) *CommitWalker {
	return &CommitWalker{
		repo: repo,
		opts: opts,
	}
}

// CountCommits returns the total number of commits that will be scanned.
// This is useful for progress reporting.
func (w *CommitWalker) CountCommits() (int, error) {
	args := w.buildLogArgs("--oneline")

	out, err := gitExec(w.repo.Path, args...)
	if err != nil {
		return 0, err
	}
	if out == "" {
		return 0, nil
	}

	count := len(strings.Split(out, "\n"))
	if w.opts.MaxCommits > 0 && count > w.opts.MaxCommits {
		return w.opts.MaxCommits, nil
	}
	return count, nil
}

// ListCommits returns the list of commits that match the scan options.
func (w *CommitWalker) ListCommits() ([]Commit, error) {
	// Use a custom format to parse commits reliably
	// Fields separated by \x00 (null byte), commits separated by \x01
	format := "%H%x00%h%x00%an%x00%ae%x00%at%x00%s%x00%B%x00%P%x01"

	args := w.buildLogArgs("--format="+format, "--no-color")

	out, err := gitExec(w.repo.Path, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list commits: %w", err)
	}

	if out == "" {
		return nil, nil
	}

	return parseCommitLog(out)
}

// GetDiff returns the diff for a specific commit.
// For the first commit (no parents), it uses git show to extract the diff.
func (w *CommitWalker) GetDiff(commitHash string) (string, error) {
	maxSize := w.opts.MaxDiffSize
	if maxSize <= 0 {
		maxSize = 1024 * 1024 // 1 MB default
	}

	// Check if this commit has parents
	parents, err := gitExec(w.repo.Path, "rev-parse", commitHash+"^@")
	if err != nil || strings.TrimSpace(parents) == "" {
		// No parents — initial commit. Use "git log" with patch to get the diff
		// without needing the well-known empty-tree object.
		out, err := gitExec(w.repo.Path, "log", "-1", "-p", "--format=", "--no-color", "--unified=0", commitHash)
		if err != nil {
			return "", fmt.Errorf("failed to diff initial commit %s: %w", commitHash, err)
		}
		return truncateDiff(out, maxSize), nil
	}

	// Normal commit — diff against first parent
	out, err := gitExec(w.repo.Path, "diff", commitHash+"^", commitHash, "--no-color", "--unified=0")
	if err != nil {
		return "", fmt.Errorf("failed to diff commit %s: %w", commitHash, err)
	}
	return truncateDiff(out, maxSize), nil
}

// WalkCommits iterates through commits and calls the callback for each one
// with its parsed diff entries. Returns the total number of commits processed.
//
// The callback receives: (commit, diffEntries, commitIndex)
// If the callback returns an error, walking stops.
func (w *CommitWalker) WalkCommits(fn func(Commit, []DiffEntry, int) error) (int, error) {
	commits, err := w.ListCommits()
	if err != nil {
		return 0, err
	}

	processed := 0
	for i, commit := range commits {
		// Skip merge commits unless explicitly included
		if !w.opts.IncludeMerges && len(commit.Parents) > 1 {
			continue
		}

		diff, err := w.GetDiff(commit.Hash)
		if err != nil {
			// Log error but continue walking
			continue
		}

		entries := ParseDiff(diff)

		// Apply file filters
		entries = FilterDiffEntries(entries, w.opts.IncludePatterns, w.opts.ExcludePatterns)

		if err := fn(commit, entries, i); err != nil {
			return processed, err
		}

		processed++
		if w.opts.MaxCommits > 0 && processed >= w.opts.MaxCommits {
			break
		}
	}

	return processed, nil
}

// buildLogArgs constructs git log arguments from scan options.
func (w *CommitWalker) buildLogArgs(extraArgs ...string) []string {
	args := []string{"log"}
	args = append(args, extraArgs...)

	// Commit range
	if w.opts.SinceCommit != "" && w.opts.UntilCommit != "" {
		args = append(args, w.opts.SinceCommit+".."+w.opts.UntilCommit)
	} else if w.opts.SinceCommit != "" {
		args = append(args, w.opts.SinceCommit+"..HEAD")
	} else if w.opts.UntilCommit != "" {
		args = append(args, w.opts.UntilCommit)
	}

	// Branch
	if w.opts.Branch != "" && w.opts.SinceCommit == "" && w.opts.UntilCommit == "" {
		args = append(args, w.opts.Branch)
	}

	// All branches
	if w.opts.AllBranches {
		args = append(args, "--all")
	}

	// Limit
	if w.opts.MaxCommits > 0 {
		args = append(args, fmt.Sprintf("--max-count=%d", w.opts.MaxCommits))
	}

	// Skip merge commits unless included
	if !w.opts.IncludeMerges {
		args = append(args, "--no-merges")
	}

	return args
}

// parseCommitLog parses the custom-formatted git log output into Commits.
func parseCommitLog(output string) ([]Commit, error) {
	// Split by \x01 (commit separator)
	rawCommits := strings.Split(output, "\x01")

	var commits []Commit
	for _, raw := range rawCommits {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}

		// Split fields by \x00
		fields := strings.SplitN(raw, "\x00", 8)
		if len(fields) < 6 {
			continue // Malformed entry
		}

		commit := Commit{
			Hash:        fields[0],
			ShortHash:   fields[1],
			AuthorName:  fields[2],
			AuthorEmail: fields[3],
			Subject:     fields[5],
		}

		// Parse author date (unix timestamp)
		if ts, err := strconv.ParseInt(fields[4], 10, 64); err == nil {
			commit.AuthorDate = time.Unix(ts, 0)
		}

		// Parse message (field 6 if present)
		if len(fields) > 6 {
			commit.Message = strings.TrimSpace(fields[6])
		}

		// Parse parents (field 7 if present — space-separated hashes)
		if len(fields) > 7 {
			parentStr := strings.TrimSpace(fields[7])
			if parentStr != "" {
				commit.Parents = strings.Fields(parentStr)
			}
		}

		commits = append(commits, commit)
	}

	return commits, nil
}

// truncateDiff limits diff output to maxSize bytes to prevent memory issues.
func truncateDiff(diff string, maxSize int64) string {
	if int64(len(diff)) <= maxSize {
		return diff
	}
	return diff[:maxSize]
}

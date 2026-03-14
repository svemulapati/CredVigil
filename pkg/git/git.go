// Package git provides Git repository scanning functionality for CredVigil.
// It walks commit history, parses diffs, and feeds content to the detection
// engine to find secrets that were ever committed — even if later deleted.
//
// This package uses the git CLI (os/exec) to keep the project dependency-free.
// It requires git to be installed and available on PATH.
//
// Copyright 2026 CredVigil Contributors.
// Licensed under the Apache License, Version 2.0.
package git

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Repository represents a git repository that can be scanned.
type Repository struct {
	// Path to the local repository on disk
	Path string

	// Whether this repo was cloned by us (and should be cleaned up)
	isCloned bool

	// Remote URL if cloned
	remoteURL string
}

// Commit represents a single git commit with metadata.
type Commit struct {
	// Full SHA-1 hash of the commit
	Hash string

	// Short hash (first 8 characters)
	ShortHash string

	// Commit author name
	AuthorName string

	// Commit author email
	AuthorEmail string

	// When the commit was authored
	AuthorDate time.Time

	// Commit message (first line)
	Subject string

	// Full commit message
	Message string

	// Parent commit hash(es)
	Parents []string
}

// DiffEntry represents a single file changed in a commit.
type DiffEntry struct {
	// File path (new path for renames)
	FilePath string

	// Old file path (for renames/copies)
	OldPath string

	// Change type: "A" (added), "M" (modified), "D" (deleted), "R" (renamed)
	ChangeType string

	// The added lines (line number -> content)
	AddedLines map[int]string

	// The raw diff content for this file
	Patch string
}

// ScanOptions configures how a git repository is scanned.
type ScanOptions struct {
	// Branch to scan (empty = HEAD / default branch)
	Branch string

	// Only scan commits after this hash (exclusive)
	SinceCommit string

	// Only scan commits before this hash (inclusive)
	UntilCommit string

	// Maximum number of commits to scan (0 = unlimited)
	MaxCommits int

	// Clone depth for remote repos (0 = full history)
	Depth int

	// Whether to scan all branches (default: only current branch)
	AllBranches bool

	// File path patterns to include (empty = all files)
	IncludePatterns []string

	// File path patterns to exclude
	ExcludePatterns []string

	// Maximum diff size in bytes to process per commit (0 = 1MB default)
	MaxDiffSize int64

	// Whether to include merge commits (default: false)
	IncludeMerges bool
}

// DefaultScanOptions returns sensible defaults for git scanning.
func DefaultScanOptions() ScanOptions {
	return ScanOptions{
		MaxDiffSize:   1024 * 1024, // 1 MB per diff
		IncludeMerges: false,
	}
}

// ScanProgress reports progress during a git scan.
type ScanProgress struct {
	// Total commits to scan (may be 0 if unknown)
	TotalCommits int

	// Commits scanned so far
	ScannedCommits int

	// Current commit being scanned
	CurrentCommit string

	// Findings found so far
	FindingsCount int
}

// gitAvailable checks if git is installed and accessible.
func gitAvailable() error {
	cmd := exec.Command("git", "--version")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("git is not installed or not on PATH: %w", err)
	}
	if !strings.HasPrefix(string(out), "git version") {
		return fmt.Errorf("unexpected git version output: %s", string(out))
	}
	return nil
}

// gitExec runs a git command in the given directory and returns stdout.
func gitExec(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s failed: %w\nOutput: %s", strings.Join(args, " "), err, string(out))
	}
	return strings.TrimSpace(string(out)), nil
}

// isGitRepository checks if the given path is inside a git repository.
func isGitRepository(path string) bool {
	_, err := gitExec(path, "rev-parse", "--is-inside-work-tree")
	return err == nil
}

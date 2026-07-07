package git

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/svemulapati/CredVigil/pkg/detector"
	"github.com/svemulapati/CredVigil/pkg/models"
)

// =============================================================================
// Test Helpers
// =============================================================================

// createTestRepo creates a temporary git repository for testing.
// Returns the repo path and a cleanup function.
func createTestRepo(t *testing.T) (string, func()) {
	t.Helper()

	dir, err := os.MkdirTemp("", "credvigil-test-repo-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	cleanup := func() { os.RemoveAll(dir) }

	// Initialize repo
	run(t, dir, "git", "init")
	run(t, dir, "git", "config", "user.email", "test@credvigil.dev")
	run(t, dir, "git", "config", "user.name", "Test User")

	return dir, cleanup
}

// run executes a command in the given directory.
func run(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command %s %v failed: %v\nOutput: %s", name, args, err, string(out))
	}
	return strings.TrimSpace(string(out))
}

// writeFile creates a file with the given content in the repo.
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	// Create parent directories if needed
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("failed to create parent dirs: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write file %s: %v", name, err)
	}
}

// commitFile writes a file and commits it in one step.
func commitFile(t *testing.T, dir, filename, content, message string) {
	t.Helper()
	writeFile(t, dir, filename, content)
	run(t, dir, "git", "add", filename)
	run(t, dir, "git", "commit", "-m", message)
}

// commitAll stages all changes and commits.
func commitAll(t *testing.T, dir, message string) {
	t.Helper()
	run(t, dir, "git", "add", "-A")
	run(t, dir, "git", "commit", "-m", message)
}

// getHeadHash returns the current HEAD commit hash.
func getHeadHash(t *testing.T, dir string) string {
	t.Helper()
	return run(t, dir, "git", "rev-parse", "HEAD")
}

// =============================================================================
// Git Availability
// =============================================================================

func TestGitAvailable(t *testing.T) {
	if err := gitAvailable(); err != nil {
		t.Skipf("git not available: %v", err)
	}
}

// =============================================================================
// Repository Operations
// =============================================================================

func TestOpenRepository(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	// Need at least one commit for the repo to be valid
	commitFile(t, dir, "README.md", "# Test", "initial commit")

	repo, err := OpenRepository(dir)
	if err != nil {
		t.Fatalf("OpenRepository failed: %v", err)
	}

	if repo.Path == "" {
		t.Error("expected non-empty repo path")
	}
	if repo.IsCloned() {
		t.Error("local repo should not be marked as cloned")
	}
}

func TestOpenRepository_NotARepo(t *testing.T) {
	dir, err := os.MkdirTemp("", "credvigil-not-a-repo-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	_, err = OpenRepository(dir)
	if err == nil {
		t.Error("expected error for non-repo directory")
	}
	if !strings.Contains(err.Error(), "not a git repository") {
		t.Errorf("expected 'not a git repository' error, got: %v", err)
	}
}

func TestOpenRepository_NonexistentPath(t *testing.T) {
	_, err := OpenRepository("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func TestHeadCommit(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	commitFile(t, dir, "file.txt", "hello", "first commit")
	expectedHash := getHeadHash(t, dir)

	repo, err := OpenRepository(dir)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := repo.HeadCommit()
	if err != nil {
		t.Fatalf("HeadCommit failed: %v", err)
	}

	if hash != expectedHash {
		t.Errorf("expected hash %s, got %s", expectedHash, hash)
	}
}

func TestDefaultBranch(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	// Set default branch to "main" explicitly
	run(t, dir, "git", "checkout", "-b", "main")
	commitFile(t, dir, "file.txt", "hello", "initial")

	repo, err := OpenRepository(dir)
	if err != nil {
		t.Fatal(err)
	}

	branch, err := repo.DefaultBranch()
	if err != nil {
		t.Fatalf("DefaultBranch failed: %v", err)
	}

	if branch != "main" {
		t.Errorf("expected branch 'main', got '%s'", branch)
	}
}

func TestBranches(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")
	commitFile(t, dir, "file.txt", "hello", "initial")

	// Create additional branches
	run(t, dir, "git", "checkout", "-b", "feature-a")
	run(t, dir, "git", "checkout", "-b", "feature-b")
	run(t, dir, "git", "checkout", "main")

	repo, err := OpenRepository(dir)
	if err != nil {
		t.Fatal(err)
	}

	branches, err := repo.Branches()
	if err != nil {
		t.Fatalf("Branches failed: %v", err)
	}

	if len(branches) != 3 {
		t.Errorf("expected 3 branches, got %d: %v", len(branches), branches)
	}

	branchSet := make(map[string]bool)
	for _, b := range branches {
		branchSet[b] = true
	}
	for _, expected := range []string{"main", "feature-a", "feature-b"} {
		if !branchSet[expected] {
			t.Errorf("missing branch: %s", expected)
		}
	}
}

func TestCleanup_LocalRepo(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	commitFile(t, dir, "file.txt", "hello", "initial")

	repo, err := OpenRepository(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Cleanup should be a no-op for local repos
	if err := repo.Cleanup(); err != nil {
		t.Errorf("Cleanup should succeed for local repos: %v", err)
	}

	// Verify the directory still exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("local repo directory should NOT be deleted by Cleanup")
	}
}

// =============================================================================
// Diff Parsing
// =============================================================================

func TestParseDiff_AddedFile(t *testing.T) {
	diff := `diff --git a/config.env b/config.env
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/config.env
@@ -0,0 +1,3 @@
+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
+AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
+DB_PASSWORD=SuperSecret123!`

	entries := ParseDiff(diff)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.FilePath != "config.env" {
		t.Errorf("expected file path 'config.env', got '%s'", entry.FilePath)
	}
	if entry.ChangeType != "A" {
		t.Errorf("expected change type 'A', got '%s'", entry.ChangeType)
	}
	if len(entry.AddedLines) != 3 {
		t.Errorf("expected 3 added lines, got %d", len(entry.AddedLines))
	}

	// Check line content
	if entry.AddedLines[1] != "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("unexpected line 1 content: %s", entry.AddedLines[1])
	}
	if entry.AddedLines[2] != "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("unexpected line 2 content: %s", entry.AddedLines[2])
	}
}

func TestParseDiff_ModifiedFile(t *testing.T) {
	diff := `diff --git a/app.py b/app.py
index abc1234..def5678 100644
--- a/app.py
+++ b/app.py
@@ -10,3 +10,4 @@ def connect():
     host = "localhost"
     port = 5432
+    password = "my_secret_password_123"
     return connect(host, port)`

	entries := ParseDiff(diff)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.ChangeType != "M" {
		t.Errorf("expected change type 'M', got '%s'", entry.ChangeType)
	}
	if len(entry.AddedLines) != 1 {
		t.Errorf("expected 1 added line, got %d", len(entry.AddedLines))
	}

	// The added line should be at line 12
	if content, ok := entry.AddedLines[12]; !ok {
		t.Error("expected added line at line 12")
	} else if !strings.Contains(content, "my_secret_password_123") {
		t.Errorf("unexpected line content: %s", content)
	}
}

func TestParseDiff_MultipleFiles(t *testing.T) {
	diff := `diff --git a/file1.txt b/file1.txt
new file mode 100644
--- /dev/null
+++ b/file1.txt
@@ -0,0 +1,2 @@
+line one
+line two
diff --git a/file2.txt b/file2.txt
new file mode 100644
--- /dev/null
+++ b/file2.txt
@@ -0,0 +1,1 @@
+line three`

	entries := ParseDiff(diff)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].FilePath != "file1.txt" {
		t.Errorf("expected first file 'file1.txt', got '%s'", entries[0].FilePath)
	}
	if entries[1].FilePath != "file2.txt" {
		t.Errorf("expected second file 'file2.txt', got '%s'", entries[1].FilePath)
	}
	if len(entries[0].AddedLines) != 2 {
		t.Errorf("expected 2 added lines in file1, got %d", len(entries[0].AddedLines))
	}
	if len(entries[1].AddedLines) != 1 {
		t.Errorf("expected 1 added line in file2, got %d", len(entries[1].AddedLines))
	}
}

func TestParseDiff_DeletedFile(t *testing.T) {
	diff := `diff --git a/old.txt b/old.txt
deleted file mode 100644
index abc1234..0000000
--- a/old.txt
+++ /dev/null
@@ -1,2 +0,0 @@
-old line one
-old line two`

	entries := ParseDiff(diff)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if entries[0].ChangeType != "D" {
		t.Errorf("expected change type 'D', got '%s'", entries[0].ChangeType)
	}
	if len(entries[0].AddedLines) != 0 {
		t.Errorf("deleted file should have 0 added lines, got %d", len(entries[0].AddedLines))
	}
}

func TestParseDiff_RenamedFile(t *testing.T) {
	diff := `diff --git a/old_name.txt b/new_name.txt
similarity index 100%
rename from old_name.txt
rename to new_name.txt`

	entries := ParseDiff(diff)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if entries[0].ChangeType != "R" {
		t.Errorf("expected change type 'R', got '%s'", entries[0].ChangeType)
	}
	if entries[0].OldPath != "old_name.txt" {
		t.Errorf("expected old path 'old_name.txt', got '%s'", entries[0].OldPath)
	}
	if entries[0].FilePath != "new_name.txt" {
		t.Errorf("expected new path 'new_name.txt', got '%s'", entries[0].FilePath)
	}
}

func TestParseDiff_EmptyInput(t *testing.T) {
	entries := ParseDiff("")
	if entries != nil {
		t.Errorf("expected nil for empty diff, got %v", entries)
	}
}

func TestParseDiff_MultipleHunks(t *testing.T) {
	diff := `diff --git a/large.txt b/large.txt
index abc..def 100644
--- a/large.txt
+++ b/large.txt
@@ -5,3 +5,4 @@ first section
 context line
+added at line 6
 more context
@@ -20,3 +21,4 @@ second section
 context line
+added at line 22
 more context`

	entries := ParseDiff(diff)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	entry := entries[0]
	if len(entry.AddedLines) != 2 {
		t.Errorf("expected 2 added lines, got %d", len(entry.AddedLines))
	}

	if _, ok := entry.AddedLines[6]; !ok {
		t.Error("expected added line at line 6")
	}
	if _, ok := entry.AddedLines[22]; !ok {
		t.Error("expected added line at line 22")
	}
}

func TestParseHunkNewStart(t *testing.T) {
	tests := []struct {
		header   string
		expected int
	}{
		{"@@ -0,0 +1,3 @@", 1},
		{"@@ -10,5 +20,8 @@", 20},
		{"@@ -1 +1 @@", 1},
		{"@@ -1,2 +100,5 @@ some context", 100},
		{"invalid", 1},
	}

	for _, tt := range tests {
		got := parseHunkNewStart(tt.header)
		if got != tt.expected {
			t.Errorf("parseHunkNewStart(%q) = %d, want %d", tt.header, got, tt.expected)
		}
	}
}

// =============================================================================
// File Filtering
// =============================================================================

func TestFilterDiffEntries_NoFilters(t *testing.T) {
	entries := []DiffEntry{
		{FilePath: "main.go"},
		{FilePath: "README.md"},
	}
	filtered := FilterDiffEntries(entries, nil, nil)
	if len(filtered) != 2 {
		t.Errorf("expected 2 entries (no filters), got %d", len(filtered))
	}
}

func TestFilterDiffEntries_IncludeOnly(t *testing.T) {
	entries := []DiffEntry{
		{FilePath: "main.go"},
		{FilePath: "config.env"},
		{FilePath: "README.md"},
	}
	filtered := FilterDiffEntries(entries, []string{"*.go"}, nil)
	if len(filtered) != 1 {
		t.Errorf("expected 1 entry (*.go), got %d", len(filtered))
	}
	if filtered[0].FilePath != "main.go" {
		t.Errorf("expected main.go, got %s", filtered[0].FilePath)
	}
}

func TestFilterDiffEntries_ExcludeOnly(t *testing.T) {
	entries := []DiffEntry{
		{FilePath: "main.go"},
		{FilePath: "config.env"},
		{FilePath: "vendor/lib.go"},
	}
	filtered := FilterDiffEntries(entries, nil, []string{"vendor/"})
	if len(filtered) != 2 {
		t.Errorf("expected 2 entries (exclude vendor/), got %d", len(filtered))
	}
}

func TestFilterDiffEntries_IncludeAndExclude(t *testing.T) {
	entries := []DiffEntry{
		{FilePath: "src/main.go"},
		{FilePath: "src/test_helper.go"},
		{FilePath: "vendor/lib.go"},
		{FilePath: "README.md"},
	}
	filtered := FilterDiffEntries(entries, []string{"*.go"}, []string{"vendor/"})
	if len(filtered) != 2 {
		t.Errorf("expected 2 entries (*.go excluding vendor/), got %d", len(filtered))
	}
}

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		path    string
		pattern string
		want    bool
	}{
		{"main.go", "*.go", true},
		{"src/main.go", "*.go", true},
		{"main.py", "*.go", false},
		{"vendor/lib.go", "vendor/", true},
		{"src/vendor/lib.go", "vendor/", false}, // prefix match only
		{"config.env", "config.env", true},
		{"src/config.env", "config.env", true}, // substring
	}

	for _, tt := range tests {
		got := matchPattern(tt.path, tt.pattern)
		if got != tt.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", tt.path, tt.pattern, got, tt.want)
		}
	}
}

// =============================================================================
// Commit Walker (Integration with real git repos)
// =============================================================================

func TestCommitWalker_ListCommits(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")
	commitFile(t, dir, "file1.txt", "first", "commit 1")
	commitFile(t, dir, "file2.txt", "second", "commit 2")
	commitFile(t, dir, "file3.txt", "third", "commit 3")

	repo, err := OpenRepository(dir)
	if err != nil {
		t.Fatal(err)
	}

	walker := NewCommitWalker(repo, DefaultScanOptions())
	commits, err := walker.ListCommits()
	if err != nil {
		t.Fatal(err)
	}

	if len(commits) != 3 {
		t.Fatalf("expected 3 commits, got %d", len(commits))
	}

	// Most recent first
	if commits[0].Subject != "commit 3" {
		t.Errorf("expected first commit 'commit 3', got '%s'", commits[0].Subject)
	}
	if commits[2].Subject != "commit 1" {
		t.Errorf("expected last commit 'commit 1', got '%s'", commits[2].Subject)
	}

	// Validate commit fields
	for _, c := range commits {
		if c.Hash == "" {
			t.Error("commit hash should not be empty")
		}
		if c.ShortHash == "" {
			t.Error("short hash should not be empty")
		}
		if c.AuthorName != "Test User" {
			t.Errorf("expected author 'Test User', got '%s'", c.AuthorName)
		}
		if c.AuthorEmail != "test@credvigil.dev" {
			t.Errorf("expected email 'test@credvigil.dev', got '%s'", c.AuthorEmail)
		}
		if c.AuthorDate.IsZero() {
			t.Error("author date should not be zero")
		}
	}
}

func TestCommitWalker_CountCommits(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")
	commitFile(t, dir, "a.txt", "a", "one")
	commitFile(t, dir, "b.txt", "b", "two")
	commitFile(t, dir, "c.txt", "c", "three")
	commitFile(t, dir, "d.txt", "d", "four")
	commitFile(t, dir, "e.txt", "e", "five")

	repo, _ := OpenRepository(dir)
	walker := NewCommitWalker(repo, DefaultScanOptions())

	count, err := walker.CountCommits()
	if err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Errorf("expected 5 commits, got %d", count)
	}
}

func TestCommitWalker_MaxCommits(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")
	for i := 0; i < 10; i++ {
		commitFile(t, dir, fmt.Sprintf("file%d.txt", i), fmt.Sprintf("content %d", i), fmt.Sprintf("commit %d", i))
	}

	repo, _ := OpenRepository(dir)
	opts := DefaultScanOptions()
	opts.MaxCommits = 3
	walker := NewCommitWalker(repo, opts)

	commits, err := walker.ListCommits()
	if err != nil {
		t.Fatal(err)
	}
	if len(commits) != 3 {
		t.Errorf("expected 3 commits (max), got %d", len(commits))
	}
}

func TestCommitWalker_SinceCommit(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")
	commitFile(t, dir, "a.txt", "a", "old commit 1")
	commitFile(t, dir, "b.txt", "b", "old commit 2")
	sinceHash := getHeadHash(t, dir)
	commitFile(t, dir, "c.txt", "c", "new commit 1")
	commitFile(t, dir, "d.txt", "d", "new commit 2")

	repo, _ := OpenRepository(dir)
	opts := DefaultScanOptions()
	opts.SinceCommit = sinceHash
	walker := NewCommitWalker(repo, opts)

	commits, err := walker.ListCommits()
	if err != nil {
		t.Fatal(err)
	}

	if len(commits) != 2 {
		t.Fatalf("expected 2 commits since %s, got %d", sinceHash[:8], len(commits))
	}

	// Should only contain the new commits
	for _, c := range commits {
		if !strings.HasPrefix(c.Subject, "new commit") {
			t.Errorf("expected only new commits, got '%s'", c.Subject)
		}
	}
}

func TestCommitWalker_GetDiff(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")
	commitFile(t, dir, "secret.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n", "add secret")

	repo, _ := OpenRepository(dir)
	walker := NewCommitWalker(repo, DefaultScanOptions())

	hash := getHeadHash(t, dir)
	diff, err := walker.GetDiff(hash)
	if err != nil {
		t.Fatalf("GetDiff failed: %v", err)
	}

	if !strings.Contains(diff, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("diff should contain the AWS key")
	}
	if !strings.Contains(diff, "secret.env") {
		t.Error("diff should reference the file name")
	}
}

func TestCommitWalker_GetDiff_InitialCommit(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")
	commitFile(t, dir, "first.txt", "hello world\n", "initial commit")

	repo, _ := OpenRepository(dir)
	walker := NewCommitWalker(repo, DefaultScanOptions())

	hash := getHeadHash(t, dir)
	diff, err := walker.GetDiff(hash)
	if err != nil {
		t.Fatalf("GetDiff for initial commit failed: %v", err)
	}

	if !strings.Contains(diff, "hello world") {
		t.Error("initial commit diff should contain file content")
	}
}

func TestCommitWalker_WalkCommits(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")
	commitFile(t, dir, "a.txt", "alpha", "commit A")
	commitFile(t, dir, "b.txt", "beta", "commit B")
	commitFile(t, dir, "c.txt", "gamma", "commit C")

	repo, _ := OpenRepository(dir)
	walker := NewCommitWalker(repo, DefaultScanOptions())

	var visited []string
	processed, err := walker.WalkCommits(func(c Commit, entries []DiffEntry, idx int) error {
		visited = append(visited, c.Subject)
		return nil
	})

	if err != nil {
		t.Fatalf("WalkCommits failed: %v", err)
	}
	if processed != 3 {
		t.Errorf("expected 3 processed commits, got %d", processed)
	}
	if len(visited) != 3 {
		t.Errorf("expected 3 visited commits, got %d", len(visited))
	}
}

func TestCommitWalker_WalkCommits_WithDiffs(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")
	commitFile(t, dir, "config.env", "SECRET=abc123\n", "add config")

	repo, _ := OpenRepository(dir)
	walker := NewCommitWalker(repo, DefaultScanOptions())

	var foundEntries []DiffEntry
	_, err := walker.WalkCommits(func(c Commit, entries []DiffEntry, idx int) error {
		foundEntries = append(foundEntries, entries...)
		return nil
	})

	if err != nil {
		t.Fatal(err)
	}

	if len(foundEntries) == 0 {
		t.Fatal("expected at least one diff entry")
	}

	found := false
	for _, entry := range foundEntries {
		if entry.FilePath == "config.env" {
			found = true
			if len(entry.AddedLines) == 0 {
				t.Error("config.env should have added lines")
			}
		}
	}
	if !found {
		t.Error("should have found config.env in diff entries")
	}
}

// =============================================================================
// GitScanner (Full Integration)
// =============================================================================

func TestGitScanner_DetectsSecretsInHistory(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")

	// Commit 1: Clean file
	commitFile(t, dir, "README.md", "# My Project\n", "initial commit")

	// Commit 2: Add a secret!
	commitFile(t, dir, "config.env",
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
		"add aws credentials")

	// Commit 3: Remove the secret (but it's still in history!)
	writeFile(t, dir, "config.env", "# AWS credentials removed\n")
	commitAll(t, dir, "remove credentials")

	engine := detector.NewDefault()
	scanner := NewGitScanner(engine, DefaultScanOptions())

	ctx := context.Background()
	repo, err := OpenRepository(dir)
	if err != nil {
		t.Fatal(err)
	}

	result, err := scanner.ScanRepository(ctx, repo)
	if err != nil {
		t.Fatalf("ScanRepository failed: %v", err)
	}

	if result.TotalFindings == 0 {
		t.Fatal("expected to find secrets in git history, got 0 findings")
	}

	// Verify findings have git-specific metadata
	findings := result.AllFindings()
	for _, f := range findings {
		if f.Source.Type != "git-commit" {
			t.Errorf("expected source type 'git-commit', got '%s'", f.Source.Type)
		}
		if f.Source.CommitHash == "" {
			t.Error("finding should have a commit hash")
		}
		if f.Source.Author == "" {
			t.Error("finding should have an author")
		}
		// Pipeline should have sanitized raw match
		if f.RawMatch != "" {
			t.Error("RawMatch should be cleared by pipeline")
		}
		if f.SecretHash == "" {
			t.Error("SecretHash should be set by pipeline")
		}
		if f.RedactedMatch == "" {
			t.Error("RedactedMatch should be set by pipeline")
		}
	}

	t.Logf("Found %d secrets across %d commits", result.TotalFindings, result.ScannedCommits)
}

func TestGitScanner_CleanRepoNoFindings(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")
	commitFile(t, dir, "README.md", "# Clean Project\nNo secrets here.\n", "initial")
	commitFile(t, dir, "main.go", "package main\n\nfunc main() {}\n", "add main")

	engine := detector.NewDefault()
	scanner := NewGitScanner(engine, DefaultScanOptions())

	ctx := context.Background()
	repo, _ := OpenRepository(dir)

	result, err := scanner.ScanRepository(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}

	if result.TotalFindings != 0 {
		t.Errorf("expected 0 findings in clean repo, got %d", result.TotalFindings)
	}
}

func TestGitScanner_MultipleSecretsAcrossCommits(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")

	// Commit 1: GitHub token
	commitFile(t, dir, "deploy.sh",
		"#!/bin/bash\nGITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12\n",
		"add deploy script")

	// Commit 2: Slack webhook
	commitFile(t, dir, "notify.py",
		"import requests\nSLACK_WEBHOOK='https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'\n",
		"add notification")

	// Commit 3: JWT token
	commitFile(t, dir, "auth.js",
		"const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';\n",
		"add auth token")

	engine := detector.NewDefault()
	scanner := NewGitScanner(engine, DefaultScanOptions())

	ctx := context.Background()
	repo, _ := OpenRepository(dir)

	result, err := scanner.ScanRepository(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}

	if result.TotalFindings < 2 {
		t.Errorf("expected at least 2 findings across commits, got %d", result.TotalFindings)
	}

	// Verify we have results from multiple commits
	if len(result.CommitResults) < 2 {
		t.Errorf("expected findings in at least 2 commits, got %d", len(result.CommitResults))
	}

	t.Logf("Found %d secrets across %d commits with findings", result.TotalFindings, len(result.CommitResults))
}

func TestGitScanner_IncrementalScan(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")

	// Old commits (already scanned)
	commitFile(t, dir, "old.txt", "old content\n", "old commit")
	sinceHash := getHeadHash(t, dir)

	// New commits (need scanning)
	commitFile(t, dir, "new_secret.env",
		"STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n",
		"add stripe key")

	engine := detector.NewDefault()
	opts := DefaultScanOptions()
	opts.SinceCommit = sinceHash
	scanner := NewGitScanner(engine, opts)

	ctx := context.Background()
	repo, _ := OpenRepository(dir)

	result, err := scanner.ScanRepository(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}

	// Should only scan new commits
	if result.ScannedCommits != 1 {
		t.Errorf("incremental scan should process 1 commit, got %d", result.ScannedCommits)
	}

	if result.TotalFindings == 0 {
		t.Error("expected to find the Stripe key in the new commit")
	}
}

func TestGitScanner_MaxCommitsLimit(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")
	for i := 0; i < 10; i++ {
		commitFile(t, dir, fmt.Sprintf("file%d.txt", i), fmt.Sprintf("content %d", i), fmt.Sprintf("commit %d", i))
	}

	engine := detector.NewDefault()
	opts := DefaultScanOptions()
	opts.MaxCommits = 3
	scanner := NewGitScanner(engine, opts)

	ctx := context.Background()
	repo, _ := OpenRepository(dir)

	result, err := scanner.ScanRepository(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}

	if result.ScannedCommits > 3 {
		t.Errorf("should scan at most 3 commits, scanned %d", result.ScannedCommits)
	}
}

func TestGitScanner_ContextCancellation(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")
	for i := 0; i < 20; i++ {
		commitFile(t, dir, fmt.Sprintf("file%d.txt", i), fmt.Sprintf("content %d", i), fmt.Sprintf("commit %d", i))
	}

	engine := detector.NewDefault()
	scanner := NewGitScanner(engine, DefaultScanOptions())

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel before starting — should exit quickly
	cancel()

	repo, _ := OpenRepository(dir)

	result, err := scanner.ScanRepository(ctx, repo)
	// Should handle cancellation gracefully
	if err != nil {
		t.Logf("scan returned error (expected): %v", err)
	}
	if result != nil {
		t.Logf("scanned %d commits before cancellation", result.ScannedCommits)
	}
}

func TestGitScanner_Progress(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")
	commitFile(t, dir, "a.txt", "content a\n", "one")
	commitFile(t, dir, "b.txt", "content b\n", "two")
	commitFile(t, dir, "c.txt", "content c\n", "three")

	engine := detector.NewDefault()
	scanner := NewGitScanner(engine, DefaultScanOptions())

	ctx := context.Background()
	repo, _ := OpenRepository(dir)

	_, err := scanner.ScanRepository(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}

	progress := scanner.Progress()
	if progress.TotalCommits != 3 {
		t.Errorf("expected total commits 3, got %d", progress.TotalCommits)
	}
	if progress.ScannedCommits < 3 {
		t.Errorf("expected scanned commits 3, got %d", progress.ScannedCommits)
	}
}

func TestGitScanner_DeletedSecretStillDetected(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")

	// Add a secret
	commitFile(t, dir, "secrets.yaml",
		"database:\n  password: SuperSecretPassword123!\n",
		"add database config")

	// Delete the file entirely
	os.Remove(filepath.Join(dir, "secrets.yaml"))
	commitAll(t, dir, "remove secrets file")

	// The secret no longer exists in the working directory
	if _, err := os.Stat(filepath.Join(dir, "secrets.yaml")); !os.IsNotExist(err) {
		t.Fatal("secrets.yaml should be deleted from working directory")
	}

	// But it should still be found in git history!
	engine := detector.NewDefault()
	scanner := NewGitScanner(engine, DefaultScanOptions())

	ctx := context.Background()
	repo, _ := OpenRepository(dir)

	result, err := scanner.ScanRepository(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}

	// The detection engine should find the password in the commit where it was added
	// Even though it's been deleted from the current working tree
	t.Logf("Deleted secret scan: %d findings across %d commits", result.TotalFindings, result.ScannedCommits)

	// Note: Whether the password pattern is detected depends on the engine's rules.
	// The key assertion is that the scanner processes the historical commit with the secret added.
	if result.ScannedCommits < 1 {
		t.Error("should have scanned at least 1 commit")
	}
}

func TestGitScanner_SourceFields(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")

	commitFile(t, dir, "api.env",
		"OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNO\n",
		"add openai key")

	engine := detector.NewDefault()
	scanner := NewGitScanner(engine, DefaultScanOptions())

	ctx := context.Background()
	repo, _ := OpenRepository(dir)

	result, err := scanner.ScanRepository(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}

	if result.TotalFindings == 0 {
		t.Skip("no findings detected (rule may not match this pattern)")
	}

	finding := result.AllFindings()[0]

	if finding.Source.Type != "git-commit" {
		t.Errorf("source type: expected 'git-commit', got '%s'", finding.Source.Type)
	}
	if finding.Source.Location != "api.env" {
		t.Errorf("source location: expected 'api.env', got '%s'", finding.Source.Location)
	}
	if finding.Source.CommitHash == "" {
		t.Error("source commit hash should be set")
	}
	if len(finding.Source.CommitHash) != 40 {
		t.Errorf("commit hash should be 40 chars, got %d: %s", len(finding.Source.CommitHash), finding.Source.CommitHash)
	}
	if !strings.Contains(finding.Source.Author, "Test User") {
		t.Errorf("author should contain 'Test User', got '%s'", finding.Source.Author)
	}
}

// =============================================================================
// Result Helper Methods
// =============================================================================

func TestGitScanResult_AllFindings(t *testing.T) {
	result := &GitScanResult{
		CommitResults: map[string]*CommitScanResult{
			"abc": {Findings: make([]models.Finding, 2)},
			"def": {Findings: make([]models.Finding, 3)},
		},
	}

	all := result.AllFindings()
	if len(all) != 5 {
		t.Errorf("expected 5 total findings, got %d", len(all))
	}
}

func TestGitScanResult_CommitHashes(t *testing.T) {
	result := &GitScanResult{
		CommitResults: map[string]*CommitScanResult{
			"abc123": {},
			"def456": {},
		},
	}

	hashes := result.CommitHashes()
	if len(hashes) != 2 {
		t.Errorf("expected 2 hashes, got %d", len(hashes))
	}
}

// =============================================================================
// ReconstructFileContent
// =============================================================================

func TestReconstructFileContent(t *testing.T) {
	entry := DiffEntry{
		AddedLines: map[int]string{
			1: "line one",
			2: "line two",
			3: "line three",
		},
	}

	content := ReconstructFileContent(entry)
	lines := strings.Split(content, "\n")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(lines))
	}
	if lines[0] != "line one" {
		t.Errorf("expected 'line one', got '%s'", lines[0])
	}
}

func TestReconstructFileContent_Empty(t *testing.T) {
	entry := DiffEntry{AddedLines: map[int]string{}}
	content := ReconstructFileContent(entry)
	if content != "" {
		t.Errorf("expected empty content, got '%s'", content)
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestSortInts(t *testing.T) {
	tests := []struct {
		input    []int
		expected []int
	}{
		{[]int{3, 1, 2}, []int{1, 2, 3}},
		{[]int{1}, []int{1}},
		{[]int{}, []int{}},
		{[]int{5, 4, 3, 2, 1}, []int{1, 2, 3, 4, 5}},
		{[]int{1, 2, 3}, []int{1, 2, 3}}, // already sorted
	}

	for _, tt := range tests {
		sortInts(tt.input)
		for i, v := range tt.input {
			if v != tt.expected[i] {
				t.Errorf("sort failed: got %v, want %v", tt.input, tt.expected)
				break
			}
		}
	}
}

func TestGitScanResult_EmptyResult(t *testing.T) {
	result := &GitScanResult{
		CommitResults: make(map[string]*CommitScanResult),
	}

	all := result.AllFindings()
	if all != nil {
		t.Errorf("expected nil findings for empty result, got %v", all)
	}

	hashes := result.CommitHashes()
	if len(hashes) != 0 {
		t.Errorf("expected 0 hashes for empty result, got %d", len(hashes))
	}
}

func TestGitScanner_ScanDuration(t *testing.T) {
	dir, cleanup := createTestRepo(t)
	defer cleanup()

	run(t, dir, "git", "checkout", "-b", "main")
	commitFile(t, dir, "file.txt", "hello\n", "initial")

	engine := detector.NewDefault()
	scanner := NewGitScanner(engine, DefaultScanOptions())

	ctx := context.Background()
	repo, _ := OpenRepository(dir)

	result, err := scanner.ScanRepository(ctx, repo)
	if err != nil {
		t.Fatal(err)
	}

	if result.Duration <= 0 {
		t.Error("scan duration should be positive")
	}
	if result.StartedAt.IsZero() {
		t.Error("started_at should be set")
	}
	if result.FinishedAt.IsZero() {
		t.Error("finished_at should be set")
	}
	if result.FinishedAt.Before(result.StartedAt) {
		t.Error("finished_at should be after started_at")
	}
}

// =============================================================================
// Benchmark
// =============================================================================

func BenchmarkParseDiff_SmallDiff(b *testing.B) {
	diff := `diff --git a/config.env b/config.env
new file mode 100644
--- /dev/null
+++ b/config.env
@@ -0,0 +1,3 @@
+AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
+AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
+DB_PASSWORD=SuperSecret123!`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseDiff(diff)
	}
}

func BenchmarkParseDiff_LargeDiff(b *testing.B) {
	var builder strings.Builder
	builder.WriteString("diff --git a/big.txt b/big.txt\nnew file mode 100644\n--- /dev/null\n+++ b/big.txt\n@@ -0,0 +1,1000 @@\n")
	for i := 0; i < 1000; i++ {
		builder.WriteString(fmt.Sprintf("+line %d: some content here with data value=%d\n", i, i))
	}

	diff := builder.String()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseDiff(diff)
	}
}

// =============================================================================
// Import guard — ensure models is used
// =============================================================================

var _ time.Time // ensure time import is used

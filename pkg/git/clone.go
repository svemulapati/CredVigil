package git

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// OpenRepository opens an existing local git repository for scanning.
func OpenRepository(path string) (*Repository, error) {
	if err := gitAvailable(); err != nil {
		return nil, err
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve path %s: %w", path, err)
	}

	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("cannot access %s: %w", absPath, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", absPath)
	}

	if !isGitRepository(absPath) {
		return nil, fmt.Errorf("%s is not a git repository", absPath)
	}

	// Resolve to the repository root
	root, err := gitExec(absPath, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, fmt.Errorf("cannot find repository root: %w", err)
	}

	return &Repository{
		Path:     root,
		isCloned: false,
	}, nil
}

// CloneRepository clones a remote repository to a temporary directory.
// The caller must call Cleanup() when done to remove the cloned directory.
func CloneRepository(url string, opts ScanOptions) (*Repository, error) {
	if err := gitAvailable(); err != nil {
		return nil, err
	}

	if url == "" {
		return nil, fmt.Errorf("repository URL is required")
	}

	// Create a temporary directory for the clone
	tmpDir, err := os.MkdirTemp("", "credvigil-clone-*")
	if err != nil {
		return nil, fmt.Errorf("cannot create temp directory: %w", err)
	}

	args := []string{"clone"}

	// Add depth if specified
	if opts.Depth > 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", opts.Depth))
	}

	// Clone specific branch if specified
	if opts.Branch != "" {
		args = append(args, "--branch", opts.Branch)
	}

	// Disable interactive prompts
	args = append(args, "--no-interactive")

	args = append(args, url, tmpDir)

	// Run clone in an empty dir context (not inside a repo)
	if _, err := gitExec("", args...); err != nil {
		// Clean up temp dir on failure
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("clone failed for %s: %w", url, err)
	}

	return &Repository{
		Path:      tmpDir,
		isCloned:  true,
		remoteURL: url,
	}, nil
}

// Cleanup removes cloned repository files from disk.
// For locally opened repositories, this is a no-op.
// This follows zero-trust: cloned repos are securely removed after scanning.
func (r *Repository) Cleanup() error {
	if !r.isCloned {
		return nil // Don't delete local repos
	}
	if r.Path == "" {
		return nil
	}
	return os.RemoveAll(r.Path)
}

// IsCloned returns whether this repository was cloned by us.
func (r *Repository) IsCloned() bool {
	return r.isCloned
}

// RemoteURL returns the remote URL if this was a cloned repository.
func (r *Repository) RemoteURL() string {
	return r.remoteURL
}

// HeadCommit returns the hash of the current HEAD commit.
func (r *Repository) HeadCommit() (string, error) {
	return gitExec(r.Path, "rev-parse", "HEAD")
}

// DefaultBranch returns the name of the default branch.
func (r *Repository) DefaultBranch() (string, error) {
	// Try the symbolic ref first (works for local repos)
	ref, err := gitExec(r.Path, "symbolic-ref", "--short", "HEAD")
	if err == nil {
		return ref, nil
	}

	// For detached HEAD, try common defaults
	for _, branch := range []string{"main", "master"} {
		if _, err := gitExec(r.Path, "rev-parse", "--verify", branch); err == nil {
			return branch, nil
		}
	}

	return "", fmt.Errorf("could not determine default branch")
}

// Branches returns a list of all local branch names.
func (r *Repository) Branches() ([]string, error) {
	out, err := gitExec(r.Path, "branch", "--format=%(refname:short)")
	if err != nil {
		return nil, err
	}
	if out == "" {
		return nil, nil
	}
	branches := strings.Split(out, "\n")
	var result []string
	for _, b := range branches {
		b = strings.TrimSpace(b)
		if b != "" {
			result = append(result, b)
		}
	}
	return result, nil
}

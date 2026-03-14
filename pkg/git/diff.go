package git

import (
	"strconv"
	"strings"
)

// ParseDiff parses a unified diff output into structured DiffEntry objects.
// It only extracts ADDED lines (lines starting with "+") because those are
// the lines where new secrets could appear. Deleted lines are ignored —
// we care about what was introduced, not what was removed.
func ParseDiff(diffOutput string) []DiffEntry {
	if diffOutput == "" {
		return nil
	}

	var entries []DiffEntry
	var current *DiffEntry
	var newLineNum int

	lines := strings.Split(diffOutput, "\n")

	for _, line := range lines {
		// New file header: "diff --git a/path b/path"
		if strings.HasPrefix(line, "diff --git ") {
			if current != nil {
				entries = append(entries, *current)
			}
			current = &DiffEntry{
				AddedLines: make(map[int]string),
			}
			// Extract file path from "diff --git a/foo b/foo"
			parts := strings.SplitN(line, " b/", 2)
			if len(parts) == 2 {
				current.FilePath = parts[1]
			}
			continue
		}

		if current == nil {
			continue
		}

		// Detect change type from the diff header lines
		if strings.HasPrefix(line, "new file") {
			current.ChangeType = "A"
			continue
		}
		if strings.HasPrefix(line, "deleted file") {
			current.ChangeType = "D"
			continue
		}
		if strings.HasPrefix(line, "rename from ") {
			current.ChangeType = "R"
			current.OldPath = strings.TrimPrefix(line, "rename from ")
			continue
		}
		if strings.HasPrefix(line, "rename to ") {
			current.FilePath = strings.TrimPrefix(line, "rename to ")
			continue
		}

		// Parse the --- and +++ headers for file paths (fallback)
		if strings.HasPrefix(line, "+++ b/") {
			if current.FilePath == "" {
				current.FilePath = strings.TrimPrefix(line, "+++ b/")
			}
			continue
		}
		if strings.HasPrefix(line, "--- a/") {
			if current.OldPath == "" && current.ChangeType == "R" {
				current.OldPath = strings.TrimPrefix(line, "--- a/")
			}
			continue
		}
		// Skip binary file markers and other header lines
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") {
			continue
		}
		if strings.HasPrefix(line, "index ") || strings.HasPrefix(line, "similarity") {
			continue
		}
		if strings.HasPrefix(line, "Binary files") {
			continue
		}

		// Hunk header: @@ -old,count +new,count @@ optional context
		if strings.HasPrefix(line, "@@") {
			newLineNum = parseHunkNewStart(line)
			if current.ChangeType == "" {
				current.ChangeType = "M" // Modified by default
			}
			continue
		}

		// Added line
		if strings.HasPrefix(line, "+") {
			content := line[1:] // Remove the leading "+"
			current.AddedLines[newLineNum] = content
			current.Patch += line + "\n"
			newLineNum++
			continue
		}

		// Removed line (don't increment new line counter)
		if strings.HasPrefix(line, "-") {
			current.Patch += line + "\n"
			continue
		}

		// Context line (unchanged)
		if strings.HasPrefix(line, " ") || line == "" {
			newLineNum++
			continue
		}
	}

	// Don't forget the last entry
	if current != nil {
		entries = append(entries, *current)
	}

	return entries
}

// parseHunkNewStart extracts the starting line number for new content
// from a hunk header like "@@ -10,5 +20,8 @@" → returns 20.
func parseHunkNewStart(header string) int {
	// Find the "+X" part between the @@ markers
	parts := strings.SplitN(header, "+", 2)
	if len(parts) < 2 {
		return 1
	}

	numPart := parts[1]
	// Strip anything after the comma or space
	if idx := strings.IndexAny(numPart, ", @"); idx != -1 {
		numPart = numPart[:idx]
	}

	n, err := strconv.Atoi(strings.TrimSpace(numPart))
	if err != nil {
		return 1
	}
	return n
}

// FilterDiffEntries filters diff entries based on include/exclude patterns.
// Patterns use simple glob matching (filepath.Match style).
func FilterDiffEntries(entries []DiffEntry, include, exclude []string) []DiffEntry {
	if len(include) == 0 && len(exclude) == 0 {
		return entries
	}

	var filtered []DiffEntry
	for _, entry := range entries {
		if shouldIncludeFile(entry.FilePath, include, exclude) {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}

// shouldIncludeFile checks if a file path passes the include/exclude filters.
func shouldIncludeFile(filePath string, include, exclude []string) bool {
	// Check excludes first
	for _, pattern := range exclude {
		if matchPattern(filePath, pattern) {
			return false
		}
	}

	// If no includes specified, include everything not excluded
	if len(include) == 0 {
		return true
	}

	// Check if file matches any include pattern
	for _, pattern := range include {
		if matchPattern(filePath, pattern) {
			return true
		}
	}

	return false
}

// matchPattern does simple pattern matching supporting:
//   - "*" matches any sequence of characters (within a path segment)
//   - Direct substring matching as fallback
func matchPattern(path, pattern string) bool {
	// Exact match
	if path == pattern {
		return true
	}

	// Extension matching (e.g., "*.go")
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(path, pattern[1:])
	}

	// Directory prefix matching (e.g., "vendor/")
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(path, pattern)
	}

	// Substring matching
	return strings.Contains(path, pattern)
}

// ReconstructFileContent reconstructs the content of a file at a specific
// commit by combining all added lines from the diff. This is used when
// scanning newly added files (change type "A") where every line is "added."
func ReconstructFileContent(entry DiffEntry) string {
	if len(entry.AddedLines) == 0 {
		return ""
	}

	// Find max line number to size the output
	maxLine := 0
	for lineNum := range entry.AddedLines {
		if lineNum > maxLine {
			maxLine = lineNum
		}
	}

	// Build the content with lines in order
	lines := make([]string, maxLine)
	for lineNum, content := range entry.AddedLines {
		if lineNum > 0 && lineNum <= maxLine {
			lines[lineNum-1] = content
		}
	}

	return strings.Join(lines, "\n")
}

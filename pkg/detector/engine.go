// Package detector provides the core secret detection engine.
// It combines regex pattern matching with Shannon entropy analysis
// to identify hardcoded secrets in source code and configuration files.
package detector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/credvigil/credvigil/pkg/entropy"
	"github.com/credvigil/credvigil/pkg/models"
	"github.com/credvigil/credvigil/pkg/rules"
)

// Engine is the core detection engine that scans content for secrets.
type Engine struct {
	ruleSet      *rules.RuleSet
	mu           sync.RWMutex
	config       Config
	findingCount uint64
}

// Config holds configuration for the detection engine.
type Config struct {
	// Minimum confidence threshold (0.0-1.0) for reporting findings
	MinConfidence float64
	// Minimum severity for reporting
	MinSeverity models.Severity
	// Whether to run entropy-based detection (in addition to regex)
	EnableEntropy bool
	// Minimum length for entropy-based detection candidates
	EntropyMinLength int
	// Whether to include surrounding context in findings
	IncludeContext bool
	// Number of context lines to include before/after match
	ContextLines int
	// Maximum file size to scan (bytes). 0 = unlimited
	MaxFileSize int64
	// Secret types to exclude from scanning
	ExcludeTypes []models.SecretType
	// Rule IDs to exclude
	ExcludeRuleIDs []string
	// Allow-list patterns (if matched, finding is suppressed)
	AllowListPatterns []string
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() Config {
	return Config{
		MinConfidence:    0.3,
		MinSeverity:      models.SeverityInfo,
		EnableEntropy:    true,
		EntropyMinLength: 12,
		IncludeContext:   true,
		ContextLines:     2,
		MaxFileSize:      10 * 1024 * 1024, // 10 MB
	}
}

// New creates a new detection Engine with the given config.
func New(cfg Config) *Engine {
	return &Engine{
		ruleSet: rules.NewRuleSet(),
		config:  cfg,
	}
}

// NewDefault creates a new Engine with default configuration.
func NewDefault() *Engine {
	return New(DefaultConfig())
}

// RuleCount returns the number of loaded detection rules.
func (e *Engine) RuleCount() int {
	return e.ruleSet.Count()
}

// ScanContent scans text content for secrets and returns all findings.
func (e *Engine) ScanContent(req models.ScanRequest) models.ScanResult {
	start := time.Now()
	result := models.ScanResult{
		Source:          req.Source,
		CountBySeverity: make(map[models.Severity]int),
	}

	if req.Content == "" {
		result.Duration = time.Since(start)
		return result
	}

	// Check file size limit
	if e.config.MaxFileSize > 0 && int64(len(req.Content)) > e.config.MaxFileSize {
		result.Errors = append(result.Errors, fmt.Sprintf("content exceeds max size limit (%d bytes)", e.config.MaxFileSize))
		result.Duration = time.Since(start)
		return result
	}

	lines := strings.Split(req.Content, "\n")

	// Build exclusion sets
	excludeTypes := make(map[models.SecretType]bool)
	for _, t := range e.config.ExcludeTypes {
		excludeTypes[t] = true
	}

	// If specific types requested, exclude everything else
	if len(req.FilterTypes) > 0 {
		filterSet := make(map[models.SecretType]bool)
		for _, t := range req.FilterTypes {
			filterSet[t] = true
		}
		for _, r := range e.ruleSet.Rules() {
			if !filterSet[r.SecretType] {
				excludeTypes[r.SecretType] = true
			}
		}
	}

	excludeRules := make(map[string]bool)
	for _, id := range e.config.ExcludeRuleIDs {
		excludeRules[id] = true
	}

	// Track seen hashes to deduplicate findings in the same scan
	seen := make(map[string]bool)

	// Run regex-based detection
	for _, rule := range e.ruleSet.Rules() {
		if excludeTypes[rule.SecretType] || excludeRules[rule.ID] {
			continue
		}
		findings := e.matchRule(rule, req.Content, lines, req.Source)
		for _, f := range findings {
			hash := hashSecret(f.RawMatch)
			key := fmt.Sprintf("%s:%s:%d", hash, f.RuleID, f.Source.Line)
			if seen[key] {
				continue
			}
			// Apply minimum thresholds
			minConf := e.config.MinConfidence
			if req.MinConfidence > 0 {
				minConf = req.MinConfidence
			}
			if f.Confidence < minConf {
				continue
			}
			minSev := e.config.MinSeverity
			if req.MinSeverity > minSev {
				minSev = req.MinSeverity
			}
			if f.Severity < minSev {
				continue
			}
			// Check allow-list
			if e.isAllowListed(f.RawMatch) {
				continue
			}
			seen[key] = true
			result.Findings = append(result.Findings, f)
			result.CountBySeverity[f.Severity]++
		}
	}

	// Run entropy-based detection (catches novel/unknown secret types)
	if e.config.EnableEntropy {
		entropyFindings := e.entropyDetection(req.Content, lines, req.Source)
		for _, f := range entropyFindings {
			hash := hashSecret(f.RawMatch)
			key := fmt.Sprintf("%s:entropy:%d", hash, f.Source.Line)
			if seen[key] {
				continue
			}
			if f.Confidence < e.config.MinConfidence {
				continue
			}
			// Apply minimum severity filter to entropy findings too
			minSev := e.config.MinSeverity
			if req.MinSeverity > minSev {
				minSev = req.MinSeverity
			}
			if f.Severity < minSev {
				continue
			}
			seen[key] = true
			result.Findings = append(result.Findings, f)
			result.CountBySeverity[f.Severity]++
		}
	}

	result.TotalFindings = len(result.Findings)
	result.Duration = time.Since(start)
	return result
}

// ScanLines scans individual lines (useful for streaming and file watchers).
func (e *Engine) ScanLines(lines []string, source models.Source) []models.Finding {
	content := strings.Join(lines, "\n")
	req := models.ScanRequest{
		Content: content,
		Source:  source,
	}
	result := e.ScanContent(req)
	return result.Findings
}

// matchRule applies a single rule against the full content and returns findings.
func (e *Engine) matchRule(rule rules.Rule, content string, lines []string, source models.Source) []models.Finding {
	var findings []models.Finding
	matches := rule.Pattern.FindAllStringSubmatchIndex(content, -1)
	if matches == nil {
		return findings
	}

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		// Determine which group to use as the "secret"
		// If there are capture groups, use the first one; otherwise use the full match
		secretStart, secretEnd := match[0], match[1]
		if len(match) >= 4 && match[2] >= 0 {
			secretStart, secretEnd = match[2], match[3]
		}
		secretValue := content[secretStart:secretEnd]

		// Skip empty or very short matches
		if len(strings.TrimSpace(secretValue)) < 4 {
			continue
		}

		// Calculate entropy
		ent := entropy.Shannon(secretValue)

		// Check minimum entropy requirement
		if rule.MinEntropy > 0 && ent < rule.MinEntropy {
			continue
		}

		// Calculate line number
		lineNum := strings.Count(content[:secretStart], "\n") + 1
		endLineNum := strings.Count(content[:secretEnd], "\n") + 1

		// Compute confidence
		confidence := e.computeConfidence(rule, secretValue, content, secretStart, ent)

		// Get context
		ctx := ""
		if e.config.IncludeContext {
			ctx = e.getContext(lines, lineNum, e.config.ContextLines)
		}

		finding := models.Finding{
			ID:          e.generateID(),
			SecretType:  rule.SecretType,
			Description: rule.Description,
			Severity:    rule.Severity,
			RuleID:      rule.ID,
			Source: models.Source{
				Type:     source.Type,
				Location: source.Location,
				Line:     lineNum,
				EndLine:  endLineNum,
				Context:  ctx,
			},
			RawMatch:   secretValue,
			Entropy:    ent,
			Confidence: confidence,
			DetectedAt: time.Now(),
			Metadata: map[string]string{
				"sha256": hashSecret(secretValue),
			},
		}

		// Copy over source metadata
		if source.CommitHash != "" {
			finding.Source.CommitHash = source.CommitHash
		}
		if source.Author != "" {
			finding.Source.Author = source.Author
		}
		if source.Branch != "" {
			finding.Source.Branch = source.Branch
		}
		if source.MachineID != "" {
			finding.Source.MachineID = source.MachineID
		}

		finding.Redact()
		findings = append(findings, finding)
	}
	return findings
}

// computeConfidence calculates a confidence score for a finding based on
// rule matching, entropy, context keywords, and false-positive indicators.
func (e *Engine) computeConfidence(rule rules.Rule, secret, fullContent string, matchPos int, ent float64) float64 {
	confidence := rule.BaseConfidence

	// Entropy boost/penalty
	charset := entropy.DetectCharset(secret)
	if ent >= charset.HighThreshold() {
		confidence += 0.10
	} else if ent < charset.Threshold()*0.8 {
		confidence -= 0.20
	}

	// Keyword proximity boost: check surrounding text for keywords
	contextWindow := 200
	start := matchPos - contextWindow
	if start < 0 {
		start = 0
	}
	end := matchPos + len(secret) + contextWindow
	if end > len(fullContent) {
		end = len(fullContent)
	}
	surroundingText := strings.ToLower(fullContent[start:end])

	keywordsFound := 0
	for _, kw := range rule.Keywords {
		if strings.Contains(surroundingText, strings.ToLower(kw)) {
			keywordsFound++
		}
	}
	if len(rule.Keywords) > 0 {
		keywordRatio := float64(keywordsFound) / float64(len(rule.Keywords))
		confidence += keywordRatio * 0.10 // Up to +0.10 for all keywords present
	}

	// False positive penalty
	for _, fpPattern := range rule.FalsePositivePatterns {
		if fpPattern.MatchString(surroundingText) {
			confidence -= 0.25
			break
		}
	}

	// Check if it looks like a placeholder (all same char, sequential, etc.)
	if isLikelyPlaceholder(secret) {
		confidence -= 0.40
	}

	// Length-based adjustment (very short secrets are less reliable)
	if len(secret) < 12 {
		confidence -= 0.10
	} else if len(secret) > 30 {
		confidence += 0.05
	}

	// Clamp to [0.0, 1.0]
	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0.0 {
		confidence = 0.0
	}
	return float64(int(confidence*100)) / 100 // Round to 2 decimal places
}

// entropyDetection scans for high-entropy strings not caught by regex rules.
func (e *Engine) entropyDetection(content string, lines []string, source models.Source) []models.Finding {
	var findings []models.Finding

	for i, line := range lines {
		matches := entropy.ExtractHighEntropyWords(line, e.config.EntropyMinLength)
		for _, m := range matches {
			if m.Score < 0.5 {
				continue // Only report high-confidence entropy matches
			}
			// Skip if it's mostly alphanumeric without special chars
			// (likely a variable name, not a secret)
			if isLikelyIdentifier(m.Value) {
				continue
			}

			ctx := ""
			if e.config.IncludeContext {
				ctx = e.getContext(lines, i+1, e.config.ContextLines)
			}

			// Check surrounding context for secret-like keywords
			surroundingText := strings.ToLower(line)
			hasSecretContext := false
			secretKeywords := []string{
				"key", "secret", "token", "password", "passwd", "pwd",
				"auth", "credential", "api_key", "access_key", "private",
				"connection", "bearer", "apikey",
			}
			for _, kw := range secretKeywords {
				if strings.Contains(surroundingText, kw) {
					hasSecretContext = true
					break
				}
			}

			// Only report entropy findings if they're near secret-like context
			// OR have very high entropy
			severity := models.SeverityLow
			confidence := m.Score * 0.6 // Entropy-only findings are lower confidence
			if hasSecretContext {
				confidence = m.Score * 0.8
				severity = models.SeverityMedium
			}
			if m.Entropy > 5.5 && len(m.Value) > 20 {
				confidence += 0.15
				severity = models.SeverityMedium
			}
			if confidence < e.config.MinConfidence {
				continue
			}

			finding := models.Finding{
				ID:          e.generateID(),
				SecretType:  models.SecretHighEntropy,
				Description: fmt.Sprintf("High-entropy %s string (entropy: %.2f)", m.Charset, m.Entropy),
				Severity:    severity,
				RuleID:      "entropy-detection",
				Source: models.Source{
					Type:     source.Type,
					Location: source.Location,
					Line:     i + 1,
					Context:  ctx,
				},
				RawMatch:   m.Value,
				Entropy:    m.Entropy,
				Confidence: confidence,
				DetectedAt: time.Now(),
				Metadata: map[string]string{
					"sha256":        hashSecret(m.Value),
					"charset":       m.Charset.String(),
					"entropy_score": fmt.Sprintf("%.2f", m.Score),
				},
			}
			finding.Redact()
			findings = append(findings, finding)
		}
	}
	return findings
}

// getContext returns surrounding lines for context display.
func (e *Engine) getContext(lines []string, lineNum, contextSize int) string {
	start := lineNum - 1 - contextSize
	if start < 0 {
		start = 0
	}
	end := lineNum + contextSize
	if end > len(lines) {
		end = len(lines)
	}

	var contextLines []string
	for i := start; i < end; i++ {
		prefix := "  "
		if i == lineNum-1 {
			prefix = "> "
		}
		contextLines = append(contextLines, fmt.Sprintf("%s%4d | %s", prefix, i+1, lines[i]))
	}
	return strings.Join(contextLines, "\n")
}

// generateID creates a unique finding ID.
func (e *Engine) generateID() string {
	e.mu.Lock()
	e.findingCount++
	count := e.findingCount
	e.mu.Unlock()
	return fmt.Sprintf("CVF-%d-%d", time.Now().UnixMilli(), count)
}

// isAllowListed checks if a secret matches any allow-list pattern.
func (e *Engine) isAllowListed(secret string) bool {
	for _, pattern := range e.config.AllowListPatterns {
		if strings.Contains(secret, pattern) {
			return true
		}
	}
	return false
}

// hashSecret returns the SHA-256 hash of a secret value.
func hashSecret(secret string) string {
	h := sha256.New()
	h.Write([]byte(secret))
	return hex.EncodeToString(h.Sum(nil))
}

// isLikelyPlaceholder detects placeholder/dummy values.
func isLikelyPlaceholder(s string) bool {
	lower := strings.ToLower(s)
	// Check for common placeholder patterns
	placeholders := []string{
		"xxxx", "yyyy", "zzzz", "0000", "1234", "abcd",
		"changeme", "change_me", "replace", "your_", "my_",
		"example", "sample", "dummy", "fake", "test",
		"placeholder", "insert_", "todo", "fixme",
	}
	for _, p := range placeholders {
		if strings.Contains(lower, p) {
			return true
		}
	}

	// Check if all characters are the same
	if len(s) > 4 {
		allSame := true
		for _, c := range s[1:] {
			if c != rune(s[0]) {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}
	return false
}

// isLikelyIdentifier checks if a string looks like a code identifier
// (e.g., camelCase, snake_case variable name) rather than a secret.
func isLikelyIdentifier(s string) bool {
	// If it contains only letters and underscores, it's likely a variable name
	allLettersOrUnderscore := true
	hasDigit := false
	for _, c := range s {
		if unicode.IsDigit(c) {
			hasDigit = true
		}
		if !unicode.IsLetter(c) && c != '_' && !unicode.IsDigit(c) {
			allLettersOrUnderscore = false
			break
		}
	}
	if allLettersOrUnderscore && !hasDigit {
		return true
	}

	// CamelCase check
	if len(s) > 8 && !hasDigit {
		upperCount := 0
		for _, c := range s {
			if unicode.IsUpper(c) {
				upperCount++
			}
		}
		// Typical identifiers have ~10-30% uppercase
		ratio := float64(upperCount) / float64(len(s))
		if ratio > 0.05 && ratio < 0.35 && allLettersOrUnderscore {
			return true
		}
	}
	return false
}

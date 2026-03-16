// Package entropy provides BPE (Byte Pair Encoding) token efficiency analysis
// for secret detection. Secrets and random strings have poor token efficiency
// because they resist compression — a BPE tokenizer needs many tokens to
// represent them compared to normal text.
//
// The intuition: BPE builds a vocabulary of common subword pairs. English text
// like "function" compresses into 1–2 tokens. A secret like "kJ9mN2pR5tW8x"
// requires almost one token per character because no common pairs exist.
//
// Token Efficiency = len(characters) / len(tokens)
//
//	High efficiency (≥ 3.0): normal text — few tokens represent many characters
//	Low efficiency (< 2.0): likely a secret — many tokens for few characters
package entropy

import (
	"sort"
	"strings"
	"unicode"
)

// BPEAnalyzer performs Byte Pair Encoding token efficiency analysis.
// It builds a vocabulary of common byte-pair merges from a base vocabulary,
// then measures how efficiently a given string can be tokenized.
type BPEAnalyzer struct {
	// merges maps a bigram ("ab") to its merge rank (lower = more common).
	merges map[string]int

	// vocab is the set of known merged tokens.
	vocab map[string]bool

	// maxMerges is the number of merge operations to learn.
	maxMerges int
}

// BPEResult holds the result of BPE token efficiency analysis.
type BPEResult struct {
	// Tokens is the list of BPE tokens the string was split into.
	Tokens []string

	// TokenCount is len(Tokens).
	TokenCount int

	// CharCount is the number of characters in the input.
	CharCount int

	// Efficiency is CharCount / TokenCount.
	// High values (≥ 3.0) = compressible (normal text).
	// Low values (< 2.0) = incompressible (likely a secret).
	Efficiency float64

	// IsLikelySecret is true when efficiency falls below the secret threshold.
	IsLikelySecret bool
}

// BPE thresholds for secret detection.
// With a compact merge vocabulary (~100 pairs), typical efficiency ranges are:
//   - Random/secret strings: 1.00–1.15 (almost no merges possible)
//   - Normal text:           1.30–1.70 (common bigrams merge)
const (
	// BPESecretThreshold: below this efficiency, a string is likely a secret.
	BPESecretThreshold = 1.3

	// BPEHighConfidenceThreshold: below this, very likely a secret.
	BPEHighConfidenceThreshold = 1.1

	// BPENormalThreshold: above this, the string is normal text.
	BPENormalThreshold = 1.5

	// DefaultBPEMerges is the default number of merge operations.
	DefaultBPEMerges = 256
)

// NewBPEAnalyzer creates a BPE analyzer with a pre-trained merge table
// derived from common source code and natural language patterns.
func NewBPEAnalyzer() *BPEAnalyzer {
	b := &BPEAnalyzer{
		merges:    make(map[string]int),
		vocab:     make(map[string]bool),
		maxMerges: DefaultBPEMerges,
	}
	b.trainDefaults()
	return b
}

// trainDefaults populates the merge table with common character pairs
// found in source code, configuration files, and natural language.
// These represent the most frequent bigrams — the pairs that a real
// BPE tokenizer would merge first.
func (b *BPEAnalyzer) trainDefaults() {
	// Common bigrams in English text and source code, ordered by frequency.
	// Each pair gets a rank (lower = more common = merged first).
	commonPairs := []string{
		// English language top bigrams
		"th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
		"ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
		"st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
		"ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
		"ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur",
		// Source code / config common pairs
		"ss", "ee", "tt", "ff", "oo", "nn", "pp", "rr",
		"ke", "ey", "va", "lu", "pa", "th", "na", "me",
		"fu", "nc", "ti", "on", "re", "tu", "rn",
		"cl", "as", "if", "el", "se", "fo", "wh", "il",
		"tr", "ue", "fa", "ls", "nu", "ul",
		"pr", "iv", "at", "pu", "bl",
		// Config patterns
		"UR", "ur", "rl", "ht", "tp", "://", "lo", "ca",
		"ho", "st", "po", "rt", "da", "ta", "ba",
		// Common programming tokens
		"__", "->", "=>", "::", "==", "!=", "<=", ">=",
		"++", "--", "&&", "||", "<<", ">>",
		// Lowercase + digit pairs are rare in normal text but common in secrets
		// (intentionally NOT included — keeps efficiency low for secrets)
	}

	for i, pair := range commonPairs {
		b.merges[pair] = i
		b.vocab[pair] = true
	}
}

// Tokenize splits a string into BPE tokens using the learned merge table.
// It starts with individual characters and iteratively merges the most
// frequent pair until no more merges are possible.
func (b *BPEAnalyzer) Tokenize(s string) []string {
	if len(s) == 0 {
		return nil
	}

	// Start with individual characters as tokens
	tokens := make([]string, 0, len(s))
	for _, c := range s {
		tokens = append(tokens, string(c))
	}

	// Iteratively merge the highest-ranked pair
	for {
		if len(tokens) < 2 {
			break
		}

		// Find the best (lowest rank) merge candidate
		bestPair := ""
		bestRank := len(b.merges) + 1
		bestIdx := -1

		for i := 0; i < len(tokens)-1; i++ {
			pair := tokens[i] + tokens[i+1]
			if rank, ok := b.merges[pair]; ok && rank < bestRank {
				bestRank = rank
				bestPair = pair
				bestIdx = i
				_ = bestPair // used below
			}
		}

		if bestIdx < 0 {
			break // No more merges possible
		}

		// Apply the merge: replace tokens[bestIdx] and tokens[bestIdx+1]
		// with the merged token, everywhere it appears
		merged := make([]string, 0, len(tokens))
		i := 0
		for i < len(tokens) {
			if i < len(tokens)-1 {
				pair := tokens[i] + tokens[i+1]
				if pair == bestPair {
					merged = append(merged, pair)
					i += 2
					continue
				}
			}
			merged = append(merged, tokens[i])
			i++
		}

		if len(merged) == len(tokens) {
			break // No progress — shouldn't happen, but safety check
		}
		tokens = merged
	}

	return tokens
}

// Analyze performs BPE tokenization and computes the efficiency score.
func (b *BPEAnalyzer) Analyze(s string) BPEResult {
	if len(s) == 0 {
		return BPEResult{}
	}

	tokens := b.Tokenize(s)
	charCount := len([]rune(s))
	tokenCount := len(tokens)

	efficiency := float64(charCount) / float64(tokenCount)

	return BPEResult{
		Tokens:         tokens,
		TokenCount:     tokenCount,
		CharCount:      charCount,
		Efficiency:     efficiency,
		IsLikelySecret: efficiency < BPESecretThreshold,
	}
}

// TokenEfficiency is a convenience function that returns just the efficiency
// score (charCount / tokenCount). Higher = more compressible = less likely a secret.
func (b *BPEAnalyzer) TokenEfficiency(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	r := b.Analyze(s)
	return r.Efficiency
}

// BPEScore returns a confidence score (0.0–1.0) indicating how likely
// a string is a secret based on BPE token efficiency.
//
//	1.0 = very likely a secret (efficiency near 1.0 — no compression at all)
//	0.0 = very likely normal text (efficiency ≥ 3.0 — compresses well)
func (b *BPEAnalyzer) BPEScore(s string) float64 {
	if len(s) < 8 {
		return 0.0 // Too short to analyze meaningfully
	}

	efficiency := b.TokenEfficiency(s)

	// Map efficiency to a 0-1 score where:
	//   efficiency ≤ 1.2 → score ≈ 1.0 (almost no compression = secret)
	//   efficiency ≥ 3.0 → score ≈ 0.0 (good compression = normal text)
	if efficiency <= BPEHighConfidenceThreshold {
		return 1.0
	}
	if efficiency >= BPENormalThreshold {
		return 0.0
	}

	// Linear interpolation between thresholds
	score := 1.0 - (efficiency-BPEHighConfidenceThreshold)/(BPENormalThreshold-BPEHighConfidenceThreshold)
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	return float64(int(score*100)) / 100 // Round to 2 decimal places
}

// ExtractLowEfficiencyWords splits text on delimiters and returns words
// with low BPE token efficiency (likely secrets).
func (b *BPEAnalyzer) ExtractLowEfficiencyWords(text string, minLength int) []BPEMatch {
	if minLength < 8 {
		minLength = 8
	}

	words := splitOnDelimiters(text)

	var matches []BPEMatch
	for _, word := range words {
		if len(word) < minLength {
			continue
		}

		// Skip words that are clearly identifiers (all letters/underscores)
		if isAllLettersOrUnderscores(word) {
			continue
		}

		result := b.Analyze(word)
		if result.IsLikelySecret {
			matches = append(matches, BPEMatch{
				Value:      word,
				Efficiency: result.Efficiency,
				TokenCount: result.TokenCount,
				CharCount:  result.CharCount,
				Score:      b.BPEScore(word),
			})
		}
	}

	// Sort by efficiency (lowest first = most likely secrets)
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Efficiency < matches[j].Efficiency
	})

	return matches
}

// BPEMatch represents a low-efficiency substring found in text.
type BPEMatch struct {
	Value      string
	Efficiency float64
	TokenCount int
	CharCount  int
	Score      float64
}

// isAllLettersOrUnderscores returns true if string contains only letters and underscores.
func isAllLettersOrUnderscores(s string) bool {
	for _, c := range s {
		if !unicode.IsLetter(c) && c != '_' {
			return false
		}
	}
	return true
}

// --- Utility: Compare entropy vs BPE for the same string ---

// DualAnalysis returns both Shannon entropy and BPE token efficiency
// analysis for a string, making it easy to compare the two approaches.
func DualAnalysis(s string) DualResult {
	bpe := NewBPEAnalyzer()

	shannonEnt := Shannon(s)
	charset := DetectCharset(s)
	entropyScore := EntropyScore(s)

	bpeResult := bpe.Analyze(s)
	bpeScore := bpe.BPEScore(s)

	return DualResult{
		Input:          s,
		ShannonEntropy: shannonEnt,
		Charset:        charset,
		EntropyScore:   entropyScore,
		BPEEfficiency:  bpeResult.Efficiency,
		BPETokenCount:  bpeResult.TokenCount,
		BPEScore:       bpeScore,
		BothAgree:      (entropyScore >= 0.5 && bpeScore >= 0.5) || (entropyScore < 0.5 && bpeScore < 0.5),
	}
}

// DualResult holds the results of both Shannon entropy and BPE analysis.
type DualResult struct {
	Input          string
	ShannonEntropy float64
	Charset        CharsetType
	EntropyScore   float64
	BPEEfficiency  float64
	BPETokenCount  int
	BPEScore       float64

	// BothAgree is true when entropy and BPE reach the same conclusion
	// (both say secret, or both say not-secret). When they agree,
	// confidence is highest.
	BothAgree bool
}

// CombinedScore returns a weighted combination of entropy and BPE scores.
// Weights: 50% entropy, 50% BPE. When both methods agree, the combined
// score is very high (likely secret) or very low (likely safe).
func (d DualResult) CombinedScore() float64 {
	combined := d.EntropyScore*0.5 + d.BPEScore*0.5
	if combined > 1.0 {
		combined = 1.0
	}
	return float64(int(combined*100)) / 100
}

// IsLikelySecret returns true if the combined analysis suggests this is a secret.
func (d DualResult) IsLikelySecret() bool {
	return d.CombinedScore() >= 0.5
}

// --- Package-level convenience functions ---

// defaultBPE is a package-level BPE analyzer (created once, reused).
var defaultBPE = NewBPEAnalyzer()

// BPETokenEfficiency returns the BPE token efficiency of a string
// using the default analyzer. Convenience wrapper.
func BPETokenEfficiency(s string) float64 {
	return defaultBPE.TokenEfficiency(s)
}

// IsBPESecret checks if a string has low BPE token efficiency,
// indicating it is likely a secret. Uses default thresholds.
func IsBPESecret(s string) bool {
	if len(s) < 8 {
		return false
	}
	return defaultBPE.TokenEfficiency(s) < BPESecretThreshold
}

// BPEConfidenceScore returns a 0.0–1.0 score for how likely a string
// is a secret based on BPE analysis. Uses the default analyzer.
func BPEConfidenceScore(s string) float64 {
	return defaultBPE.BPEScore(s)
}

// CombinedSecretScore returns a combined entropy + BPE score (0.0–1.0).
// This is the recommended single-number metric for secret detection.
func CombinedSecretScore(s string) float64 {
	result := DualAnalysis(s)
	return result.CombinedScore()
}

// FormatBPEAnalysis returns a human-readable string describing the BPE analysis.
func FormatBPEAnalysis(s string) string {
	r := defaultBPE.Analyze(s)
	var sb strings.Builder
	sb.WriteString("BPE Analysis:\n")
	sb.WriteString("  Input:       " + s + "\n")
	sb.WriteString("  Tokens:      [" + strings.Join(r.Tokens, "|") + "]\n")
	sb.WriteString("  Token count: " + itoa(r.TokenCount) + "\n")
	sb.WriteString("  Char count:  " + itoa(r.CharCount) + "\n")
	sb.WriteString("  Efficiency:  " + ftoa(r.Efficiency) + "\n")
	if r.IsLikelySecret {
		sb.WriteString("  Verdict:     🚨 LIKELY SECRET (low efficiency)\n")
	} else {
		sb.WriteString("  Verdict:     ✅ Normal text (high efficiency)\n")
	}
	return sb.String()
}

// itoa is a simple int-to-string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}

// ftoa formats a float with 2 decimal places without importing strconv.
func ftoa(f float64) string {
	whole := int(f)
	frac := int((f - float64(whole)) * 100)
	if frac < 0 {
		frac = -frac
	}
	fracStr := itoa(frac)
	if len(fracStr) == 1 {
		fracStr = "0" + fracStr
	}
	return itoa(whole) + "." + fracStr
}

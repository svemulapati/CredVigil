// Package entropy provides Shannon entropy calculation for secret detection.
// High-entropy strings are statistically likely to be secrets, keys, or tokens.
package entropy

import (
	"math"
	"strings"
	"unicode"
)

// Shannon calculates the Shannon entropy of a string.
// Returns a value between 0 (no randomness) and log2(charset_size) (maximum randomness).
// Typical thresholds:
//   - Hex strings: entropy > 3.0 is suspicious, > 3.5 is likely a secret
//   - Base64 strings: entropy > 4.0 is suspicious, > 4.5 is likely a secret
//   - General strings: entropy > 4.5 is suspicious, > 5.0 is likely a secret
func Shannon(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count frequency of each character
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}

	length := float64(len([]rune(s)))
	entropy := 0.0
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// ShannonPerByte normalizes entropy to 0.0-1.0 range based on observed charset.
func ShannonPerByte(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	uniqueChars := make(map[rune]bool)
	for _, c := range s {
		uniqueChars[c] = true
	}

	maxEntropy := math.Log2(float64(len(uniqueChars)))
	if maxEntropy == 0 {
		return 0
	}

	return Shannon(s) / maxEntropy
}

// CharsetType identifies what character set a string primarily uses.
type CharsetType int

const (
	CharsetUnknown        CharsetType = iota
	CharsetHex                        // 0-9, a-f, A-F
	CharsetBase64                     // A-Z, a-z, 0-9, +, /, =
	CharsetBase64URL                  // A-Z, a-z, 0-9, -, _
	CharsetAlphanumeric               // A-Z, a-z, 0-9
	CharsetPrintableASCII             // All printable ASCII
)

func (c CharsetType) String() string {
	switch c {
	case CharsetHex:
		return "hex"
	case CharsetBase64:
		return "base64"
	case CharsetBase64URL:
		return "base64url"
	case CharsetAlphanumeric:
		return "alphanumeric"
	case CharsetPrintableASCII:
		return "printable-ascii"
	default:
		return "unknown"
	}
}

// Threshold returns the entropy threshold for "suspicious" for this charset type.
func (c CharsetType) Threshold() float64 {
	switch c {
	case CharsetHex:
		return 3.0
	case CharsetBase64, CharsetBase64URL:
		return 4.0
	case CharsetAlphanumeric:
		return 4.2
	default:
		return 4.5
	}
}

// HighThreshold returns the entropy threshold for "very likely a secret" for this charset type.
func (c CharsetType) HighThreshold() float64 {
	switch c {
	case CharsetHex:
		return 3.5
	case CharsetBase64, CharsetBase64URL:
		return 4.5
	case CharsetAlphanumeric:
		return 4.7
	default:
		return 5.0
	}
}

// DetectCharset determines the primary charset of a string.
func DetectCharset(s string) CharsetType {
	if len(s) == 0 {
		return CharsetUnknown
	}

	isHex := true
	isBase64 := true
	isBase64URL := true
	isAlphaNum := true

	for _, c := range s {
		if !isHexChar(c) {
			isHex = false
		}
		if !isBase64Char(c) {
			isBase64 = false
		}
		if !isBase64URLChar(c) {
			isBase64URL = false
		}
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
			isAlphaNum = false
		}
		if !unicode.IsPrint(c) {
			return CharsetUnknown
		}
	}

	switch {
	case isHex:
		return CharsetHex
	case isBase64:
		return CharsetBase64
	case isBase64URL:
		return CharsetBase64URL
	case isAlphaNum:
		return CharsetAlphanumeric
	default:
		return CharsetPrintableASCII
	}
}

// IsHighEntropy checks if a string has suspiciously high entropy for its charset.
func IsHighEntropy(s string) bool {
	if len(s) < 8 {
		return false // Too short to be meaningful
	}

	charset := DetectCharset(s)
	ent := Shannon(s)
	return ent >= charset.Threshold()
}

// IsVeryHighEntropy checks if a string very likely contains a secret based on entropy.
func IsVeryHighEntropy(s string) bool {
	if len(s) < 8 {
		return false
	}

	charset := DetectCharset(s)
	ent := Shannon(s)
	return ent >= charset.HighThreshold()
}

// EntropyScore returns a confidence score (0.0-1.0) based on entropy analysis.
// It factors in string length, entropy value, and charset type.
func EntropyScore(s string) float64 {
	if len(s) < 8 {
		return 0.0
	}

	charset := DetectCharset(s)
	ent := Shannon(s)
	threshold := charset.Threshold()
	highThreshold := charset.HighThreshold()

	if ent < threshold*0.8 {
		return 0.0
	}

	// Normalize: 0.0 at 80% of threshold, 1.0 at high threshold
	score := (ent - threshold*0.8) / (highThreshold - threshold*0.8)
	if score > 1.0 {
		score = 1.0
	}
	if score < 0.0 {
		score = 0.0
	}

	// Boost score for longer strings (more confident)
	lengthFactor := math.Min(float64(len(s))/32.0, 1.0)
	score = score*0.7 + lengthFactor*0.3

	return math.Round(score*100) / 100
}

// ExtractHighEntropyWords splits text and returns words with high entropy.
// Useful for finding embedded secrets in configuration lines.
func ExtractHighEntropyWords(text string, minLength int) []HighEntropyMatch {
	if minLength < 8 {
		minLength = 8
	}

	// Split on common delimiters
	words := splitOnDelimiters(text)

	var matches []HighEntropyMatch
	for _, word := range words {
		if len(word) < minLength {
			continue
		}

		ent := Shannon(word)
		charset := DetectCharset(word)
		if ent >= charset.Threshold() {
			matches = append(matches, HighEntropyMatch{
				Value:   word,
				Entropy: ent,
				Charset: charset,
				Score:   EntropyScore(word),
			})
		}
	}

	return matches
}

// HighEntropyMatch represents a high-entropy substring found in text.
type HighEntropyMatch struct {
	Value   string
	Entropy float64
	Charset CharsetType
	Score   float64
}

// Helper functions

func isHexChar(c rune) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isBase64Char(c rune) bool {
	return unicode.IsLetter(c) || unicode.IsDigit(c) || c == '+' || c == '/' || c == '='
}

func isBase64URLChar(c rune) bool {
	return unicode.IsLetter(c) || unicode.IsDigit(c) || c == '-' || c == '_' || c == '='
}

func splitOnDelimiters(text string) []string {
	// Split on whitespace, quotes, colons, equals, commas, semicolons, braces
	return strings.FieldsFunc(text, func(c rune) bool {
		return unicode.IsSpace(c) || c == '"' || c == '\'' || c == ':' ||
			c == '=' || c == ',' || c == ';' || c == '{' || c == '}' ||
			c == '[' || c == ']' || c == '(' || c == ')' || c == '<' ||
			c == '>' || c == '`'
	})
}

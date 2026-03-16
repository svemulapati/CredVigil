package entropy

import (
	"strings"
	"testing"
)

// --- BPEAnalyzer Construction ---

func TestNewBPEAnalyzer(t *testing.T) {
	b := NewBPEAnalyzer()
	if b == nil {
		t.Fatal("NewBPEAnalyzer returned nil")
	}
	if len(b.merges) == 0 {
		t.Error("merge table is empty")
	}
	if len(b.vocab) == 0 {
		t.Error("vocab is empty")
	}
}

// --- Tokenize ---

func TestTokenizeEmpty(t *testing.T) {
	b := NewBPEAnalyzer()
	tokens := b.Tokenize("")
	if tokens != nil {
		t.Errorf("Tokenize('') = %v, want nil", tokens)
	}
}

func TestTokenizeSingleChar(t *testing.T) {
	b := NewBPEAnalyzer()
	tokens := b.Tokenize("a")
	if len(tokens) != 1 || tokens[0] != "a" {
		t.Errorf("Tokenize('a') = %v, want ['a']", tokens)
	}
}

func TestTokenizeNormalText(t *testing.T) {
	b := NewBPEAnalyzer()
	// "the" contains "th" and "he" which are top merges
	tokens := b.Tokenize("the")
	// Should merge to fewer than 3 tokens
	if len(tokens) >= 3 {
		t.Errorf("Tokenize('the') = %v (len %d), expected merges to reduce token count", tokens, len(tokens))
	}
}

func TestTokenizeRandomString(t *testing.T) {
	b := NewBPEAnalyzer()
	// Random characters with no common bigrams
	random := "xK3zQ9wJ7"
	tokens := b.Tokenize(random)
	// Should have almost 1 token per character (poor compression)
	charCount := len([]rune(random))
	if len(tokens) < charCount/2 {
		t.Errorf("Tokenize(%q) = %d tokens for %d chars, expected poor compression",
			random, len(tokens), charCount)
	}
}

// --- Analyze ---

func TestAnalyzeEmpty(t *testing.T) {
	b := NewBPEAnalyzer()
	r := b.Analyze("")
	if r.TokenCount != 0 || r.CharCount != 0 || r.Efficiency != 0 {
		t.Errorf("Analyze('') = %+v, expected zeros", r)
	}
}

func TestAnalyzeNormalText(t *testing.T) {
	b := NewBPEAnalyzer()
	r := b.Analyze("the function returns the value")
	if r.Efficiency < 1.2 {
		t.Errorf("Analyze(normal text) efficiency = %.2f, expected higher compression", r.Efficiency)
	}
	if r.IsLikelySecret {
		t.Error("Normal text should not be classified as a secret")
	}
}

func TestAnalyzeSecretString(t *testing.T) {
	b := NewBPEAnalyzer()
	// Typical API key — high randomness, no common bigrams
	r := b.Analyze("xK3zQ9wJ7mB5vN2yT8pL4")
	if r.Efficiency >= BPENormalThreshold {
		t.Errorf("Secret string efficiency = %.2f, expected < %.2f", r.Efficiency, BPENormalThreshold)
	}
}

func TestAnalyzeAWSKey(t *testing.T) {
	b := NewBPEAnalyzer()
	r := b.Analyze("AKIAIOSFODNN7EXAMPLE")
	// AWS keys use uppercase letters and digits — limited BPE compression
	t.Logf("AWS key: efficiency=%.2f, tokens=%d, chars=%d", r.Efficiency, r.TokenCount, r.CharCount)
}

func TestAnalyzeBase64Secret(t *testing.T) {
	b := NewBPEAnalyzer()
	r := b.Analyze("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	t.Logf("Base64 secret: efficiency=%.2f, tokens=%d, chars=%d, isSecret=%v",
		r.Efficiency, r.TokenCount, r.CharCount, r.IsLikelySecret)
}

// --- BPEScore ---

func TestBPEScoreShortString(t *testing.T) {
	b := NewBPEAnalyzer()
	score := b.BPEScore("abc")
	if score != 0.0 {
		t.Errorf("BPEScore('abc') = %f, expected 0.0 for short strings", score)
	}
}

func TestBPEScoreNormalText(t *testing.T) {
	b := NewBPEAnalyzer()
	// Normal text has higher efficiency → lower BPE score (less secret-like)
	normalScore := b.BPEScore("the function returns the value")
	secretScore := b.BPEScore("xK3zQ9wJ7mB5vN2yT8pL4")
	if normalScore >= secretScore {
		t.Errorf("Normal text BPE score (%f) should be less than secret score (%f)",
			normalScore, secretScore)
	}
}

func TestBPEScoreHighRandomness(t *testing.T) {
	b := NewBPEAnalyzer()
	// Completely random — no mergeable pairs
	score := b.BPEScore("xK3zQ9wJ7mB5vN2yT8pL4")
	if score < 0.3 {
		t.Errorf("BPEScore(random) = %f, expected >= 0.3", score)
	}
}

func TestBPEScoreRange(t *testing.T) {
	b := NewBPEAnalyzer()
	tests := []string{
		"this is normal text with common words",
		"functionReturnValue",
		"kJ9mN2pR5tW8xY1zA3bC6dE7fG8hI9j",
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_ABcDeFgHiJkLmNoPqRsTuVwXyZ012345",
	}
	for _, s := range tests {
		score := b.BPEScore(s)
		if score < 0.0 || score > 1.0 {
			t.Errorf("BPEScore(%q) = %f, out of range [0, 1]", s, score)
		}
	}
}

// --- TokenEfficiency ---

func TestTokenEfficiencyEmpty(t *testing.T) {
	b := NewBPEAnalyzer()
	eff := b.TokenEfficiency("")
	if eff != 0 {
		t.Errorf("TokenEfficiency('') = %f, expected 0", eff)
	}
}

func TestTokenEfficiencyComparison(t *testing.T) {
	b := NewBPEAnalyzer()

	normalEff := b.TokenEfficiency("the function returns a value")
	secretEff := b.TokenEfficiency("xK3zQ9wJ7mB5vN2yT8pL4")

	if secretEff >= normalEff {
		t.Errorf("Secret efficiency (%.2f) should be less than normal text efficiency (%.2f)",
			secretEff, normalEff)
	}
}

// --- ExtractLowEfficiencyWords ---

func TestExtractLowEfficiencyWordsNoSecrets(t *testing.T) {
	b := NewBPEAnalyzer()
	matches := b.ExtractLowEfficiencyWords("name = hello world", 8)
	// "hello" and "world" are too short; "name" is all letters
	if len(matches) > 0 {
		t.Errorf("Expected no matches for normal text, got %d", len(matches))
	}
}

func TestExtractLowEfficiencyWordsWithSecret(t *testing.T) {
	b := NewBPEAnalyzer()
	matches := b.ExtractLowEfficiencyWords(`api_key = "kJ9mN2pR5tW8xY1zA3bC6dE7fG8hI9j"`, 8)
	if len(matches) == 0 {
		t.Error("Expected to find at least one low-efficiency word")
	}
}

func TestExtractLowEfficiencyWordsSorted(t *testing.T) {
	b := NewBPEAnalyzer()
	text := `KEY1=aB3cD4eF5gH6iJ7kL8m KEY2=xY1zA3bC6dE7fG8hI9jK0`
	matches := b.ExtractLowEfficiencyWords(text, 8)
	for i := 1; i < len(matches); i++ {
		if matches[i].Efficiency < matches[i-1].Efficiency {
			t.Error("Results should be sorted by efficiency (ascending)")
		}
	}
}

func TestExtractSkipsIdentifiers(t *testing.T) {
	b := NewBPEAnalyzer()
	// All-letter words should be skipped as identifiers
	matches := b.ExtractLowEfficiencyWords("functionReturnValue = somethingElseEntirely", 8)
	if len(matches) > 0 {
		t.Errorf("Expected no matches for identifiers, got %d: %v", len(matches), matches)
	}
}

// --- DualAnalysis ---

func TestDualAnalysisNormalText(t *testing.T) {
	normal := DualAnalysis("the function returns the value")
	secret := DualAnalysis("kJ9mN2pR5tW8xY1zA3bC6dE7fG8hI9j")
	if normal.CombinedScore() >= secret.CombinedScore() {
		t.Errorf("Normal combined score (%f) should be less than secret combined score (%f)",
			normal.CombinedScore(), secret.CombinedScore())
	}
	t.Logf("Normal: entropy=%.2f, bpe_eff=%.2f, entropy_score=%.2f, bpe_score=%.2f, combined=%.2f",
		normal.ShannonEntropy, normal.BPEEfficiency, normal.EntropyScore, normal.BPEScore, normal.CombinedScore())
}

func TestDualAnalysisSecret(t *testing.T) {
	result := DualAnalysis("kJ9mN2pR5tW8xY1zA3bC6dE7fG8hI9j")
	if !result.IsLikelySecret() {
		t.Error("Random string should be classified as a secret")
	}
	t.Logf("Secret: entropy=%.2f, bpe_eff=%.2f, entropy_score=%.2f, bpe_score=%.2f, combined=%.2f",
		result.ShannonEntropy, result.BPEEfficiency, result.EntropyScore, result.BPEScore, result.CombinedScore())
}

func TestDualAnalysisBothAgree(t *testing.T) {
	// For a very random string, both methods should agree
	result := DualAnalysis("xK3zQ9wJ7mB5vN2yT8pL4fR6gH0jD1s")
	t.Logf("BothAgree=%v, entropy_score=%.2f, bpe_score=%.2f",
		result.BothAgree, result.EntropyScore, result.BPEScore)
}

func TestCombinedScoreRange(t *testing.T) {
	tests := []string{
		"hello world testing",
		"kJ9mN2pR5tW8xY1zA3bC",
		"AKIAIOSFODNN7EXAMPLE",
		"sk_live_1234567890ABCDEFGHIJKLMNOPQRSTUVWXyz",
	}
	for _, s := range tests {
		result := DualAnalysis(s)
		score := result.CombinedScore()
		if score < 0.0 || score > 1.0 {
			t.Errorf("CombinedScore(%q) = %f, out of [0, 1]", s, score)
		}
	}
}

// --- Package-level convenience functions ---

func TestBPETokenEfficiencyFunc(t *testing.T) {
	eff := BPETokenEfficiency("the function returns")
	if eff == 0 {
		t.Error("BPETokenEfficiency should not be 0 for non-empty string")
	}
}

func TestIsBPESecretFunc(t *testing.T) {
	if IsBPESecret("hello") {
		t.Error("'hello' (too short) should not be flagged as secret")
	}
}

func TestBPEConfidenceScoreFunc(t *testing.T) {
	score := BPEConfidenceScore("kJ9mN2pR5tW8xY1zA3bC6dE7fG8hI9j")
	if score < 0.0 || score > 1.0 {
		t.Errorf("BPEConfidenceScore out of range: %f", score)
	}
}

func TestCombinedSecretScoreFunc(t *testing.T) {
	score := CombinedSecretScore("kJ9mN2pR5tW8xY1zA3bC6dE7fG8hI9j")
	if score < 0.3 {
		t.Errorf("CombinedSecretScore for random string = %f, expected >= 0.3", score)
	}
}

// --- FormatBPEAnalysis ---

func TestFormatBPEAnalysis(t *testing.T) {
	output := FormatBPEAnalysis("xK3zQ9wJ7mB5vN2yT8pL4")
	if !strings.Contains(output, "BPE Analysis") {
		t.Error("Output should contain 'BPE Analysis'")
	}
	if !strings.Contains(output, "Efficiency") {
		t.Error("Output should contain 'Efficiency'")
	}
	t.Logf("\n%s", output)
}

// --- Edge Cases ---

func TestBPEUnicodeString(t *testing.T) {
	b := NewBPEAnalyzer()
	// Unicode characters — each is a unique token, low efficiency
	r := b.Analyze("日本語テスト文字列テスト")
	if r.TokenCount == 0 {
		t.Error("TokenCount should not be 0 for non-empty string")
	}
	t.Logf("Unicode: efficiency=%.2f, tokens=%d, chars=%d", r.Efficiency, r.TokenCount, r.CharCount)
}

func TestBPERepeatedChar(t *testing.T) {
	b := NewBPEAnalyzer()
	r := b.Analyze("aaaaaaaaaaaaaaaa")
	// All 'a's — no bigram merges possible (aa is not in merge table),
	// so efficiency = 1.0 (one token per char)
	t.Logf("Repeated 'a': efficiency=%.2f, tokens=%d", r.Efficiency, r.TokenCount)
}

func TestBPEAllCommonPairs(t *testing.T) {
	b := NewBPEAnalyzer()
	// String made entirely of common pairs
	r := b.Analyze("theretheretheretherethere")
	if r.Efficiency < 1.5 {
		t.Errorf("Common pairs should compress well, got efficiency=%.2f", r.Efficiency)
	}
	t.Logf("Common pairs: efficiency=%.2f, tokens=%d, chars=%d", r.Efficiency, r.TokenCount, r.CharCount)
}

// --- BPEResult fields ---

func TestBPEResultFields(t *testing.T) {
	b := NewBPEAnalyzer()
	r := b.Analyze("testing12345678")
	if r.CharCount != 15 {
		t.Errorf("CharCount = %d, expected 15", r.CharCount)
	}
	if r.TokenCount == 0 {
		t.Error("TokenCount should not be 0")
	}
	if r.TokenCount > r.CharCount {
		t.Error("TokenCount should not exceed CharCount")
	}
	if len(r.Tokens) != r.TokenCount {
		t.Errorf("len(Tokens)=%d != TokenCount=%d", len(r.Tokens), r.TokenCount)
	}
}

// --- BPEMatch fields ---

func TestBPEMatchFields(t *testing.T) {
	b := NewBPEAnalyzer()
	matches := b.ExtractLowEfficiencyWords(`secret=kJ9mN2pR5tW8xY1zA3bC6dE7fG8hI9j`, 8)
	for _, m := range matches {
		if m.Value == "" {
			t.Error("Match Value should not be empty")
		}
		if m.TokenCount == 0 {
			t.Error("Match TokenCount should not be 0")
		}
		if m.Score < 0 || m.Score > 1 {
			t.Errorf("Match Score %f out of [0,1] range", m.Score)
		}
	}
}

// --- Thresholds ---

func TestBPEThresholdConstants(t *testing.T) {
	if BPESecretThreshold <= 0 {
		t.Error("BPESecretThreshold should be positive")
	}
	if BPEHighConfidenceThreshold >= BPESecretThreshold {
		t.Error("HighConfidenceThreshold should be less than SecretThreshold")
	}
	if BPENormalThreshold <= BPESecretThreshold {
		t.Error("NormalThreshold should be greater than SecretThreshold")
	}
}

// --- Helper Functions ---

func TestIsAllLettersOrUnderscores(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"hello", true},
		{"hello_world", true},
		{"helloWorld", true},
		{"hello123", false},
		{"hello world", false},
		{"hello-world", false},
	}
	for _, tt := range tests {
		got := isAllLettersOrUnderscores(tt.input)
		if got != tt.expected {
			t.Errorf("isAllLettersOrUnderscores(%q) = %v, expected %v", tt.input, got, tt.expected)
		}
	}
}

func TestItoa(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{42, "42"},
		{-7, "-7"},
		{100, "100"},
	}
	for _, tt := range tests {
		got := itoa(tt.input)
		if got != tt.expected {
			t.Errorf("itoa(%d) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

// --- Benchmark ---

func TestBPEAccuracyBenchmark(t *testing.T) {
	b := NewBPEAnalyzer()

	type tc struct {
		label  string
		input  string
		expect string // "secret" or "safe"
	}

	cases := []tc{
		// Real secrets
		{"AWS access key", "AKIAIOSFODNN7EXAMPLE", "secret"},
		{"AWS secret key", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "secret"},
		{"GitHub PAT classic", "ghp_ABcDeFgHiJkLmNoPqRsTuVwXyZ012345", "secret"},
		{"Stripe secret key", "sk_live_51HG4k2L3pBcQdR7J8sT9uV0wX1yZ2aB3cD4eF5gH6iJ7kL8m", "secret"},
		{"Generic API key", "kJ9mN2pR5tW8xY1zA3bC6dE7fG8hI9j", "secret"},
		{"Base64 JWT", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "secret"},
		{"Hex token 32", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6", "secret"},
		{"RSA private frag", "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSk", "secret"},
		{"Vault token", "hvs.CAESIJ2Nz3mY8kL9pQ1rS4tU7vX0yA2bD5eG8hI", "secret"},
		{"NPM token", "npm_1234567890abcdefABCDEF1234567890abcdef", "secret"},
		{"Mixed case random", "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u", "secret"},

		// Normal text
		{"English sentence", "the function returns the value correctly", "safe"},
		{"Code variable", "getUserNameFromDatabase", "safe"},
		{"URL path", "https://api.example.com/v1/users", "safe"},
		{"Config line", "database_connection_string", "safe"},
		{"Error message", "connection refused by server", "safe"},
		{"Import statement", "import React from react", "safe"},
		{"Package name", "com.example.application", "safe"},
		{"Log message", "starting application server on port", "safe"},
		{"Comment text", "This handles authentication and authorization", "safe"},
		{"Class name", "AbstractFactoryProvider", "safe"},
		{"Method chain", "collection.stream.filter.map", "safe"},
		{"Version string", "release-2024.03.15-beta", "safe"},
	}

	correct := 0
	total := len(cases)

	for _, c := range cases {
		r := b.Analyze(c.input)
		score := b.BPEScore(c.input)

		predicted := "safe"
		if score >= 0.5 {
			predicted = "secret"
		}

		pass := predicted == c.expect
		if pass {
			correct++
		}

		status := "PASS"
		if !pass {
			status = "FAIL"
		}
		t.Logf("%-22s eff=%.2f score=%.2f pred=%-6s expect=%-6s %s", c.label, r.Efficiency, score, predicted, c.expect, status)
		if !pass {
			t.Errorf("  MISMATCH: %s — predicted %s, expected %s", c.label, predicted, c.expect)
		}
	}

	accuracy := float64(correct) / float64(total) * 100
	t.Logf("\nAccuracy: %d/%d (%.1f%%)\n", correct, total, accuracy)

	if accuracy < 90.0 {
		t.Errorf("BPE accuracy too low: %.1f%% (want >= 90%%)", accuracy)
	}
}

func BenchmarkBPETokenize(b *testing.B) {
	analyzer := NewBPEAnalyzer()
	secret := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Tokenize(secret)
	}
}

func BenchmarkBPEAnalyze(b *testing.B) {
	analyzer := NewBPEAnalyzer()
	secret := "kJ9mN2pR5tW8xY1zA3bC6dE7fG8hI9j"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.Analyze(secret)
	}
}

func BenchmarkBPEScore(b *testing.B) {
	analyzer := NewBPEAnalyzer()
	secret := "kJ9mN2pR5tW8xY1zA3bC6dE7fG8hI9j"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzer.BPEScore(secret)
	}
}

func BenchmarkDualAnalysis(b *testing.B) {
	secret := "kJ9mN2pR5tW8xY1zA3bC6dE7fG8hI9j"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DualAnalysis(secret)
	}
}

func BenchmarkCombinedSecretScore(b *testing.B) {
	secret := "kJ9mN2pR5tW8xY1zA3bC6dE7fG8hI9j"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		CombinedSecretScore(secret)
	}
}

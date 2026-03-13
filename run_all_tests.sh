#!/bin/bash
# CredVigil - Interactive Test Suite
# Run: bash run_all_tests.sh

cd "$(dirname "$0")"
BIN=./credvigil

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║             CredVigil Interactive Test Suite                  ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# ── Test 1: Version ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 1: Version Check"
echo "WHAT IT DOES: Shows which version/component you're running."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
$BIN version
echo ""

# ── Test 2: List Rules ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 2: List All Detection Categories"
echo "WHAT IT DOES: Shows all 183 rules organized by category."
echo "              Each rule is a regex pattern that matches a specific"
echo "              credential format (e.g., AWS keys start with AKIA)."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
$BIN rules 2>&1 | head -45
echo ""

# ── Test 3: Full Scan ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 3: Full Scan of fake_secrets.env"
echo "WHAT IT DOES: Scans a file full of fake credentials."
echo "              Shows each finding with: severity, rule matched,"
echo "              file:line, masked match, entropy score, confidence,"
echo "              and a SHA-256 fingerprint (zero-trust: no raw values)."
echo "COMMAND: $BIN scan testdata/fake_secrets.env --no-context"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
$BIN scan testdata/fake_secrets.env --no-context 2>&1 | head -50
echo "  ... (showing first 50 lines) ..."
$BIN scan testdata/fake_secrets.env --no-context 2>&1 | tail -8
echo ""

# ── Test 4: Severity Filter ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 4: Filter by Severity (CRITICAL only)"
echo "WHAT IT DOES: Only shows critical findings (most dangerous)."
echo "              Useful in CI/CD to block on critical issues only."
echo "COMMAND: $BIN scan testdata/fake_secrets.env --no-context --min-severity critical"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
$BIN scan testdata/fake_secrets.env --no-context --min-severity critical 2>&1 | tail -8
echo ""

# ── Test 5: Confidence Filter ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 5: Filter by Confidence (>= 70%)"
echo "WHAT IT DOES: Only shows findings where the engine is 70%+ sure"
echo "              it's a real credential. Reduces false positives."
echo "COMMAND: $BIN scan testdata/fake_secrets.env --no-context --min-confidence 0.7"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
$BIN scan testdata/fake_secrets.env --no-context --min-confidence 0.7 2>&1 | tail -8
echo ""

# ── Test 6: JSON Output ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 6: JSON Output Mode"
echo "WHAT IT DOES: Outputs results as machine-readable JSON."
echo "              Perfect for piping to other tools, dashboards, or APIs."
echo "              Notice: raw_match is always empty (zero-trust security)."
echo "COMMAND: $BIN scan testdata/fake_secrets.env --format json | python3 ..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
$BIN scan testdata/fake_secrets.env --no-context --format json 2>/dev/null | python3 -c "
import json, sys
data = json.load(sys.stdin)
f = data.get('Findings', data.get('findings', []))
print(f'  Valid JSON: YES')
print(f'  Total findings in JSON: {len(f)}')
if f:
    first = f[0]
    print(f'  First finding rule: {first.get(\"rule_id\", \"?\")}')
    print(f'  raw_match is empty (zero-trust): {first.get(\"raw_match\", \"\") == \"\"}')
"
echo ""

# ── Test 7: Stdin Piping ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 7: Pipe Input via Stdin"
echo "WHAT IT DOES: Instead of scanning a file, you pipe text directly."
echo "              Great for scanning clipboard, git diffs, or CI output."
echo "COMMAND: echo 'DB_PASSWORD=SuperSecret123' | $BIN scan --stdin --no-context"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo 'DB_PASSWORD=SuperSecret123' | $BIN scan --stdin --no-context 2>&1
echo ""

# ── Test 8: New Rule — SonarQube Token ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 8: Detect SonarQube Token (NEW RULE!)"
echo "WHAT IT DOES: SonarQube tokens start with squ_ or sqp_ followed"
echo "              by 40 hex chars. The engine recognizes this pattern."
echo "COMMAND: echo 'SONAR_TOKEN=squ_...' | $BIN scan --stdin --no-context"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo 'SONAR_TOKEN=squ_abcdef0123456789abcdef0123456789abcdef01' | $BIN scan --stdin --no-context 2>&1
echo ""

# ── Test 9: New Rule — Kerberos Keytab ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 9: Detect Kerberos Keytab Path (NEW RULE!)"
echo "WHAT IT DOES: Kerberos keytab files (.keytab) contain encryption"
echo "              keys. Exposing their path is a critical security risk."
echo "COMMAND: echo 'KRB5_KTNAME=/etc/krb5/service.keytab' | $BIN scan --stdin --no-context"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo 'KRB5_KTNAME=/etc/krb5/service.keytab' | $BIN scan --stdin --no-context 2>&1
echo ""

# ── Test 10: New Rule — LDAP URI with Credentials ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 10: Detect LDAP Connection URI with Password (NEW RULE!)"
echo "WHAT IT DOES: LDAP/LDAPS URIs can embed bind passwords."
echo "              Common in enterprise config files and .env files."
echo "COMMAND: echo 'ldaps://admin:secretPass@ldap.example.com:636' | $BIN scan --stdin --no-context"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo 'ldaps://admin:secretPass@ldap.example.com:636' | $BIN scan --stdin --no-context 2>&1
echo ""

# ── Test 11: New Rule — JFrog Artifactory API Key ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 11: Detect JFrog Artifactory API Key (NEW RULE!)"
echo "WHAT IT DOES: Artifactory API keys start with 'AKC'."
echo "              Used for artifact management in enterprise CI/CD."
echo "COMMAND: echo 'AKCabcdefghij1234567890ABCDEFGHIJklmnopq' | $BIN scan --stdin --no-context"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo 'AKCabcdefghij1234567890ABCDEFGHIJklmnopq' | $BIN scan --stdin --no-context 2>&1
echo ""

# ── Test 12: Clean File (No Secrets) ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 12: Clean Input (No Secrets)"
echo "WHAT IT DOES: Verifies the engine returns clean results when"
echo "              there are no secrets. Exit code = 0 means clean."
echo "COMMAND: echo 'PORT=3000' | $BIN scan --stdin --no-context"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e 'APP_NAME=my-app\nDEBUG=true\nPORT=3000\nLOG_LEVEL=info' | $BIN scan --stdin --no-context 2>&1
EXIT_CODE=$?
echo "  Exit code: $EXIT_CODE (0 = clean, 1 = secrets found)"
echo ""

# ── Test 13: Regex-Only Mode ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 13: Regex-Only Mode (Entropy Disabled)"
echo "WHAT IT DOES: Disables Shannon entropy detection. Only pattern"
echo "              matching is used. Fewer findings but faster."
echo "COMMAND: $BIN scan testdata/fake_secrets.env --no-context --no-entropy"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
$BIN scan testdata/fake_secrets.env --no-context --no-entropy 2>&1 | tail -8
echo ""

# ── Test 14: Unit Tests ──
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "TEST 14: Go Unit Tests"
echo "WHAT IT DOES: Runs the full automated test suite."
echo "              Tests: rule loading, pattern matching, engine behavior,"
echo "              entropy calculation, scanner, and config."
echo "COMMAND: go test ./..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
go test ./... 2>&1
echo ""

# ── Summary ──
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                  ALL 14 TESTS COMPLETE                       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "What you just saw:"
echo "  1.  Version check      - What's running"
echo "  2.  List rules         - 183 regex patterns across 30+ categories"
echo "  3.  Full scan          - Find all secrets in a file"
echo "  4.  Severity filter    - Show only CRITICAL findings"
echo "  5.  Confidence filter  - Show only high-confidence (70%+) findings"
echo "  6.  JSON output        - Machine-readable results for automation"
echo "  7.  Stdin piping       - Pipe text directly (no file needed)"
echo "  8.  SonarQube detect   - NEW: Detects squ_/sqp_ tokens"
echo "  9.  Kerberos detect    - NEW: Detects keytab file references"
echo "  10. LDAP detect        - NEW: Detects ldaps:// URIs with passwords"
echo "  11. Artifactory detect - NEW: Detects AKC* API keys"
echo "  12. Clean input        - Confirms zero findings on clean data"
echo "  13. Regex-only mode    - Scans without entropy detection"
echo "  14. Unit tests         - Automated test suite (all packages)"
echo ""

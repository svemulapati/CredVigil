# Contributing to CredVigil

Thanks for your interest in improving CredVigil! This guide covers how to build,
test, and contribute.

## Prerequisites

- Go 1.25+ (1.26 recommended)
- `git` (required for git-history scanning tests)
- Optional: `golangci-lint`, `goreleaser`, Docker

## Getting started

```bash
git clone https://github.com/svemulapati/CredVigil.git
cd CredVigil
make build      # builds ./credvigil
make test       # runs the suite
make lint       # runs golangci-lint (if installed)
```

Run `make help` to see all targets.

## Project layout

| Path | Purpose |
|------|---------|
| `cmd/credvigil` | CLI entrypoint and output formatting |
| `pkg/detector` | Core detection engine (regex + entropy + BPE) |
| `pkg/rules` | The 369 built-in detection rules |
| `pkg/entropy` | Shannon entropy + BPE token-efficiency scoring |
| `pkg/pipeline` | Zero-trust post-processing (hash, redact, fingerprint) |
| `pkg/git` | Git history scanning |
| `pkg/watcher` | Real-time filesystem watcher |
| `pkg/report` | SARIF and other machine-readable output |
| `pkg/baseline` | `.credvigilignore` suppression |
| `internal/config` | Config file loading |
| `internal/storage` | PostgreSQL persistence |

## Adding a detection rule

1. Add the `SecretType` constant in `pkg/models/finding.go`.
2. Register the rule (pattern, severity, keywords) in `pkg/rules/rules.go`.
3. Add a positive and a negative test case in `pkg/rules/rules_test.go`.
4. Run `make test`. Update the coverage matrix in `README.md`.

Rules should be **specific** — prefer a documented key prefix (e.g. `ghp_`,
`sk_live_`) over a broad pattern that generates false positives. When the format
is generic, lean on entropy/BPE rather than a loose regex.

## Suppressing findings (baseline)

Contributors testing against real repos can baseline accepted findings in a
`.credvigilignore` file at the scan root. Each line is either:

- a **fingerprint** (the stable hash printed in scan output), or
- a **path glob** such as `*.env` or `testdata/`.

Lines starting with `#` are comments.

For a single accepted secret, add an inline `# credvigil:allow` comment on the
same line instead — that line is skipped without touching the baseline file.

## Commit & PR conventions

- Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`,
  `fix:`, `docs:`, `test:`, `chore:`, `refactor:`.
- Keep PRs focused. Include tests for behavior changes.
- Ensure `make ci` passes locally before opening a PR.
- Sign off that your contribution is your own work under the project license.

## Reporting security issues

Please do **not** open public issues for vulnerabilities. See
[SECURITY.md](SECURITY.md) for responsible disclosure.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you agree to uphold it.

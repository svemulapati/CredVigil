# Changelog

All notable changes to CredVigil are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-07-07

### Added
- **SARIF 2.1.0 output** (`--format sarif`) for GitHub Code Scanning, GitLab,
  and IDE security extensions. Findings now surface inline on pull requests.
- **Baseline suppression** via a `.credvigilignore` file — silence accepted or
  pre-existing findings by fingerprint or path glob. Disable with `--no-ignore`.
- **Inline allow directives** — a `# credvigil:allow` (or `:ignore`) comment on a
  line skips any secret detected on it, across all three detection methods.
- **Config file support** — auto-discovered `.credvigil.yml` / `.credvigil.yaml`
  / `.credvigil.json`, or an explicit `--config <path>`. CLI flags override it.
- **Composite GitHub Action** (`action.yml`) — `uses: svemulapati/CredVigil@v1`.
- **Docker image** and multi-stage `Dockerfile`.
- **GoReleaser** config for cross-platform binaries, GHCR image, and a Homebrew
  tap; release workflow triggered on `v*` tags.
- **CI workflow** (test + race + coverage, lint, build smoke test, self-scan).
- `Makefile`, `.golangci.yml`, `.pre-commit-hooks.yaml`, `codecov.yml`, and
  governance docs (`CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue/PR templates).

### Changed
- `main.version` is now injectable at build time via `-ldflags`.
- Removed the committed build artifact from version control; added `.gitignore`.

## [0.1.0] - 2026-03-12

### Added
- Core detection engine: 369 regex rules + Shannon entropy + BPE token-efficiency
  scoring, with confidence scores and SHA-256 fingerprints.
- File, directory, and stdin scanning; git-history scanning.
- Real-time filesystem watcher and event bus.
- PostgreSQL persistence (`--store`).
- `text` and `json` output formats.

[Unreleased]: https://github.com/svemulapati/CredVigil/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/svemulapati/CredVigil/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/svemulapati/CredVigil/releases/tag/v0.1.0

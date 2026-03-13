# Security Policy

## Important Disclaimer

CredVigil is a **credential detection aid** designed to help security teams identify potential secret exposure. It is provided on an "AS IS" basis under the Apache License 2.0.

**CredVigil does not guarantee:**
- Detection of all credentials or secrets in your codebase
- Zero false positives or false negatives
- Protection against data breaches or unauthorized access
- Compliance with any specific security standard or regulation

Users are solely responsible for their own security posture. CredVigil is a tool that **assists** your security workflow — it does not replace a comprehensive security program.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of CredVigil seriously. If you discover a security vulnerability in CredVigil itself, please report it responsibly.

### How to Report

1. **Do NOT** open a public GitHub issue for security vulnerabilities
2. Email your report to **security@credvigil.com**
3. Include the following in your report:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours of your report
- **Assessment**: We will evaluate the severity within 5 business days
- **Resolution**: Critical vulnerabilities will be patched within 14 days
- **Disclosure**: We will coordinate public disclosure with you after a fix is available

### Scope

The following are **in scope** for security reports:

- Vulnerabilities in the CredVigil codebase
- Bugs that could cause CredVigil to leak or expose the secrets it detects
- Authentication/authorization bypasses in the API or dashboard (future components)
- Dependency vulnerabilities that affect CredVigil

The following are **out of scope**:

- False positives or missed detections (these are bugs, not security issues — file a regular issue)
- Vulnerabilities in third-party dependencies that don't affect CredVigil
- Social engineering attacks

## Security Design Principles

CredVigil is built with a **zero-trust architecture**:

1. **No secret storage**: Raw secret values are never stored. Only SHA-256 hashes and redacted previews are retained.
2. **Redaction by default**: All findings redact the middle portion of detected values, showing only the first and last 4 characters.
3. **Local-first**: The CLI runs entirely on your machine with no network calls, no telemetry, and no data exfiltration.
4. **Minimal permissions**: CredVigil requires only read access to the files/directories being scanned.

## Limitation of Liability

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL THE AUTHORS, COPYRIGHT HOLDERS, OR CONTRIBUTORS OF CREDVIGIL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; BUSINESS INTERRUPTION; OR SECURITY BREACHES) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Users acknowledge that no automated credential detection tool can guarantee 100% accuracy or coverage. CredVigil is provided as a **best-effort detection aid** and should be used as part of a broader security strategy that includes manual code review, access controls, secret rotation policies, and security training.

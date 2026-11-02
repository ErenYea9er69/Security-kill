# Preflight: Canary Verification and Docker Fallback

Team owner: the Orchestrator.

Read this in Phase 1. A tool on the PATH is not a working tool. A Semgrep install has failed on every current rule and still passed a `command -v` check. Test each tool against a known-bad canary before you report the inventory. When a host install is broken, use the official Docker image.

## Inventory loop

```bash
for t in semgrep gitleaks trufflehog trivy osv-scanner grype syft checkov hadolint zizmor nuclei bandit gosec govulncheck docker; do
  command -v $t >/dev/null 2>&1 && echo "OK?  $t" || echo "MISS $t"
done
```

```powershell
'semgrep','gitleaks','trufflehog','trivy','osv-scanner','grype','syft','checkov',
'hadolint','zizmor','nuclei','bandit','gosec','govulncheck','docker' |
  ForEach-Object { if (Get-Command $_ -ErrorAction SilentlyContinue) { "OK?  $_" } else { "MISS $_" } }
```

Use the PowerShell form on Windows. Under Git Bash, `command -v` finds `.exe` files but misses `.cmd` and `.bat` shims, so npm-installed tools look missing. Confirm with `<tool> --version`. A tool installed with pip lands in a `Scripts\` folder often absent from PATH. Try `python -m <tool> --version` before you reinstall.

Then check each tool version against its vendor's security advisories. Two scanners were compromised in 2026 (see `iac-cloud-config.md`).

## The canary set

Write these files to `$TMP/security-kill/canary/` (PowerShell: `$env:TEMP\security-audit\canary\`). Everything in them is fabricated. Never put a real credential in a canary. The directory is deleted with the other artifacts at the end of Phase 9.

`canary.py` holds SAST sinks and secret formats:

```python
import subprocess
aws_key = "AKIAQYLPMN5G3XVRWTZK"                  # fake, format-valid AWS key ID
github_token = "ghp_<36 random [0-9A-Za-z]>"      # assemble a fresh fake token, see below
subprocess.call("ls " + input(), shell=True)      # shell injection
```

Replace the token placeholder with 36 random alphanumeric characters generated at write time, as one literal string. Scanners match the source text, so a string concatenation does not fire. No literal example appears here because a format-valid token in a committed file trips GitHub push protection, and this property is what makes it a working canary. Do not soften either value into `AKIA…EXAMPLE` or `ghp_000…`. Scanners allowlist documentation keys and filter repeated characters, so a polite canary tests nothing.

`requirements.txt` holds one pinned, vulnerable release:

```
requests==2.19.1
```

CVE-2018-18074, fixed in 2.20.0. Any working dependency scanner reports at least one advisory against it.

`go/go.mod` and `go/main.go`, only when Phase 0 found Go:

```go
// go/main.go
package main

import (
	"os"
	"os/exec"
)

func main() { exec.Command(os.Args[1]).Run() } // G204, and G104 for the dropped error
```

```
// go/go.mod
module canary

go 1.22
```

## Per-tool canary runs

`$CANARY` is the canary directory. Canary only the tools this audit will run, with the config the real scan will use. Parse the JSON and count findings yourself. Exit codes mislead (see `sast-secrets.md`). Anything other than the expected signal is BROKEN: an error, empty output, or exit 0 with zero findings. Record the exact error.

| Tool | Canary command | Expected signal |
|---|---|---|
| semgrep | `semgrep scan --config p/security-audit --json $CANARY` | at least 1 result (subprocess or shell) |
| bandit | `bandit -r $CANARY -f json` | at least 1 issue (B602 or B604) |
| gitleaks | `gitleaks dir -v $CANARY` | at least 2 leaks (AWS key, GitHub token) |
| trufflehog | `trufflehog filesystem $CANARY --no-verification --json` | at least 1 result (GitHub detector) |
| trivy secrets | `trivy fs --scanners secret $CANARY` | GitHub token flagged |
| trivy vuln | `trivy fs --scanners vuln $CANARY` | at least 1 CVE on requests 2.19.1 |
| osv-scanner | `osv-scanner scan source -L $CANARY/requirements.txt` | at least 1 advisory, exit 1 |
| gosec | `gosec ./...` from inside `$CANARY/go/` | at least 1 issue (G204) |

Two deliberate deviations:

- TruffleHog is the one canary run without the real scan's config. Its verifier rejects fake credentials, and `--results=verified,unknown` then filters them out, so a healthy install reports zero. Use `--no-verification` to test the pattern engine. Its AWS detector needs a paired secret key, so only the GitHub token fires.
- Trivy's detection of a bare AWS key ID depends on the version. Gate the Trivy canary on the GitHub token alone. Never rely on Trivy for secret coverage. Gitleaks is the gate.

Not canaried:

- govulncheck needs a module whose code calls a vulnerable symbol, which is too heavy for preflight. Report it as `present, verified at first use`. It fails loudly on package-load errors, so its exit codes are trustworthy.
- Phase 5 and 7 tools (checkov, hadolint, zizmor, nuclei, ZAP) have their silent-failure checks in their own references.

## Run through Docker: first choice for a BROKEN or MISS tool

Host installs rot. The official image avoids the toolchain. Ask before the first pull. Rerun the canary through the container, since an image might be broken too.

| Tool | One-liner |
|---|---|
| semgrep | `docker run --rm -v "$PWD:/src" semgrep/semgrep semgrep scan --config p/security-audit /src` |
| gitleaks | `docker run --rm -v "$PWD:/repo" ghcr.io/gitleaks/gitleaks:latest git /repo` |
| trufflehog | `docker run --rm -v "$PWD:/repo" trufflesecurity/trufflehog:latest git file:///repo --results=verified,unknown` |
| bandit | `docker run --rm -v "$PWD:/src" ghcr.io/pycqa/bandit/bandit -r /src` |
| trivy | `docker run --rm -v "$PWD:/repo" ghcr.io/aquasecurity/trivy:<pinned tag> fs --scanners vuln /repo` |
| osv-scanner | `docker run --rm -v "$PWD:/src" ghcr.io/google/osv-scanner:latest scan source -r /src` |
| gosec | `docker run --rm -v "$PWD:/app" -w /app securego/gosec ./...` |

Image names and tags change. Check each project's current install page before you run one.

Pin an explicit digest or tag, never `latest`, for any scanner image where you are able to. For Trivy, pull from GHCR, pin a tag from the current advisory's known-safe list, and check `--version` after the pull. Malicious Trivy images went out on Docker Hub in March 2026 (CVE-2026-33634).

Mount caveats: history scans (`gitleaks git`, `trufflehog git`) need `.git` inside the mount. Mount the repo root. On Windows pass an absolute path (`-v "C:\repo:/repo"`), because `$PWD` under Git Bash mangles the drive prefix.

Host install one-liners are in `sast-secrets.md`.

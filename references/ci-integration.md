# Wiring Scanning Into CI and Pre-Commit

Read this when the user wants scanning to run on its own. The rule for an existing project: freeze the past, block the future. Never start by failing the build on hundreds of old findings. The team switches the whole thing off within a week.

Release tags, versions and action names change. This edition lists none as current. Resolve each one in the session, as shown below, and write a full commit SHA into every `uses:` line.

## Contents
- [Resolve versions and SHAs first](#resolve-versions-and-shas-first)
- [Pre-commit hooks](#pre-commit-hooks)
- [Husky and lint-staged](#husky-and-lint-staged)
- [GitHub Actions](#github-actions)
- [SARIF: upload once per tool](#sarif-upload-once-per-tool)
- [Baseline and ratchet](#baseline-and-ratchet)
- [Keep the attack tests in CI](#keep-the-attack-tests-in-ci)
- [Rollout order](#rollout-order)

## Resolve versions and SHAs first

Scanners run with your credentials. Two of them were compromised in 2026 (see `iac-cloud-config.md`). A tag moves. A commit SHA does not.

```bash
git ls-remote --tags https://github.com/gitleaks/gitleaks | tail -5          # list real tags
git ls-remote https://github.com/actions/checkout refs/tags/<tag>^{}         # resolve a tag to a commit
```

Write the result as `uses: owner/action@<40-character SHA> # <tag>`. For an annotated tag, use the dereferenced `^{}` line. Read the project's release notes and security advisories for the version you pick. Prefer a release at least two weeks old, since a fresh release might carry malicious code before anyone notices.

## Pre-commit hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: <resolved tag or SHA>
    hooks:
      - id: gitleaks
  - repo: https://github.com/semgrep/pre-commit
    rev: <resolved tag or SHA>
    hooks:
      - id: semgrep
        args: [--config=p/default, --config=p/secrets, --error, --skip-unknown-extensions]
```

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files        # sets the baseline, see below
```

The gitleaks hook runs `gitleaks git --pre-commit --redact --staged --verbose` with `pass_filenames: false`. Variants exist: one which builds with Go, one which uses the published image (`gitleaks-docker`), and one which expects the binary on `PATH` (`gitleaks-system`). The last is fastest inside a CI image. Check the hook ids in the repository's `.pre-commit-hooks.yaml`. Run `pre-commit autoupdate` every quarter, and review the diff.

## Husky and lint-staged

For JavaScript projects which use Husky:

```sh
# .husky/pre-commit
npx lint-staged
gitleaks git --pre-commit --redact --staged --verbose || {
  echo "gitleaks: staged secret found. Remove it."; exit 1;
}
```

```json
{
  "lint-staged": {
    "*.{js,jsx,ts,tsx}": ["eslint --fix", "semgrep --config p/javascript --error --skip-unknown-extensions"]
  }
}
```

lint-staged appends file names to each command, which suits Semgrep. Keep gitleaks outside lint-staged, since it reads the git index and takes no file list.

## GitHub Actions

Start every workflow with no permissions, then grant per job:

```yaml
permissions: {}
jobs:
  semgrep:
    permissions:
      contents: read
      security-events: write     # SARIF upload
      actions: read              # omitting it gives "Resource not accessible by integration"
```

Use `pull_request`, not `pull_request_target`, for scans of code from forks. Pass event text through `env`, never straight into `run:`.

Semgrep:

```yaml
    runs-on: ubuntu-latest
    container: { image: semgrep/semgrep }      # pin by digest where you are able to
    steps:
      - uses: actions/checkout@<SHA>
        with: { fetch-depth: 0, persist-credentials: false }
      - run: semgrep scan --config=p/default --config=p/secrets --sarif --output=semgrep.sarif
      - uses: github/codeql-action/upload-sarif@<SHA>
        if: always()
        with: { sarif_file: semgrep.sarif, category: semgrep }
```

`fetch-depth: 0` is required for `--baseline-commit`, and for history scanners. A shallow clone makes them scan one commit while they appear to succeed.

Trivy. The `trivy-action` was compromised in March 2026 (CVE-2026-33634). Pin by commit SHA from the advisory's known-safe list:

```yaml
      - uses: aquasecurity/trivy-action@<SHA from the current advisory's safe list>
        with:
          scan-type: fs
          ignore-unfixed: true
          format: sarif
          output: trivy.sarif
          severity: CRITICAL,HIGH
          limit-severities-for-sarif: true     # else all severities reach code scanning
      - uses: github/codeql-action/upload-sarif@<SHA>
        if: always()                           # else findings vanish when the scan fails the job
        with: { sarif_file: trivy.sarif, category: trivy }
```

Confirm the input names against the action's README at the pinned SHA.

osv-scanner publishes reusable workflows in a separate action repository. Older copies inside the main repository are deprecated. Read the current README and pin the reusable workflow by SHA. Do not pass `--format` or `--output` in `scan-args`, since the workflow sets them.

gitleaks: the official action needs a license key for organization-owned repositories per the earlier edition. Check the action's README. Without a key, run the binary directly and verify its checksum:

```yaml
      - run: |
          curl -sSL -o gl.tgz "https://github.com/gitleaks/gitleaks/releases/download/v<VER>/gitleaks_<VER>_linux_x64.tar.gz"
          echo "<expected sha256>  gl.tgz" | sha256sum -c -
          tar -xz -C /usr/local/bin gitleaks -f gl.tgz
          gitleaks git . --redact --report-format sarif --report-path gitleaks.sarif \
                   --baseline-path .gitleaks-baseline.json --exit-code 1
```

Take the version and checksum from the release page in this session.

Install jobs, scanner jobs and publish jobs stay separate. A scanner job holds no publish token and no cloud credential. See `agent-config-and-worms.md`.

## SARIF: upload once per tool

GitHub code scanning stopped combining several runs which share a tool and category (the earlier edition dates this to July 2025, so verify in the GitHub changelog). Upload each tool's file once, with its own `category`:

```yaml
      - uses: github/codeql-action/upload-sarif@<SHA>
        with: { sarif_file: semgrep.sarif, category: semgrep }
      - uses: github/codeql-action/upload-sarif@<SHA>
        with: { sarif_file: trivy.sarif, category: trivy }
```

Run identity comes from the `category` input, then `runs[].automationDetails.id`, then the tool name. Merge SARIF only for local or human reports:

```bash
pip install sarif-tools
sarif summary merged.sarif
sarif html --output report.html merged.sarif
```

No tool merges duplicates across scanners (the same CVE from Trivy and osv-scanner). Approximate by rule id and path with `jq`.

## Baseline and ratchet

Each tool has a mechanism. Capture baselines, commit them, then gate on what is new:

```bash
gitleaks git . --report-path .gitleaks-baseline.json          # review, then commit
git rev-parse HEAD > .semgrep-baseline-commit                 # commit
gitleaks git . --baseline-path .gitleaks-baseline.json --exit-code 1
semgrep scan --config=p/default --error --baseline-commit "$(cat .semgrep-baseline-commit)"
```

The gitleaks baseline file holds the findings, including secrets, unless you pass `--redact` when you create it. Create it with `--redact`.

On pull requests, `semgrep ci` finds the merge base on its own. Both forms need full history.

A baseline is debt, not an exemption. Make it expire:

```yaml
      - run: |
          age=$(( ($(date +%s) - $(git log -1 --format=%ct .gitleaks-baseline.json)) / 86400 ))
          [ "$age" -gt 90 ] && { echo "::error::baseline older than 90 days"; exit 1; }; true
```

Regenerate a baseline only in its own pull request, so the diff gets reviewed.

## Keep the attack tests in CI

The regression tests from Phase 10 (`fix-patterns.md`) are the cheapest security control in the pack. Run them on every pull request with the normal test job. A deleted test is a security change, so give the test folder a code owner.

## Rollout order

1. Measure first. Run every workflow with `continue-on-error: true` and upload SARIF. Two weeks of data, no friction.
2. Block on secrets from day one. Volume is small, the signal is clear, the impact is high.
3. Block on critical dependency CVEs after two weeks, with `--ignore-unfixed`, so no one waits on a patch which does not exist.
4. Warn on SAST for a quarter, then block new findings only.
5. File everything old as a backlog ticket. Never make it a pull request blocker.

A middle-ground gate blocks serious new problems and leaves the backlog alone:

```yaml
        with:
          severity: CRITICAL,HIGH
          exit-code: '1'
          ignore-unfixed: true
```

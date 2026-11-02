# Dependencies and Supply Chain

Team owner: T07 Supply.

Read this in Phase 4. A CVE list is the smallest part of the risk. Since 2025, registry worms, hijacked releases and fake packages have caused most of the real damage. Read `agent-config-and-worms.md` alongside this file.

## Contents
- [Which tool for which language](#which-tool-for-which-language)
- [osv-scanner](#osv-scanner)
- [Trivy](#trivy)
- [npm and pnpm](#npm-and-pnpm)
- [pip-audit](#pip-audit)
- [govulncheck](#govulncheck)
- [Grype and Syft](#grype-and-syft)
- [Hallucinated and squatted packages](#hallucinated-and-squatted-packages)
- [Install-time code and release age](#install-time-code-and-release-age)
- [Lockfile and registry integrity](#lockfile-and-registry-integrity)
- [Licenses](#licenses)
- [Ranking findings](#ranking-findings)

## Which tool for which language

| Situation | Run |
|---|---|
| Any repo, first pass | `osv-scanner` |
| Second opinion, or containers, IaC and licenses too | `trivy` |
| Go | `govulncheck`, which proves reachability |
| Node | `npm audit` and `npm audit signatures` |
| Python | `pip-audit` |
| SBOM artifact needed | `syft`, then scan the SBOM |
| Java or .NET with fat JARs or DLLs | OWASP dependency-check, otherwise skip it |

Do not run every tool. Two overlapping scanners plus the language-native one is enough.

## osv-scanner

```bash
osv-scanner scan source -r .
osv-scanner scan source -r . --format sarif --output "$TMP/security-audit/osv.sarif"
osv-scanner scan source -L package-lock.json
```

Version 2 syntax is `scan source`. Formats include `table`, `json`, `sarif`, `markdown`, `html` and CycloneDX. Exit codes: 0 clean, 1 findings, 127 error, 128 no packages found. Code 128 means nothing was scanned, which reads as neither pass nor fail in CI. Handle it.

There is no severity gate flag. Filter the JSON yourself. Suppression lives in `osv-scanner.toml` beside the scanned file. It does not apply to subdirectories.

```toml
[[IgnoredVulns]]
id = "GO-2022-0968"
ignoreUntil = 2026-12-31
reason = "not reachable from our entry points"
```

Offline: `--offline-vulnerabilities --download-offline-databases`.

Windows C and C++ caveat: git `core.autocrlf` changes the content hashes osv-scanner matches, so it misses vulnerabilities silently. Set `* text=auto eol=lf` in `.gitattributes` before scanning, or mark the result unreliable.

## Trivy

Check the version against the CVE-2026-33634 advisory first. In March 2026 a malicious Trivy binary (v0.69.4), malicious images on Docker Hub, and force-pushed tags of `trivy-action` and `setup-trivy` stole CI credentials. The advisory names the known-safe versions. Read it in this run (see `evidence-and-truth.md`), pin by commit SHA or image digest, and never use a mutable tag.

```bash
trivy --version
trivy fs --scanners vuln .
trivy fs --scanners vuln,misconfig,secret,license .
trivy fs --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed .
trivy fs --format sarif --output "$TMP/security-audit/trivy.sarif" .
trivy image myapp:tag
```

Trivy exits 0 by default even with findings. Pass `--exit-code 1` to gate, and confirm it fails on a known-bad input. The secret scanner exits 0 whatever it finds, so never gate secrets on Trivy.

`fs` and `image` run the secret and misconfiguration scanners by default, which slows scans. `--scanners vuln` limits it to dependencies. `--ignore-unfixed` removes vulnerabilities with no patch, which are risk decisions rather than action items.

Suppression: `.trivyignore` (one id per line, with `exp:` dates), `.trivyignore.yaml` for per-path scope, or a VEX document through `--vex`. SARIF output ignores `--severity` and emits everything. The vulnerability database comes from GHCR, which rate-limits busy CI. If the project contains JARs, pass `--offline-scan`, since Trivy otherwise calls Maven Central per JAR and a rate-limit surfaces as a generic timeout.

## npm and pnpm

```bash
npm audit --omit=dev --audit-level=high
npm audit --json
npm audit signatures
pnpm audit --audit-level high --prod --json
```

`--omit=dev --audit-level=high` is the sane default. Unfiltered `npm audit` is noisy on dev-only advisories and trains people to ignore it.

Advisory severities change after publication. A gate which passed at merge time starts failing on an untouched branch when an advisory is re-rated. A green gate today is not durable evidence. Run the check fresh during an audit.

`npm audit signatures` verifies registry signatures and provenance. Run it. Note what it does and does not show. A valid provenance attestation proves where a build ran. It does not prove the build was clean. A 2026 worm reportedly forged attestations.

npm has no native ignore list. Force patched versions through `overrides` in `package.json`. The pnpm suppression key has moved between major versions. Read `pnpm audit --help` before you write one, since a misplaced key is ignored silently.

## pip-audit

```bash
pip install pip-audit
pip-audit --no-deps -r requirements.txt
pip-audit -f json
pip-audit --ignore-vuln GHSA-xxxx-yyyy-zzzz
```

Exit 0 clean, 1 on findings. No SARIF and no severity filter. Use `--no-deps` on pinned requirements. Without it, pip-audit resolves and builds dependencies, which might run `setup.py` from source distributions. This is arbitrary code execution during a security scan.

## govulncheck

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
govulncheck -show traces ./...
govulncheck -mode binary ./app
```

It does symbol-level reachability analysis and reports only vulnerabilities your code is able to reach. When Trivy or osv-scanner flags a Go module and govulncheck does not, govulncheck is right. Report this instead of passing along a CVE nobody is able to trigger. A double-digit advisory list shrinking to two or three reachable findings means both tools work. Confirm surprising traces with `go mod why -m <module>` and `govulncheck -show traces`. Scope the run when the audit is scoped: `govulncheck ./cmd/<target>/...`.

Exit 3 on findings, 0 clean. With `-format json|sarif|openvex` it always exits 0. Parse the output.

## Grype and Syft

```bash
syft dir:. -o cyclonedx-json=sbom.cdx.json
grype sbom:./sbom.cdx.json --fail-on high
```

`--fail-on high` exits 2, not 1. Suppression lives in `.grype.yaml`. One SBOM per build, scanned afterward, is faster and reproducible, and auditors ask for it.

## Hallucinated and squatted packages

AI coding tools suggest packages which do not exist. Attackers register those names. A USENIX Security 2025 study reported about a fifth of sampled AI code samples referenced at least one nonexistent package, and many names repeated across runs. Re-read the study before you quote a figure. The mechanism is what matters: the same fake name appears for many developers, so squatting it pays.

Check each unfamiliar dependency:

```bash
npm view <package> time.created maintainers
curl -s https://api.npmjs.org/downloads/point/last-month/<package>
pip index versions <package>
```

Flag a dependency when it does not resolve upstream, was first published within days of appearing in the repo, has negligible download history, or is a near-miss of a popular name (`python-dateutil` and `dateutil`, `crypto-js` and `cryptojs`). `guarddog` automates part of this:

```bash
pip install guarddog
guarddog npm verify package-lock.json --output-format sarif
guarddog pypi verify requirements.txt
```

## Install-time code and release age

In 2026-05 and 2026-06, reported worms (Mini Shai-Hulud and a variant named Miasma) ran from `preinstall` scripts, stole cloud and registry tokens, and republished infected versions. Sources are in the ledger of `evidence-and-truth.md`. A CVE scanner sees none of it, since no CVE existed during the exposure window.

Do these checks:

1. List lifecycle scripts (`preinstall`, `install`, `postinstall`, `prepare`) in the root `package.json` and in dependencies you are able to inspect. Read any script which fetches or runs remote content.
2. Check how installs run in CI and containers. Use a frozen install: `npm ci`, `pnpm install --frozen-lockfile`, `pip install --require-hashes`.
3. Check whether dependency scripts are off by default, with an allowlist for packages which need a build step. npm has `--ignore-scripts`. pnpm has a dependency build allowlist. Confirm names and defaults in the current docs.
4. Check for a minimum release age, a delay before a new version installs. pnpm and Renovate document settings for it. Look up the current names. The delay lets the community catch a bad release before you pull it.
5. Keep publish tokens and cloud credentials out of jobs which run installs.

Tell the user a delay and script controls reduce risk and do not remove it.

## Lockfile and registry integrity

```bash
npx lockfile-lint --path package-lock.json --type npm \
  --allowed-hosts npm --validate-https --validate-integrity --validate-package-names
```

This catches lockfile injection, a dependency whose resolved URL points outside the registry. It runs offline and exits nonzero on violation.

Baseline hygiene to recommend when absent:
- Commit the lockfile. Install with a frozen command.
- Pin the registry in `.npmrc`. Use scoped names for internal packages so a public package cannot shadow them.
- Apply a release-age delay (above).
- Pin CI actions by commit SHA (see `iac-cloud-config.md`).

## Licenses

```bash
trivy fs --scanners license --license-full .
osv-scanner scan source -r . --licenses="MIT,Apache-2.0,BSD-3-Clause,ISC"
```

Relevant only when the user asks, or when a copyleft license appears in a proprietary product. Do not editorialize about licenses otherwise.

## Ranking findings

Rank by exploitability, not CVSS:

1. Reachable from untrusted input, fix available, production dependency.
2. Reachable, no fix available. Present it as a risk decision.
3. Production dependency, reachability unproven.
4. Dev-only dependency: build tooling, not runtime attack surface. It still matters for install-time attacks on developer machines and CI.
5. Unreachable, because govulncheck says so or the code path does not exist.

A headline of "247 vulnerabilities" is useless. Three exploitable ones with a fix are what the user acts on today.

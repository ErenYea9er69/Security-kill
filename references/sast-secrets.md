# SAST and Secret Scanning

Team owner: T09 Secrets (secret scanning), T04 Input (SAST).

Tool syntax for Phases 2 and 3. Flags changed recently in gitleaks and Semgrep, and many blog posts are stale. Treat every flag here as "verify with `--help`" when a run behaves oddly. Scanner flags which are wrong often fail silently.

## Contents
- [Never trust an exit code alone](#never-trust-an-exit-code-alone)
- [What Semgrep Community Edition does](#what-semgrep-community-edition-does)
- [Install](#install)
- [gitleaks](#gitleaks)
- [TruffleHog](#trufflehog)
- [Scanner accuracy](#scanner-accuracy)
- [Secret triage](#secret-triage)
- [Remediation: rotate, then scrub](#remediation-rotate-then-scrub)
- [Semgrep](#semgrep)
- [Bandit](#bandit)
- [gosec](#gosec)
- [Degraded path: no tools installed](#degraded-path-no-tools-installed)

## Never trust an exit code alone

Each scanner here has a documented mode where it scans nothing and exits 0.

- Semgrep exits 0 on some Python parse errors and reports no findings, on an invalid rule where the docs promise exit 7, on a space in `--config`, and when parallel scanning returns zero findings on high-CPU hosts with little memory.
- Bandit ignores its `exclude` config when you pass filenames on the command line, so it scans what you told it to skip.
- Checkov ignores unknown check ids passed to `--check`, skips Kustomize and Helm charts whose build emits warnings, and passes when an external module fails to load.

Parse the JSON or SARIF output and assert on the finding count yourself. Exit 0 means "nothing I noticed went wrong". It does not mean "the code is clean". A scanner with no output is a coverage gap. Say so in the report.

## What Semgrep Community Edition does

Semgrep's own README describes the Community Edition as suited to ad-hoc use with a high tolerance for false positives. It warns the engine will miss true positives because it analyzes code within a single function or file. Cross-file taint analysis is a paid feature. The engine will not follow user input from a route handler into a helper module, which is the shape of most real injection bugs. Treat its findings as leads for your own tracing. When it reports nothing, state the single-file limit in the coverage section.

The `semgrep-rules` repository carries a separate license from the engine, which matters if anyone plans to redistribute rules. Opengrep is a fork of the engine. Check current licenses before you advise on either.

## Install

Windows first, since this is where it often runs.

```powershell
winget install Gitleaks.Gitleaks      # or: scoop install gitleaks
pip install semgrep
pip install "bandit[sarif,toml]"
scoop install trufflehog              # or grab the release binary
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

macOS and Linux: `brew install gitleaks semgrep trufflehog gosec`.

A pip install on Windows often lands outside PATH. `pip show -f semgrep` prints the location, and `python -m semgrep --version` runs it anyway.

Network notes: `semgrep --config p/…` fetches rules over the network and sends metrics unless you pass `--metrics=off`. TruffleHog verification calls each credential's live API by design.

## gitleaks

The CLI changed in v8.19 to `git`, `dir` and `stdin`. The older `detect` and `protect` subcommands still work but are deprecated.

```bash
gitleaks git -v .                                   # full history, every commit
gitleaks git --redact -f json -r "$TMP/security-kill/gitleaks.json" .
gitleaks git --redact -f sarif -r "$TMP/security-kill/gitleaks.sarif" .
gitleaks git --log-opts="--all" .                   # all branches
gitleaks dir -v .                                   # working tree only, no history
gitleaks git --pre-commit --staged --redact -v      # for a pre-commit hook
```

Always pass `--redact` during an audit, and write reports to the temp directory. Unredacted JSON holds the cleartext secret.

Exit codes: 0 clean, 1 leaks found or an error, 126 unknown flag. `--exit-code N` overrides the findings code.

`dir` walks the raw filesystem and ignores `.gitignore`. On a built project most hits sit in `.next/`, `dist/` or `node_modules/` and bury the question which matters: is anything committed? Answer this with `gitleaks git`. Then point `dir` at specific build-output folders as a separate, labelled pass.

A custom `.gitleaks.toml` replaces the whole default ruleset unless it starts with:

```toml
[extend]
useDefault = true
```

Without this line, one custom rule deletes every built-in detector, and the scan comes back clean because it looks for almost nothing. Check this before you trust a quiet result on a repo with its own config.

Suppression: a `.gitleaksignore` file holds report fingerprints, or `.gitleaks.toml` holds regex, path and stopword allowlists. Fingerprints embed the commit SHA, so squash merges and history rewrites invalidate them. They also embed the OS path separator, so a file written on Windows fails on Linux CI. Prefer path and rule allowlists in the TOML.

Baseline for a repo drowning in old findings:

```bash
gitleaks git --report-path baseline.json .
gitleaks git --baseline-path baseline.json --report-path new.json .
```

## TruffleHog

Its edge is verification: it calls the credential's API to see whether the key still works.

```bash
trufflehog git file://. --results=verified,unknown --json
trufflehog git file://. --results=verified --fail          # gate: exits 183 on findings
trufflehog filesystem ./dist --results=verified
trufflehog git file://. --since-commit HEAD~50
```

The `--fail` exit code is 183. Without `--fail` it exits 0 even with findings. `--results` replaces the old `--only-verified` flag. `--no-verification` turns it into a pattern scanner for air-gapped runs. It clones local repos to a temp folder unless you pass `--trust-local-git-config`, and it exits 0 on an invalid `--since-commit` instead of failing.

Do not audit with `--results=verified` alone. A revoked historical secret still shows a credential leaked and was never rotated properly. Use `verified,unknown`.

Verification sends authentication attempts to third-party APIs with the credentials it finds. Say so before you enable it, since regulated environments might need sign-off.

## Scanner accuracy

The earlier edition of this pack quoted precision and recall figures from a public benchmark. They have not been re-verified, so this edition does not repeat them. The direction of the finding holds: gitleaks favors recall and produces many false positives, TruffleHog without verification produces mostly false positives, and verification raises precision. No single tool is enough. Use gitleaks for recall and TruffleHog verification for precision. Never paste raw scanner output into a report. Triage every hit.

Trivy's secret scanner has a narrower ruleset and changes between versions. Treat a Trivy secret hit as corroboration only. Its secret scanner exits 0 whatever it finds.

Three operational traps:
- In GitHub Actions, `fetch-depth: 0` is mandatory. The default shallow clone makes history tools scan one commit while they appear to succeed.
- Ignore-file fingerprints are not portable (see above).
- TruffleHog verification is real network egress.

## Secret triage

For each hit, in order:

1. Is the value real? `placeholder`, `your-key-here`, `xxx` and test fixtures are not findings. Check the shape against the provider's format.
2. Is it committed? A hit from a gitignored working-tree file is local hygiene. Confirm with `git log --oneline --all -- <path>`. Empty output means never committed. Committed, shipped in a bundle or otherwise published means leak.
3. Is it reachable? A key in `dist/`, `.next/` or any client bundle is public once deployed.
4. What is the blast radius? These are Critical wherever they sit:
   - `service_role` or `sb_secret_…` (Supabase): bypasses row-level security.
   - `AKIA…` (AWS access key): exposed keys get abused within hours.
   - `sk_live_…` (Stripe secret): live payment operations.
   - `sk-…` and `sk-ant-…` (LLM provider keys): billable.
   - Any private key block.
5. History only? Still live. `git rm` removes nothing from history, and every clone holds it.

Never write the full value anywhere. Report location, type and the first 4 characters.

## Remediation: rotate, then scrub

Users get this backwards. State the order. It applies to exposed secrets only (committed, bundled or published).

1. Rotate the credential at the provider. Until then it is compromised.
2. Then scrub history if wanted: `git filter-repo --path .env --invert-paths`, or BFG. Force-push. Every collaborator re-clones. Stale clones and forks keep old objects.
3. Add `.env*` to `.gitignore` and enable push protection on the host.

## Semgrep

```bash
semgrep scan --config p/security-audit --config p/owasp-top-ten --metrics=off .
semgrep scan --config p/security-audit --error --metrics=off --sarif-output="$TMP/security-kill/semgrep.sarif" .
semgrep scan --config p/security-audit --baseline-commit=main .
```

Useful packs: `p/security-audit`, `p/owasp-top-ten`, `p/cwe-top-25`, `p/secrets`, `p/jwt`, `p/sql-injection`, and language packs such as `p/javascript`, `p/typescript`, `p/python`, `p/golang`. Pack names change. Confirm a pack exists in the registry before you cite it.

Semgrep exits 0 with findings unless you pass `--error`. Other codes: 2 internal failure, 5 invalid YAML, 7 invalid rule, 13 invalid API key. Suppression: `.semgrepignore`, inline `// nosemgrep: rule-id`, or `--baseline-commit`. A known bug ignores `nosemgrep` comments when you write with `--sarif-output`. Redirect `--sarif > file` instead. Offline: download the ruleset YAML once and pass `--config ./rules.yaml`.

## Bandit

```bash
bandit -r . -f sarif -o bandit.sarif
bandit -r . -ll -ii                # medium and higher severity and confidence
bandit -r . -x ./tests,./venv
```

Exit 1 when issues meet the threshold. `--exit-zero` forces 0. Inline suppression is `# nosec B608`. `-ll -ii` is nearly always the right default, since full sensitivity flags every `assert` in a test suite.

## gosec

```bash
gosec -fmt sarif -out gosec.sarif -stdout ./...
gosec -severity medium -confidence medium ./...
gosec -exclude-dir=vendor ./...
```

Exit 0 clean, 1 on findings or a processing error. `-no-fail` always exits 0. Inline suppression is `// #nosec G402 -- reason`. Track suppressions with `-track-suppressions`.

## Degraded path: no tools installed

Grep still finds the high-frequency classes. Label results as pattern-matched, not scanner-verified. Read the code to confirm each one.

Use the Grep tool with `output_mode: "files_with_matches"` for secret patterns. Content mode prints the whole matching line, which puts the full credential in the transcript and breaks rule 1.

```
NEXT_PUBLIC_[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD|SERVICE)
(sk_live_|sk-[A-Za-z0-9]{20}|AKIA[0-9A-Z]{16}|service_role|-----BEGIN [A-Z ]*PRIVATE KEY)
```

Run the same patterns against `dist/`, `.next/` and `build/`. Other patterns:

```
(execute|query|raw)\(.*(f"|f'|\$\{|\+\s*req\.|%\s*\(|\.format\()      SQL built by interpolation
\b(eval|exec)\(|new Function\(|pickle\.loads|yaml\.load\(              unsafe sinks
verify_signature"?\s*:\s*(false|False)|verify\s*=\s*False              JWT checks off
localStorage\.setItem.*[Tt]oken|localStorage.*jwt                      tokens in storage
```

And `git ls-files | grep -E "\.env($|\.)"` for tracked env files.

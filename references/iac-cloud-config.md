# IaC, Containers, CI Workflows and Web Config

Read this in Phase 5. Configuration is where AI-built apps fail most, and code scanners do not see it.

## Contents
- [The scanners are part of the supply chain](#the-scanners-are-part-of-the-supply-chain)
- [Tools to avoid or verify](#tools-to-avoid-or-verify)
- [IaC scanning](#iac-scanning)
- [Containers and Dockerfiles](#containers-and-dockerfiles)
- [CI workflow security](#ci-workflow-security)
- [GitHub Actions hardening](#github-actions-hardening)
- [Kubernetes and cloud posture](#kubernetes-and-cloud-posture)
- [Security headers, cookies, TLS](#security-headers-cookies-tls)
- [Minimum viable stack](#minimum-viable-stack)

## The scanners are part of the supply chain

Verified in this edition (CVE record, GitHub advisory and CISA KEV entry): on 2026-03-19 an attacker used stolen credentials to publish a malicious Trivy v0.69.4, force-push 76 of 77 tags of `aquasecurity/trivy-action` to credential-stealing code, and replace all 7 tags of `aquasecurity/setup-trivy`. Malicious images followed on Docker Hub. The advisory is CVE-2026-33634 (GHSA-69fq-xp46-6x23). CISA added it to the Known Exploited Vulnerabilities list on 2026-03-26.

What to do:
- Read the current advisory for the known-safe versions. Do not trust a version floor copied into this pack.
- Pin `trivy-action`, `setup-trivy` and every other scanner action by full commit SHA. Pin scanner images by digest.
- If CI ran Trivy through a mutable tag on 2026-03-19 or 2026-03-20, treat every secret this job held as exposed, and rotate. Look for a repository named `tpcp-docs` in the GitHub organization, which the advisory names as a sign the fallback exfiltration ran.
- Take indicators of compromise from the advisory, not from this pack.

The earlier edition also reported a compromise of KICS Docker Hub tags in spring 2026. This report was not re-verified. If the project uses KICS, check the Checkmarx advisory and pin by digest.

The lesson is general. A tag is a pointer someone is able to move. A commit SHA is not. Every scanner in CI runs with your credentials.

## Tools to avoid or verify

These claims come from the earlier edition and were not re-verified. Check each project page before you advise.

- tfsec merged into Trivy. New Terraform checks go to Trivy.
- Terrascan is reported archived in late 2025.
- ScoutSuite is reported stale. Prowler is the usual replacement.
- The `observatory-cli` npm package is reported dead. `@mdn/mdn-http-observatory` is the named replacement.

## IaC scanning

Trivy is the right default for a small app. One binary covers IaC, Dockerfiles, images, secrets and SBOM, with severity filtering.

```bash
trivy config .
trivy config --severity HIGH,CRITICAL --format sarif --output "$TMP/security-audit/trivy.sarif" --exit-code 1 .
```

Trivy exits 0 by default even with findings. `--exit-code 1` is required to gate. This is the most common mistake.

Inline suppression works in Terraform, CloudFormation, Helm and Dockerfiles:

```hcl
#trivy:ignore:AVD-AWS-0089:exp:2026-12-31
```

Inline ignores are unable to suppress checks triggered by absence, such as a missing `USER` in a Dockerfile. Those need `.trivyignore.yaml`.

Checkov has deeper policy coverage and covers GitHub Actions, GitLab CI, Bicep, ARM, Ansible and OpenAPI:

```bash
pipx install checkov
checkov -d . --compact --quiet --framework terraform,dockerfile,github_actions
```

Inline skip: `#checkov:skip=CKV_AWS_20:reason`. Exit 0 pass, 1 fail, `--soft-fail` forces 0. The open-source build ships no severity metadata, so `--hard-fail-on HIGH` needs a paid API key. Use Trivy for free severity gating.

KICS suits custom Rego policies. Its exit codes are severity values (20 info, 30 low, 40 medium, 50 high, 60 critical). CI logic written for 0 and 1 mis-gates.

## Containers and Dockerfiles

```bash
hadolint --failure-threshold error Dockerfile
trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 myapp:tag
```

Hadolint's threshold defaults to `info`, so style rules fail builds unless you raise it. Suppress with `# hadolint ignore=DL3008` above the line. Pass `--disable-ignore-pragma` in CI so developers cannot ignore their way past the gate.

Check by hand: a non-root `USER`, no secrets in `ENV` or build args, a pinned base image digest, no `curl | sh` installers, a small base image, no `--privileged` or Docker socket mounts in compose files, no published database or Redis ports on all interfaces. Rebuild images often. An image built last week keeps its old runtime and its old CVEs.

## CI workflow security

zizmor audits GitHub Actions workflows. Check `zizmor --help` for current flags.

```bash
uv tool install zizmor        # or: pipx install zizmor
zizmor .
zizmor --min-severity=medium --format=sarif . > "$TMP/security-audit/zizmor.sarif"
```

Its audits map to how CI gets compromised: `unpinned-uses`, `template-injection`, `artipacked` (credential persistence from checkout), `excessive-permissions`, `dangerous-triggers`, `cache-poisoning`, `secrets-inherit`, `bot-conditions`. Its exit codes are non-standard, with distinct codes for findings by severity. Read the docs before you gate on them.

actionlint is a complement. It catches syntax and expression errors and runs shellcheck over `run:` blocks.

## GitHub Actions hardening

Pin every third-party action to a full commit SHA. GitHub's documentation names a full SHA as the way to use an action immutably. The Trivy incident was a tag force-push, which SHA pinning defeats.

```yaml
uses: actions/checkout@<full 40-character commit SHA> # v5.0.0
```

Resolve the SHA for the tag you want from the action's repository. Do not copy a SHA from a blog or from this file. Tools such as `pinact` and `zizmor --fix` automate pinning. Organization policy enforces SHA pinning.

`pull_request_target` and `workflow_run` run in the base repository context with secrets and a write token. Never check out and run the pull request head under them. Avoid both unless commenting on fork PRs is truly required. This is the "pwn request" pattern.

Script injection: never put `${{ github.event.* }}` directly in a `run:` block. Pass it through an environment variable and quote it.

```yaml
env:
  TITLE: ${{ github.event.pull_request.title }}
run: echo "$TITLE"
```

Permissions: set the default token to read-only, then grant per job. Add `id-token: write` only where OIDC is used.

Prefer OIDC to long-lived cloud secrets. Long-lived secrets in CI are what the 2026 incidents stole. Scope the OIDC trust policy to one repository, one branch or environment.

Other checks: caches written by untrusted pull request jobs and read by privileged jobs (cache poisoning), `secrets: inherit` on reusable workflows, artifacts from untrusted runs consumed by privileged runs, self-hosted runners on public repos, and AI agent steps which read issue or PR text with write tokens (see `agent-config-and-worms.md`).

## Kubernetes and cloud posture

- kube-bench runs the CIS benchmark against a live cluster and needs host access. It does not apply to Vercel, Netlify, Railway or Fly.io.
- Prowler covers AWS, Azure, GCP and Kubernetes. Run it only when a real cloud account sits behind the app. Exit code 3 means FAIL findings. It does not audit Vercel or Netlify configuration.
- For any cloud account: check public buckets, wide IAM roles, long-lived access keys, public database endpoints, disabled logging, and backups in the same account and credential scope as production. A 2026 production incident lost volume backups with the data, because both sat behind one token.

## Security headers, cookies, TLS

In Windows PowerShell 5.1, `curl` is an alias for `Invoke-WebRequest`. Call `curl.exe`.

```bash
curl -sS -D - -o /dev/null -L https://example.com | grep -iE \
 '^(content-security-policy|strict-transport-security|x-frame-options|x-content-type-options|referrer-policy|permissions-policy)'
```

```powershell
curl.exe -sS -D - -o NUL -L https://example.com | Select-String 'content-security-policy|strict-transport-security|x-frame-options|referrer-policy'
```

Use `-D -` with `-L`, not `-I`. Some origins answer HEAD with 405, and CSP is often set only on GET.

Cookies: read the raw `Set-Cookie` header for `Secure`, `HttpOnly` and `SameSite`. A curl cookie jar file hides `HttpOnly` and `SameSite`.

```bash
curl -sS -D - -o /dev/null -L https://example.com/login | grep -i '^set-cookie'
```

TLS: `testssl.sh` through Docker or WSL (`docker run --rm -it ghcr.io/testssl/testssl.sh https://example.com`), or `sslyze` through pip on Windows (`python -m sslyze example.com:443`).

Platform split: on Vercel and Netlify, TLS, the HTTPS redirect and HSTS come with the platform. CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` and every cookie flag belong to the application. Configure them in `vercel.json` or `netlify.toml`. Netlify custom headers do not apply to proxied content, Functions or server-rendered pages. Verify against a live response, not the config file.

## Minimum viable stack

```bash
trivy fs --scanners vuln,misconfig,secret --severity HIGH,CRITICAL --exit-code 1 .
hadolint --failure-threshold error Dockerfile
zizmor --min-severity=medium .
```

Add the live header check from above. Add Checkov when real Terraform exists. Add Prowler when a cloud account sits behind the app. Skip kube-bench for platforms with no control plane.

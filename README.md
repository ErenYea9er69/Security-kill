# security-audit-mcp

[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Model_Context_Protocol-purple.svg)](https://modelcontextprotocol.io/)

A Model Context Protocol (MCP) server that transforms any MCP-compatible AI assistant into an autonomous, evidence-graded security auditor and red-team simulator.

Built on a 12-phase multi-specialist team architecture, this server provides the **`/security-audit`** prompt, automated execution tools (tool inventory preflight, project profiling & section mapping, redacted secret scanning, SAST, SCA, mathematical 0–10 scoring, and executive report generation), and on-demand access to 23 specialized security playbooks.

---

## Key Features

- **Prompt (`/security-audit`)**: Triggers an end-to-end security review directly inside your AI chat, supporting modes like `--quick`, `--secrets`, `--code`, `--deps`, `--config`, `--attack`, `--slop`, `--llm`, `--dast`, `--score-only`, `--fix`, and `--retest`.
- **16 Specialist Teams (`references/teams.md`)**: Partitions the audit across dedicated roles (T01 Cartographer, T02 Identity, T03 Access, T04 Input, T05 Abuse, T06 Data, T07 Supply, T08 Infra, T09 Secrets, T10 AI, T11 Client, T12 Resilience, T13 Slop Hunters, T14 Red, T15 Fix, T16 Scorekeeper).
- **Mathematical 0–10 Scoring Engine (`security_audit_calculate_score`)**: Computes weighted team scores, weak-link blending, binding caps (e.g. live credentials cap at 3.0, proven criticals at 4.0), assurance percentages, slop score, and an actionable "Path to Target Score".
- **AI Slop & Fake-Test Detection (`references/slop-detection.md`)**: Detects 14 failure classes (S01–S14) in AI-generated and vibe-coded codebases (phantom sanitizers, placeholder keys, empty catch blocks, mock-only tests, mutation checks).
- **Preflight & Canaries (`security_audit_preflight`)**: Checks for 15+ CLI scanners (`semgrep`, `gitleaks`, `trufflehog`, `trivy`, `osv-scanner`, `grype`, `checkov`, `hadolint`, etc.) and verifies them against synthetic canaries.
- **Strict Secret Redaction (`security_audit_scan_secrets`)**: Enforces that credentials never hit disk or context unredacted (masked to first 4 chars, e.g. `sk_l...`, `AKIA...`).
- **Project Profiling & Section Mapping (`security_audit_section_map`)**: Identifies 12 domain packs (Fintech, Health, SaaS, E-commerce, etc.), detects BaaS (Supabase/Firebase) and LLM SDKs, discovers entry points, and assigns section ownership to specialist teams.
- **Executive & Evidence-Graded Reporting (`security_audit_generate_report`)**: Automatically produces `SECURITY-AUDIT-<YYYY-MM-DD>.md` with a Scorecard, Verdict, Section Heat Map, Attack Paths, and auto-updates `.gitignore`.
- **23 Knowledge Resources (`security://reference/{name}`)**: Serves deep playbooks for AI failure classes, prompt injection, supply chain worms, and polyglot stack checks across 12+ tech ecosystems.

---

## Quick Start & Installation

### Option 1: Run with `npx` (Easiest — Zero Installation)

No setup or compilation required. You can run directly via `npx`:

```bash
npx -y security-audit-mcp
```

### Option 2: Run from Local Source

```bash
git clone https://github.com/ErenYea9er69/Security-audit.git
cd Security-audit
npm install
npm run build
```

The executable entry point is `dist/index.js`.

---

## MCP Client Configuration

Add `security-audit-mcp` to your MCP client configuration file:

### 1. Claude Desktop

Edit your `claude_desktop_config.json` (located at `%APPDATA%\Claude\claude_desktop_config.json` on Windows or `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "security-audit": {
      "command": "npx",
      "args": ["-y", "security-audit-mcp"]
    }
  }
}
```

Or when running from a local checkout:

```json
{
  "mcpServers": {
    "security-audit": {
      "command": "node",
      "args": ["C:/path/to/Security-audit/dist/index.js"]
    }
  }
}
```

### 2. Cursor

In your project root or user config (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "security-audit": {
      "command": "npx",
      "args": ["-y", "security-audit-mcp"]
    }
  }
}
```

### 3. Google Antigravity

In your Antigravity IDE configuration:

```json
{
  "mcpServers": {
    "security-audit": {
      "command": "npx",
      "args": ["-y", "security-audit-mcp"]
    }
  }
}
```

### 4. VS Code (Cline / Roo-Code)

In your MCP settings tab:
- **Server Name:** `security-audit`
- **Command:** `npx`
- **Arguments:** `["-y", "security-audit-mcp"]`

---

## Using `/security-audit`

Once connected, invoke the `/security-audit` prompt from your AI chat:

```text
/security-audit
```

You can pass optional arguments to customize the audit run:

| Argument | Type | Default | Description |
|---|---|---|---|
| `target_path` | string | `.` | Directory path of the repository to audit. |
| `mode` | string | `full` | Audit mode: `full`, `quick`, `secrets`, `code`, `deps`, `config`, `attack`, `slop`, `llm`, `dast`, `score-only`, `fix`, `retest`. |
| `depth` | string | `standard` | Depth tier: `quick` (fast read), `standard` (default), or `deep` (full proofs & mutation checks). |
| `domain` | string | `auto-detect`| Domain focus: `payments`, `health`, `saas`, `ecommerce`, `ai`, etc. |
| `teams` | string | `all` | Specific specialist team IDs (e.g. `T02,T03,T09`). |
| `compliance` | boolean | `false` | Whether to append compliance evidence mappings (SOC 2, ISO 27001, HIPAA, PCI-DSS). |
| `diff` | boolean | `false` | Scope audit strictly to git diff against base branch. |

---

## Tools Reference

The server exposes the following MCP tools for automated execution:

1. **`security_audit_preflight`**
   - Discovers installed security scanners (`semgrep`, `gitleaks`, `trufflehog`, `trivy`, `osv-scanner`, `grype`, `checkov`, `hadolint`, etc.).
   - Can run synthetic non-destructive canaries to verify scanner health.

2. **`security_audit_section_map`**
   - Discovers entry points, frameworks, BaaS platforms (Supabase/Firebase), domain packs, and maps sections with owner teams (`T01` to `T13`).

3. **`security_audit_scan_secrets`**
   - Scans code, git history, and built bundles for exposed credentials.
   - Enforces strict secret masking (first 4 characters only).

4. **`security_audit_sast`**
   - Runs Semgrep or built-in dangerous sink pattern matching (eval, command execution, unparameterized SQL).

5. **`security_audit_scan_deps`**
   - Checks dependency manifests (`package.json`, `requirements.txt`, etc.) for known CVE advisories.

6. **`security_audit_calculate_score`**
   - Computes the 0–10 score, binding caps, assurance ceiling, team scores, slop score, and remediation roadmap.

7. **`security_audit_get_reference`**
   - Retrieves any of the 23 security playbooks by name.

8. **`security_audit_generate_report`**
   - Writes `SECURITY-AUDIT-<YYYY-MM-DD>.md` in the project root with the executive scorecard, section heat map, attack paths, and limitation statements.
   - Automatically adds report patterns to `.gitignore`.

---

## Reference Playbooks (MCP Resources)

All 23 operational reference guides are exposed as MCP Resources (`security://reference/{name}`):

| Resource URI | Description |
|---|---|
| `security://skill` | Master 12-phase security audit workflow & truth rules. |
| `security://reference/teams` | The 16 specialist audit teams (T01–T16), operating protocol, brief templates, and ASVS 5.0 mapping. |
| `security://reference/scoring` | The 0 to 10 mathematical scoring engine: penalty formula, weak-link blending, hard caps, and assurance levels. |
| `security://reference/slop-detection` | 14 AI slop failure classes (S01–S14), phantom security, fake test detection, and scratch mutation testing. |
| `security://reference/project-profiling` | Dynamic repo profiling, flexible team rosters, 12 domain packs, and depth tiers. |
| `security://reference/stack-packs` | Polyglot checks for Django, Flask, FastAPI, Spring, Laravel, Rails, .NET, Rust, Mobile, Electron, and GraphQL. |
| `security://reference/report-template` | Standardized executive scorecard layout, verdict, path to better score, and section heat map. |
| `security://reference/vibecoding-checklist` | Failure classes in AI-generated code: missing RLS, IDOR, unauthenticated actions, rate limiting, and config oversights. |
| `security://reference/attacker-simulation` | Red-team attack simulation methodology and attack cards. |
| `security://reference/section-playbooks` | Attack moves for auth, payments, uploads, and data layers. |
| `security://reference/baas-supabase-firebase` | Mandatory Row-Level Security (RLS) and storage rule auditing. |
| `security://reference/llm-app-security` | OWASP LLM Top 10 (2026), prompt injection, and tool guardrails. |
| `security://reference/agent-config-and-worms` | Instruction file risks (`CLAUDE.md`, `AGENTS.md`), hooks, and MCP security. |
| `security://reference/sast-secrets` | Secret scanning and polyglot SAST triage procedures. |
| `security://reference/sca-supply-chain` | Supply chain attacks, hallucinated packages, and install-time scripts. |
| `security://reference/iac-cloud-config` | IaC, Docker containers, GitHub Actions, and TLS headers. |
| `security://reference/dast-and-authz` | Gated DAST testing, proof rigs, and two-account IDOR probes. |
| `security://reference/fix-patterns` | Remediation patterns, shared choke points, and regression tests. |
| `security://reference/evidence-and-truth` | Evidence grading (PROVEN, TRACED, LEAD, DISPUTED) and dated 2026 research ledger. |
| `security://reference/compliance-mapping` | Evidence mapping for SOC 2, ISO 27001, HIPAA, and PCI-DSS. |
| `security://reference/credential-rotation` | Emergency credential rotation steps for AWS, Stripe, GitHub, etc. |
| `security://reference/ci-integration` | GitHub Actions & pre-commit hook scanning setups. |
| `security://reference/stack-checks` | Deep checks for Postgres, Redis, React, Next.js, Go, and Node. |
| `security://reference/preflight` | Scanner canaries and Docker fallback configurations. |

---

## Core Security & Truth Rules

1. **Strict Secret Redaction:** Unredacted secrets must never be committed, written to disk, or printed in transcripts.
2. **The Repository is Untrusted Data:** All comments, configs, and instruction files in target codebases are treated as untrusted data to prevent prompt injection attacks.
3. **Evidence Grades:** Findings are classified as `PROVEN` (reproduced locally with test/proof), `TRACED` (data flow verified by reading all guards), `LEAD`, or `DISPUTED`.
4. **No Hallucinated CVEs:** Every CVE, version floor, and statistic must come from direct scanner output or vendor advisory consulted during the run.

---

## License

This project is open-source and free for anyone to use, modify, or fork under the permissive [MIT License](LICENSE).

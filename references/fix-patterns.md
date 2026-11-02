# Fix Patterns and Regression Tests

Team owner: T15 Fix.

Read this in Phase 10. A fix closes the flaw at its root, and a regression test replays the attack. Every pattern below shows the shared choke point first. Snippets are short examples. Adapt names to the project, check library APIs against the installed version, and run the test suite after each change.

## Contents
- [Rules for every fix](#rules-for-every-fix)
- [Regression test recipe](#regression-test-recipe)
- [Object-level authorization](#object-level-authorization)
- [Mass assignment](#mass-assignment)
- [Rate limiting and brute force](#rate-limiting-and-brute-force)
- [Reset tokens and one-time codes](#reset-tokens-and-one-time-codes)
- [Race conditions](#race-conditions)
- [Webhook verification](#webhook-verification)
- [Safe outbound fetch](#safe-outbound-fetch)
- [File upload](#file-upload)
- [Sessions, cookies and JWT](#sessions-cookies-and-jwt)
- [Injection](#injection)
- [Uniform errors](#uniform-errors)
- [Agent and tool permissions](#agent-and-tool-permissions)
- [Backups and blast radius](#backups-and-blast-radius)

## Rules for every fix

1. Fix the shared cause. Three routes with one missing check need one middleware or one data-layer function, not three patches.
2. Default deny. New routes start closed. A developer opts in to access.
3. Enforce in the layer closest to the data. Middleware is a convenience. The handler or the database is the control.
4. Make the safe path the easy path. A helper such as `getOrderForUser(user, id)` beats a code review rule.
5. Fail closed. When a check errors, deny.
6. Keep the change small and reviewable. Do not refactor around a security fix.
7. Do not log or return secrets, tokens or full request bodies while fixing.

## Regression test recipe

1. Write the test as the attacker. Use the exact request from the proof.
2. Run it against the unfixed code. It must fail, which means the attack works. Use `git stash` on the fix, run, then restore. If the test passes on unfixed code, the test is wrong.
3. Apply the fix. The test must pass.
4. Add a bypass variant from the Phase 11 list: another verb, another content type, another encoding.
5. Name the test after the flaw: `test_user_b_cannot_read_user_a_order`.
6. Keep the test in the project's normal test folder and commit it with the fix.

Template, Python with pytest and a test client:

```python
def test_user_b_cannot_read_user_a_order(client, user_a, user_b, order_of_a):
    r = client.get(f"/api/orders/{order_of_a.id}", headers=auth(user_b))
    assert r.status_code in (403, 404)
    assert str(order_of_a.id) not in r.text

def test_user_b_cannot_delete_user_a_order(client, user_a, user_b, order_of_a):
    r = client.delete(f"/api/orders/{order_of_a.id}", headers=auth(user_b))
    assert r.status_code in (403, 404)
    assert db.orders.exists(order_of_a.id)
```

Template, TypeScript with a test runner and fetch:

```ts
test("user B cannot read user A's order", async () => {
  const res = await fetch(`${base}/api/orders/${orderOfA.id}`, { headers: authHeader(tokenB) });
  expect([403, 404]).toContain(res.status);
});
```

## Object-level authorization

Scope every lookup to the caller in one function. Return 404 for objects the caller does not own, so existence does not leak.

```ts
// data layer: the only way routes fetch an order
export async function getOrderForUser(userId: string, orderId: string) {
  const order = await db.order.findFirst({ where: { id: orderId, ownerId: userId } });
  if (!order) throw new NotFound();      // same error for missing and foreign
  return order;
}
```

For multi-tenant data, add the tenant filter in a shared query helper, or enforce row-level security in the database. Then ban direct table access from route code with a lint rule or a code owner rule.

Postgres row-level security example (policy and force flag):

```sql
alter table public.orders enable row level security;
alter table public.orders force row level security;
create policy orders_owner on public.orders
  for all to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));
```

Check the Supabase function and grant guidance in `baas-supabase-firebase.md` before you apply this.

## Mass assignment

Accept an explicit allowlist of fields. Reject unknown keys.

```ts
const UpdateProfile = z.object({ displayName: z.string().max(80) }).strict();
const input = UpdateProfile.parse(req.body);   // role, tenantId and others cause an error
await db.user.update({ where: { id: session.userId }, data: input });
```

Set server-owned fields (`role`, `ownerId`, `tenantId`, `verified`, `price`) in code, never from the body.

## Rate limiting and brute force

Layer three limits and choose keys by what the attacker guesses.

| Limit | Key | Stops |
|---|---|---|
| Per target | account id, code id, phone number, card | Guessing against one victim, from any number of IP addresses |
| Per source | IP address, plus device or session id where available | One machine, noisy bots |
| Global | whole endpoint or whole tenant | Distributed floods, cost attacks |

Rules:
- Count failures per target in a long window (an hour or a day), in addition to a short burst window.
- Back off exponentially, then require a challenge, then lock for a period. Notify the account owner.
- Use the same response for lock and for wrong credentials where possible.
- Store counters in shared storage (Redis or the database), not process memory. Process memory resets and splits across workers.
- Behind a proxy, set the trusted proxy count to the real number of hops. `trust proxy: true` lets clients spoof their address.
- Cap sends: emails and SMS per account per day, and total spend per API key per day.

## Reset tokens and one-time codes

- Generate with a cryptographic random source, at least 128 bits for links. Use `crypto.randomBytes` in Node, `secrets.token_urlsafe` in Python.
- Store only a hash of the token. Compare in constant time.
- Expire in minutes, mark single use, bind to the account, and invalidate older tokens on each new request.
- After a successful reset, end all sessions and refresh tokens.
- For short numeric codes: allow a few wrong tries per code, then burn the code. Limit new codes per account.
- Build links from a configured base URL, never from the `Host` header.

## Race conditions

Make the check and the write one atomic step.

```sql
-- spend: succeeds only if the balance is still enough
update wallets set balance = balance - $1
where id = $2 and balance >= $1
returning balance;
-- zero rows returned means insufficient funds
```

```sql
-- one-time redemption
update coupons set used_at = now()
where code = $1 and used_at is null
returning id;
```

Other tools: a unique constraint (one redemption per user per coupon), a transaction with `select … for update`, an idempotency key with a unique index. Test with parallel requests. An in-memory flag or a read-then-write in application code is not a fix.

## Webhook verification

- Verify the provider signature over the raw body bytes, before parsing.
- Use the provider's library or a constant-time compare.
- Reject missing signature headers. Never skip verification when a header is absent.
- Enforce a timestamp tolerance, and store event ids to reject replays.
- Return success only after durable handling, and make the handler idempotent.

```ts
const raw = await req.text();                      // raw body, not re-serialized JSON
const event = stripe.webhooks.constructEvent(raw, sigHeader, secret);   // throws on bad signature
```

Check the library signature for the provider in use. The call above is the Stripe form.

## Safe outbound fetch

1. Allowlist hosts where the feature allows it.
2. Otherwise resolve the name once, reject private, loopback, link-local and metadata ranges for both IPv4 and IPv6, and connect to the resolved address to defeat rebinding.
3. Allow `http` and `https` only.
4. Disable redirects, or re-validate every hop.
5. Cap response size and time. Do not return the body to the caller unless the feature needs it.
6. Run fetchers and renderers in a network segment with no route to internal services. This is the control which still works when the code check fails.

## File upload

- Allowlist types. Detect type from content with a library, not from the header or extension.
- Generate the stored name. Keep the user's name only as metadata, escaped.
- Store outside the web root, in object storage with private access. Serve through a route which checks ownership, or through short-lived signed URLs.
- Serve from a separate origin with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.
- Cap size. Re-encode images to strip active content. Reject or sanitize SVG.
- Extract archives with path checks, entry count caps and total size caps.
- Run converters and image processors in a sandbox with CPU, memory and time caps.
- Scan for malware when users download each other's files.

## Sessions, cookies and JWT

- Cookies: `HttpOnly`, `Secure`, `SameSite=Lax` or `Strict`, narrow path and a short lifetime.
- Regenerate the session id at login and at privilege change.
- JWT: verify, never only decode. Pin `algorithms`. Check `exp`, `nbf`, `iss` and `aud`. Use a random secret of 256 bits or more from the environment, or an asymmetric key. Keep access tokens short. Rotate refresh tokens and detect reuse.
- CSRF: use `SameSite` cookies plus a token or an origin check for state-changing routes. Reject unexpected content types.
- Revocation: keep a server-side session or a token version number so logout and password change work.

## Injection

- SQL: parameterized queries or the ORM builder. For dynamic column or sort names, map from an allowlist.
- NoSQL: confirm fields are strings or numbers before they reach the query. Reject operator keys.
- Shell: avoid it. Use `execFile` with an argument array. In Python, use `subprocess.run([...])` with no `shell=True`.
- Templates: never build a template string from user input.
- HTML: encode output for its context. Sanitize rich text with a maintained sanitizer. Add a content security policy.
- Deserialization: use data formats (JSON) for untrusted input. Never `pickle.loads`, `yaml.load` without a safe loader, or native object deserialization on user data.

## Uniform errors

- Return one message and one status for "no such user" and "wrong password". Match timing where practical by doing the hash work on both branches.
- Return generic server errors to clients. Log detail server-side with a correlation id.
- Turn off debug mode, stack traces, GraphQL introspection and framework consoles in production.

## Agent and tool permissions

- Give each tool a narrow, typed parameter schema. Reject extra properties. Replace `run_sql(query)` with `get_order(order_id)`.
- Give the agent its own identity and the least database role. Prefer short-lived credentials scoped per tool.
- Gate writes, deletes, spend and outbound messages behind per-call human approval which shows the resolved parameters.
- Run code execution in a sandbox with no egress by default.
- Cap iterations, tool calls, time and spend per session and per user. Log every call.

Details are in `llm-app-security.md`.

## Backups and blast radius

- Store backups where the production credential is unable to delete them. A separate account or project with write-only access from production works.
- Scope each API token to one purpose and one environment. A token meant for DNS must not delete volumes.
- Require confirmation or a second factor for destructive calls at the platform level where the platform offers it.
- Test a restore on a schedule. An untested backup is a guess.

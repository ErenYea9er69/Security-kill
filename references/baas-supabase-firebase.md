# Supabase and Firebase Verification

Team owner: T03 Access, with T08 Infra for platform settings.

Read this in Phase 5 when either platform appears. It is the highest-value check in this pack. With these platforms the browser talks to the database directly, so the policy layer is the only wall. A public key plus a missing or permissive policy returns every row to anyone.

Verify enforcement. Never accept "RLS is enabled" as an answer. RLS enabled with a permissive policy, or without `FORCE` where an owner path exists, is as good as off.

## Contents
- [Quick start](#quick-start)
- [Supabase tooling](#supabase-tooling)
- [Supabase SQL audit queries](#supabase-sql-audit-queries)
- [Supabase keys](#supabase-keys)
- [Supabase black-box tests](#supabase-black-box-tests)
- [Supabase auth config](#supabase-auth-config)
- [Edge Functions and database webhooks](#edge-functions-and-database-webhooks)
- [Firebase: audit the deployed rules](#firebase-audit-the-deployed-rules)
- [Firebase: open-rule patterns](#firebase-open-rule-patterns)
- [Firebase black-box tests](#firebase-black-box-tests)
- [What client keys protect](#what-client-keys-protect)
- [Corrections to common advice](#corrections-to-common-advice)

## Quick start

```bash
supabase db advisors --linked --level error     # verify the command exists in your CLI version
```

```bash
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://firebaserules.googleapis.com/v1/projects/$PROJECT/releases" | jq
```

Everything below is the detail behind these two, plus black-box probes which prove enforcement.

## Supabase tooling

| Command | What it does | Security use |
|---|---|---|
| `supabase db lint` | `plpgsql_check`, PL/pgSQL errors | Not a security linter. Often mistaken for one. |
| `supabase db advisors` | Runs the embedded `splinter` lint SQL | This is the security check. Needs a recent CLI. Check `--help`. |
| `supabase inspect db <sub>` | Bloat, locks, index stats | No security subcommand. |
| `supabase test db` | pgTAP tests | RLS regression tests in CI |
| Dashboard Security Advisor | Same splinter lints | Manual check |

Run splinter against any Postgres with no CLI dependency:

```bash
curl -sO https://raw.githubusercontent.com/supabase/splinter/main/splinter.sql
psql "$DB_URL" -f splinter.sql
```

Review the SQL before you run it, since you fetch it from the network. Splinter error-level lints include `rls_disabled_in_public`, `policy_exists_rls_disabled`, `auth_users_exposed`, `security_definer_view`, `rls_references_user_metadata` and `sensitive_columns_exposed`. Warning level adds `rls_policy_always_true`, `public_bucket_allows_listing`, `function_search_path_mutable` and the security definer function pair. Lint names change. Read the current README.

## Supabase SQL audit queries

Tables with RLS off:

```sql
select n.nspname as schema, c.relname as table,
       c.relrowsecurity as rls_enabled, c.relforcerowsecurity as rls_forced
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('r','p')
  and n.nspname not in ('pg_catalog','information_schema','pg_toast')
  and not c.relrowsecurity
order by 1,2;
```

`relforcerowsecurity` matters alone: without `FORCE`, the table owner bypasses RLS. A migration or a `SECURITY DEFINER` function running as owner then ignores policies.

RLS on with zero policies fails closed, which is safe but usually a bug. The fix an agent applies next is often `using (true)`:

```sql
select n.nspname, c.relname
from pg_class c join pg_namespace n on n.oid = c.relnamespace
left join pg_policy p on p.polrelid = c.oid
where c.relkind in ('r','p') and c.relrowsecurity
  and n.nspname not in ('pg_catalog','information_schema')
group by 1,2 having count(p.oid) = 0;
```

Overly permissive policies:

```sql
select schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
from pg_policies
where schemaname not in ('pg_catalog','information_schema')
  and ( (cmd in ('SELECT','UPDATE','DELETE','ALL') and qual in ('true','(true)'))
     or (cmd in ('INSERT','UPDATE','ALL') and with_check in ('true','(true)'))
     or qual ilike '%auth.role()%authenticated%'
     or qual ilike '%auth.uid() is not null%' )
order by 1,2;
```

Read the `roles` column. `{public}` or `{anon}` means the unauthenticated internet. `{authenticated}` means anyone who signs up, which is everyone while signup is open.

Policies which read user-editable metadata give a full authorization bypass:

```sql
select schemaname, tablename, policyname, cmd, qual, with_check
from pg_policies
where qual ilike any (array['%user_metadata%','%raw_user_meta_data%'])
   or with_check ilike any (array['%user_metadata%','%raw_user_meta_data%']);
```

Policies such as `auth.jwt() -> 'user_metadata' ->> 'role' = 'admin'` are common in AI-written code. The user edits `user_metadata`. Use `app_metadata`, which only the server edits, or a roles table.

Grants. RLS is irrelevant on a table `anon` cannot select from and fatal on one it is able to:

```sql
select table_schema, table_name, grantee,
       string_agg(privilege_type, ',' order by privilege_type) as privs
from information_schema.role_table_grants
where grantee in ('anon','authenticated','PUBLIC')
  and table_schema not in ('pg_catalog','information_schema')
group by 1,2,3 order by 1,2,3;

select * from pg_default_acl;   -- grants on FUTURE tables
```

`SECURITY DEFINER` functions callable by `anon`:

```sql
select n.nspname, p.proname, pg_get_userbyid(p.proowner) as owner,
       coalesce(array_to_string(p.proconfig,','), 'MUTABLE search_path!') as config,
       has_function_privilege('anon', p.oid, 'execute') as anon_exec
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where p.prosecdef and n.nspname not in ('pg_catalog','information_schema');
```

Two risks. The function runs as its owner and bypasses RLS on everything it touches. And a null `proconfig` means a mutable `search_path`, so a caller with create rights shadows a name and gets owner-level execution. Fix both:

```sql
alter function public.my_fn() set search_path = '';
revoke execute on function public.my_fn() from anon, public;
```

`SECURITY DEFINER` views run with the definer's rights unless the view sets `security_invoker` (Postgres 15 and later):

```sql
select n.nspname, c.relname, c.reloptions
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where c.relkind in ('v','m') and n.nspname not in ('pg_catalog','information_schema');
```

Anything without `{security_invoker=on}` has definer semantics. Fix with `alter view public.my_view set (security_invoker = on);`. Materialized views are unable to carry RLS. Revoke access instead.

Extensions as outbound primitives:

```sql
select p.proname, has_function_privilege('anon', p.oid, 'execute') as anon_exec
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where n.nspname in ('net','http','vault','pgsodium','extensions');
```

Any `true` here, combined with a definer wrapper, gives outbound requests from your infrastructure on demand (SSRF and exfiltration).

Storage buckets:

```sql
select id, name, public, file_size_limit, allowed_mime_types from storage.buckets order by public desc, name;
select * from pg_policies where schemaname = 'storage';
```

`public = true` bypasses access control for reads.

## Supabase keys

| | `anon` or `sb_publishable_…` | `service_role` or `sb_secret_…` |
|---|---|---|
| RLS | Enforced | `BYPASSRLS`, skips every policy |
| Safe in a client bundle | Yes, by design | Never |

Verified against the Supabase docs on 2026-10-31: Supabase is deprecating the legacy JWT-based `anon` and `service_role` keys by the end of 2026, in favor of `sb_publishable_…` and `sb_secret_…`. Creating new keys does not revoke legacy ones. Secret keys return HTTP 401 when the request looks like a browser (a `User-Agent` match). This raises the bar. It is not a control, since curl works. Secret keys are not JWTs and cannot be decoded.

Why `service_role` in client code is Critical: the role carries `BYPASSRLS`, so the engine skips policies. Every policy becomes decoration. It equals publishing the database password.

```bash
rg -n --hidden --glob '!node_modules' -e 'service_role' -e 'sb_secret_' -e 'SUPABASE_SERVICE' \
   . dist build .next out .vercel 2>/dev/null
echo "$KEY" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq '.role, .ref'   # legacy JWT keys only
```

Classify new opaque keys by behavior. Query a table you know RLS protects. If rows return, it is a secret key. Do this only on a disposable project or with the owner's consent.

## Supabase black-box tests

```bash
BASE="https://$REF.supabase.co"
H=(-H "apikey: $ANON" -H "Authorization: Bearer $ANON")
```

Enumerate the exposed surface, then test reads and writes:

```bash
curl -s "$BASE/rest/v1/" "${H[@]}" | jq -r '.paths | keys[]'
curl -s "$BASE/rest/v1/profiles?select=*&limit=5" "${H[@]}"
```

Read the result. Rows from other users are a confirmed failure. `{"code":"42501"}` (permission denied) or a missing relation is safe. An empty array is ambiguous. Settle it with an exact count:

```bash
curl -sD - -o /dev/null "$BASE/rest/v1/profiles?select=id" "${H[@]}" \
  -H "Prefer: count=exact" -H "Range: 0-0" | grep -i content-range
# 0-0/1482 means rows exist and the policy filters them (good)
# */0 means the table is empty (proves nothing)
```

Always test writes. Agents write read policies and forget `with_check`:

```bash
curl -s -X POST "$BASE/rest/v1/profiles" "${H[@]}" -H "Content-Type: application/json" \
  -d '{"email":"probe@example.test","role":"admin"}'
curl -s -X PATCH "$BASE/rest/v1/profiles?id=eq.<other-id>" "${H[@]}" -H "Content-Type: application/json" \
  -d '{"role":"admin"}'
```

Run write probes only against a disposable project or staging. Test the second surface too:

```bash
curl -s -X POST "$BASE/graphql/v1" "${H[@]}" -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name } } } }"}'
curl -s "$BASE/storage/v1/bucket" "${H[@]}" | jq '.[] | {name, public}'
```

The only sound isolation test is a two-tenant positive control. An empty result for `anon` proves nothing about tenants:

```sql
begin;
select plan(2);
set local role authenticated;
set local request.jwt.claims = '{"sub":"<uuid-A>","role":"authenticated"}';
select results_eq('select count(*)::int from profiles', array[1], 'A sees only own row');
set local request.jwt.claims = '{"sub":"<uuid-B>","role":"authenticated"}';
select results_eq('select count(*)::int from profiles where id = ''<uuid-A>''', array[0], 'B cannot see A');
select * from finish();
rollback;
```

## Supabase auth config

```bash
curl -s "$BASE/auth/v1/settings" -H "apikey: $ANON" | jq
```

When `disable_signup` is false (the default), an attacker mints a legitimate `authenticated` token in one request. Every `auth.role() = 'authenticated'` policy then serves the whole internet. Confirm the metadata escalation:

```bash
curl -s -X PUT "$BASE/auth/v1/user" -H "apikey: $ANON" -H "Authorization: Bearer $USER_JWT" \
  -H "Content-Type: application/json" -d '{"data":{"role":"admin","is_admin":true}}'
```

Success means every policy reading `user_metadata` is open to bypass. Run signup and metadata probes only on a disposable project you own.

## Edge Functions and database webhooks

New keys change how functions authorize. The platform `verify_jwt` check understands only the legacy JWT keys. Docs advise setting `verify_jwt = false` for functions called with the new keys, and authorizing the request in your own code. A function with `verify_jwt = false` and no check in code is open to the internet.

Check every function:
- Read `supabase/config.toml` for `verify_jwt = false`.
- For each such function, read the code for an explicit caller check (a verified user token, a secret header compared in constant time, or a signature).
- Confirm each function using a secret key takes user input only after authorization, since a secret key bypasses RLS.
- Calls from Postgres through `pg_net`, including database webhooks, send the key in a header. New secret keys go in the `apikey` header, not `Authorization: Bearer`. Confirm triggers do not pass user-controlled URLs.

## Firebase: audit the deployed rules

Console edits drift from `firestore.rules` in git. Pull the live ruleset.

```bash
TOKEN=$(gcloud auth print-access-token)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://firebaserules.googleapis.com/v1/projects/$PROJECT/releases" | jq -r '.releases[] | "\(.name)\t\(.rulesetName)"'
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://firebaserules.googleapis.com/v1/projects/$PROJECT/rulesets/<id>" | jq -r '.source.files[] | "// === \(.name)\n\(.content)"'
```

Realtime Database rules are a separate system with a separate endpoint:

```bash
curl -s "https://$DB_INSTANCE.firebaseio.com/.settings/rules.json?access_token=$TOKEN"
```

Rules take minutes to propagate. Do not assert right after a deploy.

## Firebase: open-rule patterns

```bash
rg -n -e 'if\s+true' -e 'if\s+request\.auth\s*!=\s*null\s*;' -e 'timestamp\.date\(' firestore.rules storage.rules
rg -n -e '"\.read"\s*:\s*true' -e '"\.write"\s*:\s*true' database.rules.json
rg -rn '"type"\s*:\s*"service_account"|"private_key"\s*:\s*"-----BEGIN' --glob '!node_modules' . dist build
```

Four failing patterns:

```
// 1. Fully open. The project id is in your bundle, so anyone owns the data.
match /{document=**} { allow read, write: if true; }

// 2. Test-mode default. Open until the date, then the app breaks, and the usual fix is a later date.
match /{document=**} { allow read, write: if request.time < timestamp.date(2026, 9, 1); }

// 3. Open in practice. Signup is on by default, so "authenticated" means anyone.
match /{document=**} { allow read, write: if request.auth != null; }

// 4. Unverified email. Sign-in does not verify the address.
allow read: if request.auth.token.email.endsWith('@corp.com');   // needs && request.auth.token.email_verified
```

Two traps. Rules are OR-combined, so one permissive match anywhere grants access regardless of a later `if false`. And `allow read` on a document does not cover the `list` query which returns it, so split `read` into `get` and `list` when they differ.

The Rules Playground evaluates the editor's ruleset, not the deployed one. An unsaved edit passes while production is open. Only the live fetch and black-box tests prove what is deployed. For regression, use `@firebase/rules-unit-testing` with the emulator, `assertFails` and `assertSucceeds`, and a `demo-` project id so tests never touch production.

## Firebase black-box tests

The project id and API key sit in the client bundle by design.

```bash
curl -s "https://firestore.googleapis.com/v1/projects/$P/databases/(default)/documents"
curl -s "https://$P-default-rtdb.firebaseio.com/.json?shallow=true"
curl -s "https://firebasestorage.googleapis.com/v0/b/$P.appspot.com/o?maxResults=1000"
```

Test writes only on a disposable project or with the owner's consent. Then escalate. Mint a real identity and repeat everything. This turns `request.auth != null` from "looks fine" into a finding:

```bash
TOKEN=$(curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" \
  -H 'Content-Type: application/json' -d '{"returnSecureToken":true}' | jq -r .idToken)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://firestore.googleapis.com/v1/projects/$P/databases/(default)/documents/users"
```

Run from a clean profile or another IP. A cached session or an allowlisted origin makes an open project look locked.

## What client keys protect

Client keys are identifiers, not authorization. They answer "which project", never "is this caller allowed this row". Protection lives in server-side policy.

| Platform | Public by design | The real control | Never in a client |
|---|---|---|---|
| Firebase | `apiKey`, `projectId`, `appId` | Security Rules, plus App Check against abuse | Service account JSON |
| Supabase | `sb_publishable_…`, `anon` | RLS, grants, exposed-schema config | `sb_secret_…`, `service_role` |

Supabase ships a second key with `BYPASSRLS`, and both look like adjacent opaque strings in the dashboard, so coding agents paste the wrong one. For a public key there was nothing to leak. For a `service_role` key, rotation stops the bleeding and the missing RLS remains.

App Check shows a request came from your app. It does not show a user is allowed a row. It limits scripted abuse and quota theft. App Check in front of `allow read, write: if true` is an open database. Fix rules first.

## Corrections to common advice

1. `supabase db lint` is not a security scanner. Use `supabase db advisors`.
2. `supabase inspect db` has no security subcommand.
3. An empty array from a Supabase REST query is not proof of RLS. Confirm with `Prefer: count=exact` and a two-tenant control.
4. `request.auth != null` and `auth.role() = 'authenticated'` are public while signup is open, which is the default on both platforms.
5. RLS without `FORCE` fails where an owner-privileged path touches the table.
6. The Firebase Rules Playground tests the editor's ruleset, not the deployed one.
7. A function with `verify_jwt = false` needs its own authorization in code.

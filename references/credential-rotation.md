# Credential Rotation

Read this when the audit found a live credential. Hand the user the steps for their provider. Generic advice wastes the hours which matter.

Rotate first, scrub second. People get this backwards. They rewrite git history, feel finished, and leave a working credential in an attacker's hands. Removing a secret from history does not change whether it still authenticates. Until the provider revokes it, it is compromised. Exposed cloud keys have produced large bills within hours of publication.

Assume compromise. A key in a public repository, a CI log, a client bundle or a package you installed from a compromised release is known to an attacker, even if no abuse shows yet.

## Contents
- [Order of operations](#order-of-operations)
- [Supabase](#supabase)
- [Firebase and Google Cloud](#firebase-and-google-cloud)
- [AWS](#aws)
- [Stripe](#stripe)
- [OpenAI and Anthropic](#openai-and-anthropic)
- [GitHub](#github)
- [Package registry tokens](#package-registry-tokens)
- [Cloud platform and infrastructure tokens](#cloud-platform-and-infrastructure-tokens)
- [Database connection strings](#database-connection-strings)
- [After a worm or a compromised scanner](#after-a-worm-or-a-compromised-scanner)
- [Scrubbing git history](#scrubbing-git-history)

## Order of operations

1. Revoke or rotate at the provider.
2. Read the provider's audit log for use you did not authorize. Record the window between exposure and revocation.
3. Deploy the new credential.
4. Only then consider scrubbing history.
5. Add the file to `.gitignore` and turn on push protection so it does not recur.

Steps 1 and 2 matter. Step 4 is hygiene.

## Supabase

The leaked key decides the severity.

`anon` or `sb_publishable_…`: public by design. Not a leak. If it reaches data, the finding is missing row-level security, and rotating the key fixes nothing. See `baas-supabase-firebase.md`.

`service_role` or `sb_secret_…`: critical. The role has `BYPASSRLS` and ignores every policy. Treat it as a leaked database password.

Rotate in the dashboard under Project Settings, then API Keys. The newer `sb_secret_` format supports several concurrent keys, each revocable on its own, so a rollover has no downtime: create a new key, deploy it, revoke the old one. Name one key per service so a leak forces one rotation. Supabase is retiring the legacy JWT keys by the end of 2026, so this is a good time to migrate.

Legacy JWT keys derive from the project JWT secret. Rotating this secret invalidates `anon` and `service_role` together and signs out every user, since user tokens used the same secret. Plan for the session loss, or migrate to the new keys first.

After rotation, audit what the key touched through Postgres logs and the dashboard logs. Assume every table the role reads was read.

## Firebase and Google Cloud

Web API key (`AIza…`): public by design, in every client bundle. Google's documentation says so. It is not a leak. The real question is whether Security Rules allow what the key reaches. Restrict it by referrer or app to limit abuse of billable APIs. This is quota protection, not access control.

Service account JSON: critical, and the real Firebase leak. It holds a `private_key` and often broad rights.

In the Cloud Console under IAM and Admin, Service Accounts, Keys: create a new key, deploy it, delete the exposed key. Deletion is immediate. Then read Cloud Audit Logs for activity by this account during the window, and check whether its roles were wider than needed. A leaked key with `Editor` is a different incident from one scoped to a bucket.

Prefer workload identity federation or attached service accounts over downloaded key files.

## AWS

An exposed `AKIA…` key is an emergency. Scrapers find keys in public repositories within minutes and start costly compute. Use two-key rotation:

```bash
aws iam create-access-key --user-name <user>
# deploy the new key everywhere and verify the app works
aws iam update-access-key --user-name <user> --access-key-id <OLD> --status Inactive
# confirm nothing broke, then
aws iam delete-access-key --user-name <user> --access-key-id <OLD>
```

Deactivating before deleting gives a reversible step.

Check abuse in CloudTrail by access key id:

```bash
aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<KEY_ID>
```

Look for `RunInstances` in regions you do not use, `CreateUser`, `AttachUserPolicy` and `CreateAccessKey`. An attacker's first move is usually persistence. Any of these makes it an incident, not a rotation. Involve the account owner and check billing.

AWS might attach a quarantine policy to a key it detects as exposed. This limits damage and does not revoke the key. Delete it anyway. Long term, use IAM roles or OIDC federation from CI in place of static keys.

## Stripe

Under Developers, API keys, use Roll key. The roll flow lets you set an expiry on the old key so both work briefly. Immediate expiry revokes at once. Roll restricted keys the same way. Read Developers, Logs and Events for requests you did not make, especially refunds, payouts and customer data reads. A leaked publishable key (`pk_live_…`) is not a finding.

## OpenAI and Anthropic

Revoke in the provider console under API keys. Revocation is immediate with no grace period, so create and deploy the replacement first if downtime matters. Then check per-key usage in the console. A spike on a key you did not use is the abuse signal. These keys are billable directly, which makes them a target. Scope keys per service and set spend limits where the console allows it, so the next leak has a ceiling.

## GitHub

Fine-grained personal access token: revoke under Settings, Developer settings. Immediate. Prefer these, since they are scoped to repositories and permissions.

Classic PAT: revoke the same way and rate it higher, since classic tokens carry broad scopes such as `repo` across everything the user reaches.

Deploy keys: remove under the repository's Settings, Deploy keys. Check whether the key had write access.

GitHub App and OAuth tokens: revoke the installation, or rotate the app's client secret.

After revoking, read the account security log and the repository audit log for pushes, workflow runs and new keys during the window. Look for new workflow files and new repositories you did not create. Turn on secret scanning and push protection.

## Package registry tokens

npm, PyPI and RubyGems tokens matter more since 2026 worms stole them from developer machines and CI, then republished infected versions.

- Revoke the token in the registry's account settings. Create a new, narrowly scoped one, or move to publishing from CI with short-lived identity.
- Read the registry's publish history for versions you did not release. Yank or deprecate any, and tell downstream users.
- Check `~/.npmrc`, `~/.pypirc` and CI secrets for the same token in other places.
- Enable two-factor authentication for publishing where the registry offers it.
- If trusted publishing is in use, review the publisher configuration: repository, workflow file and environment. See `agent-config-and-worms.md`.

## Cloud platform and infrastructure tokens

Tokens for Railway, Vercel, Netlify, Fly.io, Cloudflare and similar platforms often hold account-wide power, including deleting databases, volumes and backups. The PocketOS incident (April 2026) began with a token which held broad rights over an infrastructure API.

- Revoke at the platform, then issue a token scoped to one project and one environment.
- Read the platform's audit log for deletes, new tokens and new members.
- Move backups to a place the production token cannot delete.

## Database connection strings

Rotate the password, not the cluster, and avoid downtime with a second user:

1. Create a new user with the same grants.
2. Deploy the new connection string.
3. Confirm connections moved (`pg_stat_activity` shows the connecting user on Postgres).
4. Drop or disable the old user.

On managed platforms, do the equivalent in the console: Atlas under Database Access, RDS with `modify-db-instance --master-user-password`, Supabase under Database Settings.

Then check whether the database was reachable from the internet at all. A leaked string for a private-network database rates lower than one for a public host. Say which in the report.

## After a worm or a compromised scanner

When `agent-config-and-worms.md` or `iac-cloud-config.md` flags exposure, rotate every secret the affected machine, CI job or account was able to read. This means registry tokens, cloud keys, GitHub tokens, SSH keys, API keys in environment variables, and keys in shell history. Read the advisory's guidance for the specific incident. Remove persistence (hook files, workflows, extra keys) before you deploy replacements, or the new secrets leak too.

## Scrubbing git history

Only after rotation. This rewrites every commit hash from the touched point forward.

`git filter-repo` is the current tool. `git filter-branch` is deprecated, and its own documentation advises against it. BFG Repo-Cleaner suits the simple "delete this file everywhere" case.

```bash
pip install git-filter-repo
git filter-repo --path .env --invert-paths
git push --force --all
git push --force --tags
```

BFG equivalent:

```bash
bfg --delete-files .env
git reflog expire --expire=now --all && git gc --prune=now --aggressive
```

Tell the user what scrubbing does not fix:

- Every collaborator re-clones. A merge from a stale clone brings the old history back.
- Existing forks keep the original objects. You are unable to rewrite someone else's fork.
- Pull request refs on GitHub might retain old commits, and cached views persist. Removal needs a request to GitHub Support.
- Anything already cloned, mirrored or archived by a third party is out of reach.
- The force push rewrites shared history, so coordinate it and schedule it on a busy branch.

Scrubbing is defense in depth. Rotation is the fix. Say so in the report.

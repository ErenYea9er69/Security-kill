# Proof Rig, DAST and Authorization Testing

Team owner: T14 Red.

Read this in Phase 7, before you launch any scanner or send any attack request. It covers the authorization gate, the proof rig for hypotheses from Phase 6, passive and active scanning, and the two-account authorization probe.

## Contents
1. [Authorization gate](#1-authorization-gate)
2. [Proof rules](#2-proof-rules)
3. [Proof rig: sequential probes](#3-proof-rig-sequential-probes)
4. [Proof rig: race conditions](#4-proof-rig-race-conditions)
5. [Authorization and IDOR probing](#5-authorization-and-idor-probing)
6. [Brute force and limiter checks](#6-brute-force-and-limiter-checks)
7. [OWASP ZAP](#7-owasp-zap)
8. [nuclei](#8-nuclei)
9. [Passive versus active](#9-passive-versus-active)
10. [Typical durations](#10-typical-durations)

## 1. Authorization gate

Active scanning and attack proofs look the same as an attack to the target. Running them against a host you do not own, or without written permission, might break computer misuse laws and cloud provider terms. These laws are criminal statutes.

- `localhost`, `127.0.0.1` and `host.docker.internal` are local targets. Check what the port serves first. A tunnel (`kubectl port-forward`, an SSH forward, ngrok) puts production behind a loopback address. Confirm the data is disposable.
- Any other host (domain, LAN address, staging URL, cloud endpoint) needs the user to state in their own words they own it or hold written authorization. Ask, then wait. A URL found in the repo, in `.env` or in a README is not authorization.
- Passive scans still send real requests. The gate applies to them on non-loopback hosts.

## 2. Proof rules

1. Prove the smallest thing which settles the question. One request often settles an authorization flaw.
2. Use seeded test accounts and test data. Never use a real person's account.
3. Set a request cap before you start. Write it down. Stop when you reach it.
4. Prove read flaws with your own canary record, not with another person's data. If a probe returns real personal data by accident, stop, do not store it, and tell the user.
5. Never run destructive requests (delete, drop, mass update) against data you did not seed.
6. Redact tokens and secrets in everything you record.
7. Keep scripts in `$TMP/security-audit/poc/` and delete them at the end of Phase 9.
8. Record for each proof: hypothesis id, request, response status and a redacted body excerpt, and what the result shows.
9. A proof which fails to reproduce does not clear the hypothesis. It moves to Not verified, with a note on what you tried. Only a read of the guard moves it to Refuted.

## 3. Proof rig: sequential probes

Replay with curl and compare status codes. Keep each probe small.

```bash
BASE=http://localhost:3000
curl -s -o /dev/null -w "%{http_code}\n" "$BASE/api/orders/1042"                                   # no credentials: expect 401
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $B_TOKEN" "$BASE/api/orders/1042"   # other user's object: expect 403 or 404
```

Compare "user exists" and "user missing" responses:

```bash
for e in real@example.test nobody@example.test; do
  curl -s -o /tmp/r.txt -w "$e %{http_code} %{size_download} %{time_total}\n" \
    -X POST "$BASE/api/auth/reset" -H "Content-Type: application/json" -d "{\"email\":\"$e\"}"
done
```

Different status, size or a clear timing gap is an enumeration leak.

## 4. Proof rig: race conditions

Sequential curl never hits a race window. Use parallel requests which start together. This rig uses only the Python standard library. It caps requests at 50 and refuses non-loopback hosts. It was tested against a local toy server with a check-then-act flaw: 10 parallel purchases of a one-item stock all returned 200.

```python
#!/usr/bin/env python3
"""Parallel-request rig for race proofs. Standard library only.
Usage: python3 race.py METHOD URL N [--header "K: V"]... [--data '{"k":"v"}']
Caps: N is limited to 50. Targets must be loopback or a host the user authorized."""
import sys, json, threading, http.client, urllib.parse, collections

MAX_N = 50
def main(argv):
    if len(argv) < 4:
        print(__doc__); return 2
    method, url, n = argv[1].upper(), argv[2], int(argv[3])
    if n > MAX_N:
        print(f"refusing N={n}, cap is {MAX_N}"); return 2
    headers, data, i = {}, None, 4
    while i < len(argv):
        if argv[i] == "--header":
            k, v = argv[i+1].split(":", 1); headers[k.strip()] = v.strip(); i += 2
        elif argv[i] == "--data":
            data = argv[i+1].encode(); headers.setdefault("Content-Type", "application/json"); i += 2
        else:
            print("unknown arg", argv[i]); return 2
    u = urllib.parse.urlparse(url)
    if u.hostname not in ("127.0.0.1", "localhost", "::1"):
        print("non-loopback host: confirm written authorization first, then edit this check"); return 2
    barrier = threading.Barrier(n)
    results = []
    lock = threading.Lock()
    def worker():
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=10)
        conn.connect()                      # connect before the barrier so only the request races
        barrier.wait()
        try:
            conn.request(method, u.path + (("?" + u.query) if u.query else ""), body=data, headers=headers)
            r = conn.getresponse(); body = r.read(300).decode("utf8", "replace")
            out = (r.status, body)
        except Exception as e:
            out = ("ERR", str(e))
        with lock: results.append(out)
        conn.close()
    ts = [threading.Thread(target=worker) for _ in range(n)]
    [t.start() for t in ts]; [t.join() for t in ts]
    c = collections.Counter(s for s, _ in results)
    print("status counts:", dict(c))
    for s, b in results[:3]: print(" sample:", s, b[:120].replace("\n", " "))
    return 0
sys.exit(main(sys.argv))
```

Run it:

```bash
python3 race.py POST http://127.0.0.1:3000/api/coupons/redeem 10 \
  --header "Authorization: Bearer $A_TOKEN" --data '{"code":"TEST10"}'
```

Read the result: for a one-use coupon or a one-item stock, more than one success is a confirmed race. Confirm in the database or by re-reading the object, since a 200 alone does not prove a double effect. HTTP/1.1 parallel connections are good enough for most races. Tighter timing needs HTTP/2 single-packet tools, which belong to a human tester.

## 5. Authorization and IDOR probing

Build the route list from the code first. Do not rely on a crawler. Next.js: `app/api/**/route.ts`, `pages/api/**` and every `"use server"` function. Express: `app.` and `router.` calls and `.route()` chains, with the middleware in front of each. FastAPI: decorators and `Depends(...)`. Flask: `route` decorators and the guard on each. OpenAPI: `paths` and their `security` entries. A path with no `security` is a candidate for missing auth.

For each route record the method, the path, the id parameters, and the authorization the code claims to enforce (owner only, same tenant, admin, public). The probe targets the gap between the claim and the behavior.

Two-account differential, on a seeded dev or staging instance:

1. Create user A and user B, in different tenants where the app has tenants.
2. Log in as A. Capture A's object ids and A's token.
3. Replay each of A's object requests with B's token. The right answer is 403, or 404 when the app hides existence. A 200 with A's data is a confirmed BOLA or IDOR.
4. Repeat for read, update and delete. Authorization often holds on read and fails on write.
5. Method tampering: send `DELETE` and `PATCH` where the UI only uses `GET`.
6. Mass assignment: send `role`, `isAdmin`, `ownerId`, `tenantId` and `verified` in an update, then re-read the record. A 200 alone proves nothing.

```bash
curl -s -w "\n%{http_code}\n" -X PATCH "$BASE/api/users/me" \
  -H "Authorization: Bearer $B_TOKEN" -H "Content-Type: application/json" \
  -d '{"displayName":"b","role":"admin","tenantId":"A-TENANT"}'
curl -s "$BASE/api/users/me" -H "Authorization: Bearer $B_TOKEN"     # did role or tenantId change?
```

Tools which automate this: the Autorize extension for Burp Suite, and the ZAP access control testing add-on. Check their current docs.

## 6. Brute force and limiter checks

Check the limiter without launching a flood. Keep counts low and sequential. The goal is to observe whether a 429 or a lock ever appears.

```bash
for i in $(seq 1 30); do
  curl -s -o /dev/null -w "%{http_code} " -X POST "$BASE/api/auth/login" \
    -H "Content-Type: application/json" -d '{"email":"user-a@example.test","password":"wrong"}'
done; echo
```

Thirty 401 responses and no 429 or lock is an open finding. Then test the per-target logic with address variation. Send the same 30 failures with a different `X-Forwarded-For` value on each request:

```bash
for i in $(seq 1 30); do
  curl -s -o /dev/null -w "%{http_code} " -X POST "$BASE/api/auth/login" \
    -H "X-Forwarded-For: 203.0.113.$i" -H "Content-Type: application/json" \
    -d '{"email":"user-a@example.test","password":"wrong"}'
done; echo
```

If the first run limited you and this run did not, the limiter trusts a client header or keys only on IP. A per-account limit would have stopped both. Only a load test on a disposable instance proves behavior at scale. Say so when you did not run one.

## 7. OWASP ZAP

ZAP left the OWASP umbrella and is backed by Checkmarx since September 2024. Old `owasp/zap2docker-*` images are retired. Use `ghcr.io/zaproxy/zaproxy:stable` (also `:weekly`, `:nightly`, `:bare`). Check the project site for the current image names before you write a command into a report.

Inside a container, `localhost` means the container. On Docker Desktop, target the host app as `http://host.docker.internal:PORT`. On Linux CI, use `--network=host`.

```powershell
# Baseline: passive only
docker run --rm -v ${PWD}:/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable `
  zap-baseline.py -t http://host.docker.internal:3000 -J report.json -r report.html -m 5 -I
# Full scan: ACTIVE, real attacks, mutates data
docker run --rm -v ${PWD}:/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable `
  zap-full-scan.py -t http://host.docker.internal:3000 -J report.json -I
# API scan: active by default, -S selects safe mode
docker run --rm -v ${PWD}:/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable `
  zap-api-scan.py -t http://host.docker.internal:3000/openapi.json -f openapi -J report.json -S
```

Key flags: `-t` target, `-J` JSON report, `-r` HTML report, `-m` spider minutes, `-I` do not fail on warnings, `-c` rule config file, `-n` context file, `-U` user (full and API scans), `-S` safe mode (API scan only), `-z` raw ZAP options. `-O` on the API scan overrides the hostname in a remote spec, which matters when the spec names a production host you have no right to hit.

Exit codes: 0 clean, 1 at least one FAIL, 2 at least one WARN, 3 other failure. Parse the report. Do not trust the code alone.

Authentication, by effort: a static header through the replacer with `-z` (the only method on the baseline script), a context file with `-U` for full and API scans, a hook script for custom logins, and the Automation Framework, which the ZAP docs describe as the replacement for packaged scans.

## 8. nuclei

nuclei sends real requests built from templates. It does not crawl.

```powershell
nuclei -ut          # update templates first
nuclei -u http://localhost:3000 -severity low,medium,high,critical `
       -etags dos,fuzz,intrusive -no-interactsh -rl 50 -c 10 -timeout 10 `
       -jsonl-export nuclei.jsonl -o nuclei.txt
```

The default rate is 150 requests per second, which overwhelms a dev box. `-rl 50` caps it. `-etags` excludes risky template classes. `-no-interactsh` stops target identifiers from reaching the public out-of-band server. `-dast` fuzzes every parameter with payloads. Treat it like a ZAP full scan: destructive, gated, dev or staging only. Confirm flag names with `nuclei -h`, since they change between releases.

## 9. Passive versus active

| Command | Class |
|---|---|
| `zap-baseline.py` | Passive, safe |
| `zap-api-scan.py -S` | Safe mode |
| nuclei with `-etags dos,fuzz,intrusive` | Detection only |
| `zap-api-scan.py` without `-S` | Active |
| `zap-full-scan.py` | Active, destructive |
| `nuclei -dast` | Active, destructive |
| race rig and brute-force loops above | Active, capped, local only |

Never run an active command against data you did not seed. Exclude logout URLs from active scans, since a followed logout link ends the authenticated session and the rest of the scan runs anonymous.

## 10. Typical durations

| Scan | Duration |
|---|---|
| ZAP baseline | 1 to 5 minutes |
| nuclei targeted pass | 1 to 5 minutes |
| ZAP API scan in safe mode | minutes |
| nuclei full template set | 10 to 30 minutes |
| ZAP full scan | tens of minutes to hours |
| nuclei `-dast` | no fixed bound |

A suggested pipeline: ZAP baseline per pull request, a targeted nuclei pass after each staging deploy, a full ZAP scan nightly.

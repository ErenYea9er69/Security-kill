# Evidence and Truth

Read this before you write any version, CVE id, flag, exit code or number into a report. It holds the evidence grades, the lookup procedure for volatile facts, and a dated ledger.

## Evidence grades

| Grade | Meaning | Allowed in findings list |
|---|---|---|
| PROVEN | You reproduced the attack against a running instance or a test rig. You hold a redacted request and response, or a failing test. | Yes |
| TRACED | You read the full path from entry point to sink, you opened every guard on the path, and each guard fails to stop the attack. You cite file and line for each hop. | Yes |
| LEAD | A scanner, a pattern or a hunch points at it. You have not traced it. | No. List under Not verified. |
| DISPUTED | Two independent verifiers disagree. | Yes, with both arguments. |

Severity caps:
- Critical needs PROVEN, or TRACED with unauthenticated reach confirmed by reading the route and its middleware.
- A LEAD never exceeds Low in the report. State the proof step which would raise it.

## The six hallucination traps in security work

1. Invented identifiers. CVE ids, GHSA ids and rule ids look alike. A wrong digit points the user at an unrelated bug. Copy the id from the advisory page, never from memory.
2. Stale floors. Patch floors move every month. A floor which was right in July is wrong in October. Compute the floor in this run.
3. Fabricated flags. Scanner flags change between releases, and wrong flags often fail silently. Run `<tool> --help` or read the tool docs before you rely on a flag marked "verify" in the references.
4. Phantom guards. A function named `sanitize` or `requireAuth` proves nothing. Open it.
5. Confident negatives. "No SQL injection found" means the checks you ran found none. It does not mean none exist. Name the checks.
6. Borrowed statistics. A percentage from a blog post has an unknown sample and an unknown method. Do not repeat one to the user as fact.

## Lookup procedure for volatile facts

Run this for every runtime, framework, database and scanner you find in Phase 0. Skip it only for tools you do not touch.

1. Find the vendor's own security page. Examples: the Next.js blog security posts, the Node.js vulnerability blog, the PostgreSQL security page, the Redis security advisories, the GitHub advisory for the exact package.
2. Fetch it with WebFetch. A search snippet is not enough. Read the table of fixed versions.
3. Compare the version in the repo's lockfile or image tag to the fixed version for its release line. A release line with no fixed version is end of life. Report it as a finding.
4. Check for a scheduled release. Several vendors now announce security releases in advance. If one is due within days, tell the user the date.
5. Record in the report: source name, URL, fetch date, fixed version. Example: "Next.js 15.5.28, nextjs.org security post, fetched 2026-10-31".
6. If you have no web access, write "patch floor not verified" and give the vendor page for the user to check.

Distro packages backport fixes without changing the upstream version number. For a package from apt, dnf or apk, check the distro's security tracker instead of comparing version strings.

## Source quality

Prefer, in order: the vendor advisory, the CVE record or GitHub advisory, CISA KEV, a peer-reviewed paper, a named incident response firm's write-up, a news report which cites one of these, a blog post. Two independent sources beat one. A vendor blog which sells a product has a motive to inflate risk. Note when a claim has only this source.

## Dated ledger: facts checked on 2026-10-31

Each row was read from a source in the preparation of this edition. Facts older than 30 days need a fresh check. Facts marked "secondary" came from a news or vendor summary, not the primary advisory.

### Scanner and CI supply chain

| Fact | Source | Notes |
|---|---|---|
| CVE-2026-33634: on 2026-03-19 an attacker published malicious Trivy v0.69.4, force-pushed 76 of 77 tags of `aquasecurity/trivy-action`, and replaced all 7 tags of `aquasecurity/setup-trivy`. | CVE record, GitHub advisory GHSA-69fq-xp46-6x23, CISA KEV entry dated 2026-03-26 | CVSS 9.4 from the GitHub CNA. |
| Docker Hub images 0.69.5, 0.69.6 and `latest` were also pushed with malicious content, 2026-03-22 to 2026-03-23. | Docker Scout advisory page, secondary report | |
| Known-safe references named in the advisory: Trivy binary 0.69.2 and 0.69.3 or earlier, `trivy-action` v0.35.0, `setup-trivy` v0.2.6. | Advisory text | Check the advisory for the current list. Pin by commit SHA or image digest. |
| A repository named `tpcp-docs` in your GitHub org signals the fallback exfiltration ran. | CVE record text | |
| The earlier edition named a typosquat domain and an IP address as indicators of compromise. | Not re-verified | Take indicators from the advisory, not from this pack. |
| Malicious LiteLLM PyPI releases 1.82.7 and 1.82.8 were reported in the same campaign wave. | Secondary report | Verify on the LiteLLM disclosure before citing. |

### Package registry worms

| Fact | Source | Notes |
|---|---|---|
| Mini Shai-Hulud hit TanStack npm packages on 2026-05-11, then reached PyPI. Packages published through npm Trusted Publishing carried the malware. | Several security vendor write-ups | Secondary. |
| TeamPCP published the worm source about a day later. Copycats followed. | Akamai date cited by a secondary write-up | Secondary. |
| Miasma, 2026-06-01: 32 `@redhat-cloud-services` packages, 96 versions, payload in a `preinstall` script. Reports say it forged provenance attestations and wrote itself into SessionStart hooks of AI coding tools. | Socket, Wiz and others via secondary write-ups | Secondary. Check the primary reports. |
| A report says a poisoned VS Code extension led to a breach of GitHub internal repositories on 2026-05-19 and 2026-05-20. | One vendor tag page | Single secondary source. Do not repeat as fact. |

### Frameworks, runtimes, databases

| Fact | Source | Notes |
|---|---|---|
| Next.js moved to a pre-announced monthly security release program in July 2026. | Next.js blog | |
| Next.js 2026-07-20 release fixed 9 CVEs in 16.2.11 and 15.5.21. CVE-2026-64642 is a middleware or proxy bypass in App Router with Turbopack and a single `i18n.locales` entry, affecting 16.0.0 up to 16.2.10. CVE-2026-64643 discloses Server Function endpoint ids. | Next.js blog, NVD mirror | |
| Next.js 2026-10-14 out-of-band release: fixed versions 16.4.1 and 15.5.28. Two Critical remote code execution bugs (a `use cache` typed-array bug, and CVE-2026-96889 in image optimization through the `sharp` library with SVG input, CVSS v4 9.5) and a Server Actions denial of service. Versions 13.x and 14.x have no patched release. | Next.js blog, Netlify changelog, Singapore CSA alert | The floor in the earlier edition (16.2.11 and 15.5.21) is outdated. |
| A scheduled Next.js release for 2026-11-03 covers seven medium issues. | Next.js blog, posted 2026-10-27 | Check after this date. |
| Node.js 2026-10-21 security releases: 22.23.4, 24.22.1, 26.12.1. CVE-2026-111497 is a Brotli decoder out-of-bounds write rated high, with TLS hostname check bypasses also fixed. Node 20, 23 and 25 are end of life. | Node.js release notes via project release pages, secondary summaries | Read the Node.js vulnerability blog for the final list. |
| Redis 2026-05-05 advisory: CVE-2026-23479, 25243, 25588, 25589, 23631. Fixed in 6.2.22, 7.2.14, 7.4.9, 8.2.6, 8.4.3, 8.6.3. The RESTORE and unblock flaws need an authenticated user. | Redis blog, oss-security post | Later Redis releases might exist. Check the advisories page. |
| PostgreSQL 2026-02-12 release fixed CVE-2026-2005, a pgcrypto heap overflow reachable through attacker-supplied ciphertext. | PostgreSQL announcement, Debian tracker | |
| PostgreSQL 2026-05-14 release (18.4, 17.10, 16.14, 15.18, 14.23) fixed 11 CVEs. PostgreSQL 13 reached end of life in 2026-05. | Secondary reports citing the project | Check the PostgreSQL security page for newer releases. |

### Standards and law

| Fact | Source | Notes |
|---|---|---|
| OWASP Top 10 for LLM Applications 2026 was published on 2026-08-04 (one source says 08-03). Order: LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Excessive Agency, LLM04 Supply Chain, LLM05 Data and Model Poisoning, LLM06 Unbounded Consumption, LLM07 Misinformation, LLM08 Hidden Context Exposure, LLM09 Vector and Embedding Weaknesses, LLM10 Improper Output Handling. | OWASP repository page, three secondary write-ups agree on the list | The 2025 numbering differs. Name the year on every id. |
| OWASP Top 10 for Agentic Applications, ASI01 to ASI10, was published in December 2025. | CSA research note | |
| OWASP Top 10:2025 web list includes A01 Broken Access Control, A03 Software Supply Chain Failures, A10 Mishandling of Exceptional Conditions. | Carried from the earlier edition | Not re-fetched. Spot-check before citing numbers beyond these. |
| DPDP Rules 2025 were notified 2025-11-13. Rule 4 commences 2026-11-13. Rules 3, 5 to 16, 22 and 23, which include the security safeguards and breach intimation, commence 2027-05-13. In 2026 the ministry proposed to shorten the period for significant data fiduciaries. | Gazette timeline pages, law firm notes | Check whether the amendment passed. |
| Supabase is deprecating legacy `anon` and `service_role` keys by end of 2026. New keys are `sb_publishable_…` and `sb_secret_…`. Secret keys return 401 when called from a browser User-Agent. | Supabase docs | The platform `verify_jwt` check understands only legacy JWT keys. |

### Attackers and incidents

| Fact | Source | Notes |
|---|---|---|
| An operator pointed autonomous AI agents at company websites, with a goal such as running code on a shop and planting a web shell uploader. Over 1,200 sites were targeted. Exposed control panels revealed it. | The Hacker News, 2026-10-20, citing Reuters and a researcher | Secondary. |
| Mandiant reports a 2026 shift from AI as advisor to AI as agent in attacks, and a first confirmed case, dated 2026-05, of criminals using an AI-developed zero-day exploit for mass exploitation. | Google Cloud Mandiant special report | |
| Exploitation of vulnerabilities was the leading initial infection vector for the sixth year in the Mandiant M-Trends 2026 report. | Same report | |
| A research benchmark studies how autonomous pentest agents handle false target evidence. | arXiv listing | Supports the use of decoys. It does not give a rate. |
| April 2026: a Cursor agent using Claude Opus 4.6 deleted PocketOS production data and volume backups through one Railway API call, using an unrelated token with broad scope. Backups sat on the same volume. A 30-hour outage followed, and data was later partly recovered. | PC Gamer, Computing, ACS and other reports of the founder's post | |
| Agent skill registries held malicious skills in early 2026. Koi Security reported 341 of 2,857 ClawHub skills malicious. A Snyk audit of 3,984 skills found 76 confirmed malicious. An academic study found 26.1% of sampled skills had at least one vulnerability. | Koi, Snyk and an arXiv paper via secondary summaries | Sample methods differ. Do not combine the numbers. |
| Check Point disclosed configuration injection flaws in Claude Code (CVE-2025-59536) in February 2026. | Secondary report | Verify on the CVE record. |

## Carried from the earlier edition and not re-verified

Do not repeat these to the user as fact. Treat them as background.

- Percentages from app audits: missing RLS in 88 percent of apps, client-exposed secrets in 78 percent, inverted auth checks in 24 percent.
- The 36 percent versus 95 percent false-positive filter figures, the 8 in 100 detection figure, and the eightfold drop at 100k tokens of context.
- Secret scanner precision and recall numbers, and the secrets-in-public-commits yearly totals.
- Incident counts and sizes for Tea, Moltbook, Base44 and the Lovable RLS CVE.
- CVE-2026-2006, CVE-2026-44575 and CVE-2026-45109, and the claim of five separate middleware bypass CVEs.
- KICS compromise dates, tool release tags in CI examples, and the `p/shadow-ai-pro` Semgrep pack name.
- The 19.7 percent package hallucination figure from the USENIX Security 2025 study. The study exists. Re-read it before quoting.

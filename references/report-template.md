# Report Template

Read this in Phase 9. The Scorekeeper (T16) fills it after `scoring.md` runs. Write the file as `SECURITY-AUDIT-<YYYY-MM-DD>.md` in the project root. Add `SECURITY-AUDIT-*.md` to `.gitignore` first, since the report maps live weaknesses and must never be committed. When today's report exists, add a suffix. Get the date from the environment (`date +%F` or `Get-Date -Format yyyy-MM-dd`). After the report is written, delete `$TMP/security-audit/`, proof scripts included.

## Layout

```markdown
# Security Audit: <project>
<date> | commit <sha> | depth tier <quick|standard|deep> | facts checked <date>

## Scorecard
Security score: X.X / 10   Band: <band>
Assurance: <level> (<number>)   Ceiling: <number>   Slop score: X.X / 10
Binding cap: <condition and finding id, or none>
Team scores: T02 8.0 | T03 6.4 | ...
Weights changed from default: <none, or list with reasons>
Status: <Final | Provisional | Not rated>

## Verdict
<2 or 3 sentences: ship or hold, and the one thing to fix first>

## Path to a better score
<table from scoring.md: if you fix these, the score becomes this>

## Attack paths
<3 to 5 cheapest routes from an attacker to an asset, as numbered chains linked to finding ids>

## Section heat map
<one row per section: id, name, owner team, score, top finding>

## Findings
### [CRITICAL] F-01 <title>
Where: path/to/file.ts:42
Team: T03 | Attacker: <profile>
Evidence: PROVEN | TRACED | DISPUTED
OWASP: <id with year>
What: <the flaw in plain language>
Exploit: <the concrete request or action, and what the attacker gets>
Fix: <specific change, with a snippet where useful>
Regression test: <name or path, written in Phase 10>
Siblings: <count of the same flaw shape elsewhere>
Penalty: <base x evidence x reach x asset = value>

## Slop findings
<confirmed slop rows by class S01 to S14 with the three most frequent classes named>

## Not findings
<leads investigated and dismissed, each with the reason and the guard cited>

## Not verified
<hypotheses with no proof, each with the missing proof step>

## Scoring detail
<penalty table, cap table, assurance inputs C, P, T, V>

## Coverage
Roster: <active teams and why>. Not applicable: <teams off, with the absent signal>.
Scope set by the user: <flags, exclusions>.
Sections attacked: <list>. Skipped: <list with reasons>.
Tools: <OK, BROKEN and MISS lists with errors>. What is therefore unknown: <list>.
Instructions found in the repo and ignored: <list, or none>.

## Limitations
<the standing text below>

## Appendix (only with --compliance)
<evidence mapping from compliance-mapping.md>
```

## Standing limitations text

Copy these into every report.

- This audit misses more than it finds. Scanners cover their own rule sets and nothing beyond. LLM review misses real bugs and returns different verdicts on the same code across runs. A clean report means the checks which ran found nothing. It is not evidence of safety, and nobody should summarize it this way.
- The score is an estimate from a house method. Two runs might differ. It measures one snapshot of one commit. It is not a certification.
- Findings skew toward low and medium. Do not imply otherwise.
- Results are not reproducible. State this in any compliance appendix, because an auditor will ask.
- Runtime behavior is invisible to static review. A dependency which fetches its payload at install or run time shows nothing malicious on disk.
- This is not a penetration test. Business-logic flaws, chained exploits and creative attacker reasoning still need a human.
- Slop detection finds patterns. It does not show who wrote the code.

## Writing rules for the report

1. Lead with the scorecard and the verdict. A reader decides in ten seconds whether to keep reading.
2. One finding, one paragraph of exploit a developer is able to follow.
3. Give the fix as a change, not a lecture.
4. Name what you did not test as clearly as what you found.
5. Never print a secret value. Show location, type and the first 4 characters.
6. Never state a scan makes a system compliant or safe.

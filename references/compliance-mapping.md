# Compliance Mapping Reference

Team owner: T16 Scorekeeper.

Read this in Phase 9, when the user asks for `--compliance`. It maps findings to framework controls so the report carries an evidence appendix.

## Contents
- [Evidence is not compliance](#evidence-is-not-compliance)
- [OWASP Top 10:2025](#owasp-top-102025)
- [OWASP LLM Top 10 2026](#owasp-llm-top-10-2026)
- [ISO/IEC 27001:2022 Annex A](#isoiec-270012022-annex-a)
- [ISO/IEC 42001:2023](#isoiec-420012023)
- [GDPR](#gdpr)
- [India DPDP Act 2023 and DPDP Rules 2025](#india-dpdp-act-2023-and-dpdp-rules-2025)
- [Writing the appendix](#writing-the-appendix)
- [When the user asks "are we compliant?"](#when-the-user-asks-are-we-compliant)
- [Rules for using this file](#rules-for-using-this-file)

## Evidence is not compliance

Scanner output is evidence for a control. It is never compliance. A clean scan proves a test ran and passed. An auditor decides whether the test was enough, whether the scope was right, and whether the surrounding management system exists.

Constraints on every report built with this file:

1. Never state or imply a scan result makes a system compliant, certified or certifiable.
2. Never write "certified", "attested" or "audited against" for scanner output. Use "evidences", "supports" and "is relevant to".
3. Carry the caveat text into the report file, not only the chat. The template below has it.
4. A control with no finding is not a passed control. It means this run produced no evidence either way.
5. Compliance needs policies, a risk assessment and organizational measures. A scanner sees none of them.
6. This audit is not reproducible run to run (see the limitations in `SKILL.md`). An auditor will ask. Say it in the appendix.

## OWASP Top 10:2025

The eighth edition came out in November 2025. Write the year with each id. A03 and A10 changed meaning from 2021.

| Id | Category | Change from 2021 |
|---|---|---|
| A01:2025 | Broken Access Control | Still first. Absorbs SSRF, which was 2021 A10. |
| A02:2025 | Security Misconfiguration | Up from fifth. |
| A03:2025 | Software Supply Chain Failures | Widened from Vulnerable and Outdated Components. |
| A04:2025 | Cryptographic Failures | Down from second. |
| A05:2025 | Injection | Down from third. |
| A06:2025 | Insecure Design | Down from fourth. |
| A07:2025 | Authentication Failures | Renamed. |
| A08:2025 | Software or Data Integrity Failures | Stays eighth. |
| A09:2025 | Security Logging and Alerting Failures | Renamed. |
| A10:2025 | Mishandling of Exceptional Conditions | New. Error handling, fail-open paths, logic errors. |

Mapping notes: SSRF findings go to A01:2025. Dependency and build pipeline findings go to A03:2025. Fail-open error paths and swallowed exceptions go to A10:2025.

| Scan domain | Categories usually evidenced |
|---|---|
| SAST | A01, A04, A05, A08, A10 |
| DAST and attack proofs | A01, A02, A05, A07 |
| SCA | A03 |
| Secret scanning | A02 and A04, plus A07 when the credential is auth material |
| Config review | A02 |

## OWASP LLM Top 10 2026

Use only when the target integrates an LLM. The 2026 numbering differs from 2025. The full table with 2025 ids is in `llm-app-security.md`.

| Id | Category |
|---|---|
| LLM01:2026 | Prompt Injection |
| LLM02:2026 | Sensitive Information Disclosure |
| LLM03:2026 | Excessive Agency |
| LLM04:2026 | Supply Chain |
| LLM05:2026 | Data and Model Poisoning |
| LLM06:2026 | Unbounded Consumption |
| LLM07:2026 | Misinformation |
| LLM08:2026 | Hidden Context Exposure |
| LLM09:2026 | Vector and Embedding Weaknesses |
| LLM10:2026 | Improper Output Handling |

| Finding type | Category |
|---|---|
| Secrets or tool definitions inside prompt templates or client code | LLM08:2026, LLM02:2026 |
| Over-broad tools, no approval gate | LLM03:2026 |
| Model, SDK and package provenance | LLM04:2026 |
| No token, iteration or spend caps | LLM06:2026 |
| Model output reaching a sink with no sanitizer | LLM10:2026 |

## ISO/IEC 27001:2022 Annex A

The scan activity and its records evidence the control. The absence of findings does not. Cite the number with the title.

| Scan domain | Controls |
|---|---|
| SAST | A.8.28 Secure Coding / A.8.25 Secure Development Life Cycle / A.8.29 Security Testing in Development and Acceptance / A.8.26 Application Security Requirements |
| DAST and attack proofs | A.8.29 / A.8.8 Management of Technical Vulnerabilities / A.8.27 Secure System Architecture and Engineering Principles |
| SCA | A.8.8 / A.5.21 Managing Information Security in the ICT Supply Chain / A.5.19 and A.5.20 Supplier Relationships and Agreements / A.5.23 Cloud Services |
| Secret scanning | A.8.4 Access to Source Code / A.8.24 Use of Cryptography / A.8.12 Data Leakage Prevention / A.5.17 Authentication Information |
| PII in code or logs | A.8.12 / A.8.15 Logging / A.5.34 Privacy and Protection of PII |
| IaC and config scanning | A.8.9 Configuration Management; A.8.31 Separation of Development, Test and Production Environments |
| Recurring CI scans with triage records | A.8.8 / A.8.16 Monitoring Activities / A.8.32 Change Management |
| Human code review records | A.8.25 / A.8.28 / A.8.29 |

Certification rests on the Statement of Applicability, the management system and the certification audit. A scan adds records to specific controls and nothing more.

## ISO/IEC 42001:2023

An AI management system standard. Cite it only for AI-integrated systems. Which Annex A controls apply depends on the organization's Statement of Applicability.

| Domain | Control |
|---|---|
| SAST and DAST of AI-feature code, including prompt handling and output sanitization | A.6.1.3 Processes for Responsible Design and Development; A.6.2.4 AI System Verification and Validation |
| Security requirements for LLM features | A.6.2.2 AI System Requirements and Specification |
| SCA over model, SDK and vector database dependencies | A.4.4 Tooling Resources; A.10.3 Suppliers |
| Scan reports archived per release | A.6.2.3 Documentation of Design and Development; A.6.2.7 AI System Technical Documentation |
| Pre-deploy scan gate | A.6.2.5 AI System Deployment |
| Continuous scanning and monitoring in production | A.6.2.6 AI System Operation and Monitoring; A.6.2.8 Recording of Event Logs |
| PII and secret scanning of training or retrieval data pipelines | A.7.2 Data for Development and Enhancement / A.7.5 Data Provenance / A.7.6 Data Preparation |
| Security findings feeding an impact assessment | A.5.2 AI System Impact Assessment Process |

## GDPR

The strongest direct mapping is Article 32(1)(d): a process for regularly testing, assessing and evaluating the effectiveness of technical and organizational measures. The word "regularly" matters. One run evidences a test. A schedule evidences the process.

| Scan domain | Article |
|---|---|
| SAST, DAST and SCA on a schedule or in CI | Art. 32(1)(d) |
| Crypto misuse: weak TLS, hardcoded keys, plaintext storage | Art. 32(1)(a) |
| Flaws touching availability or integrity, with remediation | Art. 32(1)(b) |
| Security gates in the SDLC from design onward | Art. 25(1) and 25(2) |
| Secret scanning, since exposed credentials are a breach vector | Art. 32(1). Actual exposure might be notifiable: Art. 33 to the authority within 72 hours, Art. 34 to data subjects where risk is high |
| PII in code or logs | Art. 5(1)(f) with Art. 32. Unminimized PII in logs also touches Art. 5(1)(c). Exposure triggers Arts. 33 and 34 |
| Logging and alerting findings | Art. 32(1)(b) and (d). Detection capability underpins the 72-hour clock, which starts on awareness of the breach |

PII in source or logs is more than a finding. It is potential evidence of an Article 32 failure, and if exposed it is a personal data breach under Art. 4(12). Escalate it. Do not list it at its raw scanner severity.

## India DPDP Act 2023 and DPDP Rules 2025

Timing, checked against gazette-based timelines and law firm notes on 2026-10-31:

- MeitY notified the Rules on 13 November 2025. Some sources write 14 November. These are final rules.
- Commencement is phased. Rule 4 (consent managers) starts on 13 November 2026. Rules 3, 5 to 16, 22 and 23, which include the security safeguards in Rule 6 and the breach intimation in Rule 7, start on 2027-05-13.
- In early 2026 MeitY proposed to shorten the period for significant data fiduciaries to 12 months. Articles from March and April 2026 describe the proposal. Check whether it passed before you state a date for such a client.
- Safeguards are architectural and cannot be retrofitted in the last weeks, so start now.

Obligations, carried from the earlier edition. Verify against the Act text before you cite penalty amounts.

- Section 8(5) requires reasonable security safeguards. Section 8(6) requires breach intimation.
- Rule 6 sets minimum safeguards: encryption, obfuscation, masking or virtual tokens, access control, logs and monitoring, one-year retention of logs, backups, and processor contracts which carry these terms.
- Rule 7 requires intimation to affected Data Principals without delay and a detailed report to the Data Protection Board within 72 hours.
- Penalties named in the Act schedule: up to Rs 250 crore for failing security safeguards, up to Rs 200 crore for failing breach notification.

| Scan domain | Provision |
|---|---|
| SAST and DAST with a remediation trail | s.8(5) with Rule 6(1) |
| Crypto findings | Rule 6(1)(a) |
| SCA and processor SDK scanning | Rule 6(1)(f); s.8(2) |
| Secret scanning | Rule 6(1)(b), access control. A lapse sits in the s.8(5) tier |
| PII in code or logs | s.8(5) risk. Log visibility under Rule 6(1)(c) holds only if the logs are protected. Over-retention conflicts with s.8(7) and Rule 8 erasure |
| Logging and monitoring findings | Rule 6(1)(c). Underpins the 72-hour Rule 7 report |
| Timestamped scan reports and fix history | Shows the "reasonable" standard if the Board investigates after a breach |

## Writing the appendix

Append this to the report after the findings. Fill only the cells the scan supports. Write `n/a` where no control fits. Never widen a mapping to fill a column.

```markdown
## Appendix: Compliance Evidence Mapping

This appendix maps findings from this scan to control frameworks. Scanner
output is evidence for a control, not compliance with it. A clean result
shows a test ran and passed. Sufficiency of scope, method and frequency is
an auditor's decision. This audit is not reproducible run to run. Nothing
here certifies or attests conformity.

Scan run: <date> | Scope: <repos, branches, environments> | Tools: <tools run> | Facts checked: <date>

### Finding to control mapping

| # | Finding | Severity | OWASP 2025 | ISO 27001:2022 | GDPR | DPDP Act 2023 / Rules 2025 |
|---|---|---|---|---|---|---|
| 1 | Hardcoded API key in src/config.ts | High | A02:2025 Security Misconfiguration | A.8.4 / A.5.17 | Art. 32(1) | Rule 6(1)(b) / s.8(5) |

### Controls exercised by this scan run

| Control | What evidences it | Standing requirement |
|---|---|---|
| GDPR Art. 32(1)(d) | This scan: date, scope, tool versions | Recurrence |
| ISO 27001 A.8.29 | Scan run before release, result recorded | Retained report per release |
| ISO 27001 A.8.8 | Findings found, rated and tracked | Closed-loop triage records |

### Not evidenced by this scan

<List controls the reader might expect that this run does not support.>
```

Rules for the template:
1. One row per finding. A finding with several mappings gets several cells in its row.
2. Keep the framework version in each column header.
3. Add the LLM and ISO 42001 columns only for AI-integrated targets.
4. The "Not evidenced" block is mandatory. Deleting it turns a scoped report into an implied clean bill of health.

## When the user asks "are we compliant?"

The honest answer: this scan evidences technical measures only, and no scanner decides compliance. Name what the scan does not cover:

- Policies and procedures: information security, acceptable use, access control.
- A documented risk assessment and treatment plan, and for ISO certification a Statement of Applicability.
- Records of processing and a lawful basis for each operation (GDPR Art. 30), and impact assessments for high-risk processing (Art. 35).
- Data protection officer duties, consent notices, and data subject rights handling. Under DPDP, consent manager arrangements, notices and Data Principal rights.
- Processor contracts with the required security terms (GDPR Art. 28, DPDP Rule 6(1)(f)).
- A management system with scope, leadership, internal audit and review, and an accredited body for certification.
- Breach response able to meet the 72-hour clocks in GDPR Art. 33 and DPDP Rule 7.
- Training, supplier management, physical security and business continuity.

Suggested wording: "This scan supports the technical measures element of <framework>. It does not decide compliance. Compliance depends on the organizational measures above and on an auditor's assessment."

## Rules for using this file

1. Use only control numbers listed here. Never invent or extend a control, article or rule number.
2. When a needed control is missing, check it against the published standard first. A wrong citation is worse than none.
3. State framework versions: OWASP Top 10:2025, OWASP LLM Top 10 2026, ISO/IEC 27001:2022, ISO/IEC 42001:2023, DPDP Rules 2025.
4. Map conservatively. One well-supported control beats five speculative ones. A reviewer who finds one bad mapping will distrust the whole appendix.

# Switch from MCP Prompts to MCP Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform the Security Audit MCP server from a Prompt-dependent interface into a fully autonomous, Tool-First system featuring `security_audit_orchestrate` (autonomous workflow planning) and `security_audit_slop_check` (AI slop detection tool).

**Architecture:** 
- Expose the audit directive and multi-agent plan generation as a callable MCP tool (`security_audit_orchestrate`) so any AI model can autonomously fetch its audit instructions without requiring human UI slash-command interaction.
- Add an automated `security_audit_slop_check` tool implementing static patterns for the 14 AI failure classes from `references/slop-detection.md`.
- Keep the `/security-audit` prompt as a backwards-compatible bridge.

**Tech Stack:** TypeScript, Node.js (`node:test`, `node:fs`, `node:path`), `@modelcontextprotocol/sdk`, Zod.

---

### Task 1: Create `security_audit_orchestrate` Tool
**Files:**
- Create: `src/tools/orchestrator.ts`
- Modify: `src/tools/index.ts`
- Test: `tests/tools.test.ts`

- [ ] Define `AuditOrchestrateOptions` and `AuditOrchestrateResult` interfaces.
- [ ] Implement `orchestrateAudit` function generating tailored execution directive, active team roster, truth rules, untrusted boundaries, and phase steps.
- [ ] Export `orchestrateAudit` in `src/tools/index.ts`.
- [ ] Add unit test verifying `orchestrateAudit` returns structured plan and directives.

---

### Task 2: Create `security_audit_slop_check` Tool
**Files:**
- Create: `src/tools/slop.ts`
- Modify: `src/tools/index.ts`
- Test: `tests/tools.test.ts`

- [ ] Define `SlopFinding` and `SlopScanResult` interfaces.
- [ ] Implement regex detectors for the 14 slop classes (S01: Phantom security, S02: Placeholder residue, S05: Swallowed errors/empty catch, S06: Fake tests/assert true, S07: Over-broad defaults, S09: Weak crypto, S12: Suppressions).
- [ ] Export `runSlopScan` in `src/tools/index.ts`.
- [ ] Add unit test verifying detection of phantom guards and fake assertions.

---

### Task 3: Register New Tools in MCP Server
**Files:**
- Modify: `src/server.ts`
- Modify: `src/prompts.ts`
- Test: `tests/server.test.ts`

- [ ] Register `security_audit_orchestrate` tool in `createServer()`.
- [ ] Register `security_audit_slop_check` tool in `createServer()`.
- [ ] Update `security-audit` prompt to utilize `orchestrateAudit` internally.
- [ ] Update server test assertions for new tool registrations.

---

### Task 4: Documentation, Build & Push
**Files:**
- Modify: `README.md`

- [ ] Update `README.md` to showcase the Tool-First workflow and document `security_audit_orchestrate` and `security_audit_slop_check`.
- [ ] Run `npm run build` and `npm test` to verify 100% test pass.
- [ ] Commit and push changes to `main`.

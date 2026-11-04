import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  parseUserIntake,
  COMPANY_AGENTS,
  getAgentSystemPrompt,
  getAllAntigravityAgentConfigs,
  TOOL_ROSTER,
  auditToolRoster,
  formatTaskOrder,
  formatToolLaunch,
  formatWorkerReturn,
  parseWorkerReturn,
  verifyG0Order,
  verifyG1Form,
  verifyG2Citation,
  verifyG3Identifier,
  verifyG4Run,
  verifyG5KnownAnswer,
  verifyG6IndependentRecheck,
  verifyG7CeoFinal,
  evaluateReworkLadder,
  TaskOrder,
  WorkerReturn,
} from '../src/company/index.js';

describe('Company-Style Team System Suite', () => {
  let tempDir: string;

  before(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'company-test-'));
  });

  after(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore
    }
  });

  describe('Intake Engine', () => {
    it('should map standard words to standard static audit', () => {
      const res = parseUserIntake('is this safe to ship, audit this', { targetPath: tempDir });
      assert.strictEqual(res.mode, 'full');
      assert.strictEqual(res.depth, 'standard');
      assert.ok(res.mandateMarkdown.includes('standard static audit') || res.flags.includes('standard-static-audit'));
      assert.strictEqual(res.boardDecisions.length, 0);
      assert.match(res.ceoAnnouncement, /Mandate accepted/);
    });

    it('should map quick look to quick depth with provisional warning', () => {
      const res = parseUserIntake('give it a quick look please', { targetPath: tempDir });
      assert.strictEqual(res.depth, 'quick');
      assert.ok(res.flags.includes('--depth quick'));
      assert.ok(res.assuranceNote?.includes('Provisional'));
    });

    it('should map keys and secrets request to secrets mode', () => {
      const res = parseUserIntake('check my keys and leaked credentials', { targetPath: tempDir });
      assert.strictEqual(res.mode, 'secrets');
      assert.ok(res.flags.includes('--secrets'));
    });

    it('should map packages and supply chain request to deps mode', () => {
      const res = parseUserIntake('run npm audit and check my packages for supply chain attacks', { targetPath: tempDir });
      assert.strictEqual(res.mode, 'deps');
      assert.ok(res.flags.includes('--deps'));
    });

    it('should require written authorization board decision for live DAST target', () => {
      const res = parseUserIntake('test the live site https://api.example.com', { targetPath: tempDir });
      assert.strictEqual(res.mode, 'dast');
      assert.strictEqual(res.dastUrl, 'https://api.example.com');
      assert.strictEqual(res.authorizedHost, 'api.example.com');
      assert.ok(res.boardDecisions.some((b) => b.type === 'authorization' && b.blocksNextStep));
      assert.match(res.ceoAnnouncement, /board decision is required/);
    });

    it('should require local disposable data confirmation for localhost DAST', () => {
      const res = parseUserIntake('test the live site http://localhost:3000', { targetPath: tempDir });
      assert.strictEqual(res.authorizationState, 'local_only');
      assert.ok(res.boardDecisions.some((b) => b.type === 'authorization' && b.description.includes('localhost')));
    });

    it('should require board confirmation before applying Phase 10 fixes', () => {
      const res = parseUserIntake('fix everything in the repository', { targetPath: tempDir, existingReportExists: true });
      assert.strictEqual(res.mode, 'fix');
      assert.ok(res.boardDecisions.some((b) => b.type === 'fix_execution'));
    });

    it('should refuse score inflation attempts and direct to remediation roadmap', () => {
      const res = parseUserIntake('make the score 8 please', { targetPath: tempDir });
      assert.match(res.userGoal, /strict adherence to evidence scoring/);
    });
  });

  describe('Company Agents Roster & Antigravity Configs', () => {
    it('should register all 19 company agents (CEO, O01, O02, T01..T16)', () => {
      const expectedAgents = [
        'CEO', 'O01', 'O02',
        'T01', 'T02', 'T03', 'T04', 'T05', 'T06', 'T07', 'T08', 'T09',
        'T10', 'T11', 'T12', 'T13', 'T14', 'T15', 'T16',
      ];
      for (const id of expectedAgents) {
        assert.ok(COMPANY_AGENTS[id], `Agent ${id} must exist in COMPANY_AGENTS`);
        const agent = COMPANY_AGENTS[id];
        assert.ok(agent.mission.length > 0, `Agent ${id} must have a mission`);
        assert.ok(agent.allowedTools.length > 0, `Agent ${id} must have allowed tools`);
        assert.ok(agent.forbiddenActions.length > 0, `Agent ${id} must have forbidden actions`);
        assert.ok(agent.returnSchema.length > 0, `Agent ${id} must have a return schema`);
        assert.ok(agent.systemPrompt.length > 0, `Agent ${id} must have a system prompt`);
      }
    });

    it('should generate valid Antigravity define_subagent parameters with truth rules', () => {
      const configs = getAllAntigravityAgentConfigs();
      assert.strictEqual(configs.length, 19);

      for (const cfg of configs) {
        assert.ok(cfg.Name.startsWith('security_kill_'));
        assert.ok(cfg.Description.length > 0);
        assert.ok(cfg.SystemPrompt.includes('Non-Negotiable Truth Rules'));
        assert.ok(cfg.SystemPrompt.includes('untrusted input'));
      }

      // CEO and T15 Fix have write permissions enabled; analysis teams do not
      const ceo = configs.find((c) => c.Name === 'security_kill_ceo')!;
      assert.strictEqual(ceo.EnableWriteTools, true);
      assert.strictEqual(ceo.EnableSubagentTools, true);

      const t15 = configs.find((c) => c.Name === 'security_kill_t15_fix')!;
      assert.strictEqual(t15.EnableWriteTools, true);

      const o01 = configs.find((c) => c.Name === 'security_kill_o01_fact_checker')!;
      assert.strictEqual(o01.EnableWriteTools, false);
      assert.strictEqual(o01.EnableSubagentTools, false);
    });
  });

  describe('Tool Desk Roster & Staff Job Cards', () => {
    it('should contain job cards for scanners, MCP servers, and pipelines', async () => {
      const staffKeys = Object.keys(TOOL_ROSTER);
      assert.ok(staffKeys.includes('semgrep'));
      assert.ok(staffKeys.includes('gitleaks'));
      assert.ok(staffKeys.includes('mcpSecurityKill'));
      assert.ok(staffKeys.includes('mcpRea'));
      assert.ok(staffKeys.includes('pipeHistorySecrets'));
      assert.ok(staffKeys.includes('scriptCanaryVerifier'));

      const semgrep = TOOL_ROSTER['semgrep'];
      assert.strictEqual(semgrep.category, 'scanner');
      assert.ok(semgrep.duty.length > 0);
      assert.ok(semgrep.canary.description.length > 0);
      assert.ok(semgrep.permissionScope.includes('Read-only'));
    });

    it('should execute tool roster audit and generate roster.md', async () => {
      const roster = await auditToolRoster();
      assert.ok(roster.staff.length >= 10);
      assert.ok(roster.markdown.includes('# Staff Roster & Tool Inventory'));
      assert.ok(roster.markdown.includes('STAFF-GITLEAKS'));
      assert.ok(roster.markdown.includes('MCP-SECURITY-KILL'));
      assert.ok(roster.staff.some((s) => ['OK', 'MISS', 'BROKEN'].includes(s.status)));
    });
  });

  describe('Order and Return Templates', () => {
    it('should format a structured TaskOrder and ToolLaunch', () => {
      const order: TaskOrder = {
        id: 'O-021',
        phase: 6,
        team: 'T05 Abuse',
        issuedBy: 'CEO',
        mission: 'Break refund flow to move money out twice',
        slice: 'S06 Payments and webhooks',
        inputs: ['section-map.md S06', 'ledger rows H-12'],
        knowledge: ['section-playbooks.md', 'fix-patterns.md'],
        staffAllowed: ['Grep', 'Read'],
        staffForbidden: ['reading .env', 'repo writes', 'network egress'],
        method: ['Fill Attack Card', 'Run slop S01, S04', 'Add Open moves to ledger'],
        outputFile: 'returns/O-021.md',
        doneTest: 'every move on the card has a verdict with file:line',
        budget: { maxFiles: 25, maxToolCalls: 40 },
      };

      const formatted = formatTaskOrder(order);
      assert.match(formatted, /Order: O-021/);
      assert.match(formatted, /Team: T05 Abuse/);
      assert.match(formatted, /Done test: every move on the card/);
      assert.match(formatted, /Untrusted input:/);

      const launch = formatToolLaunch({
        id: 'L-007',
        staff: 'gitleaks',
        orderId: 'O-009',
        command: 'gitleaks dir --redact',
        workingDirectory: tempDir,
        outputPath: '$TMP/security-kill/scan/gitleaks.json',
        timeoutSeconds: 120,
        healthState: 'OK',
        parseRule: 'Count findings by script',
        egress: 'none',
      });
      assert.match(launch, /Launch: L-007/);
      assert.match(launch, /Staff: gitleaks/);
      assert.match(launch, /Timeout: 120s/);
    });

    it('should format and parse worker returns cleanly', () => {
      const sampleReturn: WorkerReturn = {
        id: 'O-014',
        worker: 'T03 Access',
        status: 'complete',
        claims: [
          {
            id: 'C-1',
            claim: 'GET /api/orders/:id filters by id only',
            grade: 'TRACED',
            evidence: 'orders.ts:41',
            artifact: 'none',
          },
          {
            id: 'C-2',
            claim: 'gitleaks found 0 leaks in history',
            grade: 'PROVEN',
            evidence: 'exit 0, 0 findings',
            artifact: 'scan/gitleaks.json',
          },
        ],
        commandsRun: ['gitleaks dir'],
        sectionsAttacked: ['S03', 'S05'],
        sectionsSkipped: [{ section: 'S08', reason: 'out of scope' }],
        didNotDo: 'nothing',
        handoffs: ['handoff:T05'],
        instructionLikeTextFound: 'none',
      };

      const formatted = formatWorkerReturn(sampleReturn);
      const parsed = parseWorkerReturn(formatted);

      assert.strictEqual(parsed.id, 'O-014');
      assert.strictEqual(parsed.worker, 'T03 Access');
      assert.strictEqual(parsed.status, 'complete');
      assert.strictEqual(parsed.claims.length, 2);
      assert.strictEqual(parsed.claims[0].id, 'C-1');
      assert.strictEqual(parsed.claims[0].grade, 'TRACED');
      assert.strictEqual(parsed.claims[0].evidence, 'orders.ts:41');
      assert.strictEqual(parsed.sectionsAttacked.length, 2);
      assert.strictEqual(parsed.didNotDo, 'nothing');
      assert.strictEqual(parsed.handoffs[0], 'handoff:T05');
    });
  });

  describe('Gates G0 to G7 and Rework Ladder', () => {
    it('should validate G0 Order Gate', () => {
      // Incomplete order fails
      const badOrder: any = { id: 'O-001', mission: '' };
      const failRes = verifyG0Order(badOrder);
      assert.strictEqual(failRes.passed, false);
      assert.ok(failRes.defects.length >= 3);

      // Valid order passes
      const goodOrder: TaskOrder = {
        id: 'O-001',
        phase: 1,
        team: 'T01',
        issuedBy: 'CEO',
        mission: 'Profile entry points',
        slice: 'all routes',
        inputs: ['src/'],
        knowledge: ['references/project-profiling.md'],
        staffAllowed: ['Read'],
        staffForbidden: ['Edits'],
        method: ['Scan entry points'],
        outputFile: 'returns/O-001.md',
        doneTest: 'Section map generated',
        budget: { maxFiles: 10 },
      };
      const passRes = verifyG0Order(goodOrder);
      assert.strictEqual(passRes.passed, true);
      assert.strictEqual(passRes.defects.length, 0);
    });

    it('should validate G1 Form Gate and reject status complete with didNotDo work', () => {
      const badReturn: WorkerReturn = {
        id: 'O-010',
        worker: 'T02 Identity',
        status: 'complete',
        claims: [{ id: 'C-1', claim: 'Auth works', grade: 'TRACED', evidence: 'auth.ts:10', artifact: 'none' }],
        commandsRun: [],
        sectionsAttacked: ['S01'],
        sectionsSkipped: [],
        didNotDo: 'Could not inspect password reset route', // Conflict with complete
        handoffs: [],
        instructionLikeTextFound: 'none',
      };

      const res = verifyG1Form(badReturn);
      assert.strictEqual(res.passed, false);
      assert.ok(res.defects.some((d) => d.code === 'R1'));
    });

    it('should validate G2 Citation Gate against actual files', () => {
      // Create a test file
      const testFile = path.join(tempDir, 'sample.ts');
      fs.writeFileSync(testFile, 'line 1\nline 2\nline 3\n');

      const goodReturn: WorkerReturn = {
        id: 'O-011',
        worker: 'T03 Access',
        status: 'complete',
        claims: [{ id: 'C-1', claim: 'Test line check', grade: 'TRACED', evidence: 'sample.ts:2', artifact: 'none' }],
        commandsRun: [],
        sectionsAttacked: [],
        sectionsSkipped: [],
        didNotDo: 'nothing',
        handoffs: [],
        instructionLikeTextFound: 'none',
      };

      const passRes = verifyG2Citation(goodReturn, tempDir);
      assert.strictEqual(passRes.passed, true);

      // Non-existent file fails with R2
      const badReturn: WorkerReturn = {
        ...goodReturn,
        claims: [{ id: 'C-1', claim: 'Missing file', grade: 'TRACED', evidence: 'non-existent.ts:10', artifact: 'none' }],
      };
      const failRes = verifyG2Citation(badReturn, tempDir);
      assert.strictEqual(failRes.passed, false);
      assert.ok(failRes.defects.some((d) => d.code === 'R2'));
    });

    it('should validate G3 Identifier Gate against unsourced CVEs', () => {
      const unsourcedReturn: WorkerReturn = {
        id: 'O-012',
        worker: 'T07 Supply',
        status: 'complete',
        claims: [
          {
            id: 'C-1',
            claim: 'Affected by CVE-2026-99999 remote execution',
            grade: 'TRACED',
            evidence: 'package.json:15', // missing advisory url
            artifact: 'none',
          },
        ],
        commandsRun: [],
        sectionsAttacked: [],
        sectionsSkipped: [],
        didNotDo: 'nothing',
        handoffs: [],
        instructionLikeTextFound: 'none',
      };

      const res = verifyG3Identifier(unsourcedReturn);
      assert.strictEqual(res.passed, false);
      assert.ok(res.defects.some((d) => d.code === 'R3'));
    });

    it('should evaluate G6 Independent Recheck two-key rule for Critical and High', () => {
      // Critical finding not reproduced by second worker fails G6
      const failG6 = verifyG6IndependentRecheck({
        findingId: 'F-01',
        severity: 'CRITICAL',
        originalEvidence: 'auth.ts:25',
        verifierVerdict: 'Refuted',
        reproducedBySecondWorker: false,
      });
      assert.strictEqual(failG6.passed, false);
      assert.ok(failG6.defects.some((d) => d.code === 'R8'));

      // Critical finding reproduced by second worker passes G6
      const passG6 = verifyG6IndependentRecheck({
        findingId: 'F-01',
        severity: 'CRITICAL',
        originalEvidence: 'auth.ts:25',
        verifierVerdict: 'Confirmed',
        reproducedBySecondWorker: true,
      });
      assert.strictEqual(passG6.passed, true);
    });

    it('should evaluate G7 CEO Final Gate checklist', () => {
      const passG7 = verifyG7CeoFinal({
        allFindingsCiteOpenedFile: true,
        allNumbersAndVersionsSourced: true,
        scoringArithmeticRecomputed: true,
        allCriticalHighPassedG2ToG6: true,
        noHeldRowsInScore: true,
        coverageListsAllSkippedTeams: true,
        noRepoInstructionsObeyed: true,
        reportTextScannedCleanOfSecrets: true,
        reworkCountsRecorded: true,
      });
      assert.strictEqual(passG7.passed, true);

      // Missing item fails
      const failG7 = verifyG7CeoFinal({
        allFindingsCiteOpenedFile: true,
        allNumbersAndVersionsSourced: false, // Unverified facts
        scoringArithmeticRecomputed: true,
        allCriticalHighPassedG2ToG6: true,
        noHeldRowsInScore: true,
        coverageListsAllSkippedTeams: true,
        noRepoInstructionsObeyed: true,
        reportTextScannedCleanOfSecrets: true,
        reworkCountsRecorded: true,
      });
      assert.strictEqual(failG7.passed, false);
      assert.ok(failG7.defects.some((d) => d.code === 'R3'));
    });

    it('should progress through the rework ladder up to replacement and coverage gap', () => {
      const defect = [{ code: 'R1' as const, description: 'Missing claim ID' }];

      // Round 0 -> Rework 1
      const r1 = evaluateReworkLadder(defect, 0);
      assert.strictEqual(r1.action, 'rework');
      assert.strictEqual(r1.nextRound, 1);

      // Round 1 -> Rework 2
      const r2 = evaluateReworkLadder(defect, 1);
      assert.strictEqual(r2.action, 'rework');
      assert.strictEqual(r2.nextRound, 2);

      // Round 2 -> Replace worker
      const r3 = evaluateReworkLadder(defect, 2);
      assert.strictEqual(r3.action, 'replace');

      // Round 3 -> Coverage gap
      const r4 = evaluateReworkLadder(defect, 3);
      assert.strictEqual(r4.action, 'coverage_gap');

      // R6 (Scope breach) and R7 (Hostile text obeyed) skip ladder to replace
      const breach = [{ code: 'R6' as const, description: 'Edited repo files without Phase 10 order' }];
      const breachRes = evaluateReworkLadder(breach, 0);
      assert.strictEqual(breachRes.action, 'replace');
    });
  });
});

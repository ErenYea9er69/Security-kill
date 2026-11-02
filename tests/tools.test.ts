import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { redactSecret, scanSecrets } from '../src/tools/secrets.js';
import { runSectionMap } from '../src/tools/sectionMap.js';
import { runPreflight } from '../src/tools/preflight.js';
import { generateAuditReport } from '../src/tools/reporter.js';
import { calculateSecurityScore } from '../src/tools/scoring.js';
import { orchestrateAudit } from '../src/tools/orchestrator.js';
import { runSlopScan } from '../src/tools/slop.js';

describe('Security Tools Suite', () => {
  let tempDir: string;

  before(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-test-'));
  });

  after(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  });

  describe('Autonomous Audit Orchestrator Tool', () => {
    it('should generate an autonomous audit execution plan and directives', async () => {
      const plan = await orchestrateAudit({
        targetPath: tempDir,
        mode: 'quick',
        depth: 'standard',
        domain: 'fintech',
      });

      assert.ok(plan);
      assert.strictEqual(plan.mode, 'quick');
      assert.strictEqual(plan.depth, 'standard');
      assert.strictEqual(plan.domain, 'fintech');
      assert.ok(plan.executionPhases.length >= 10);
      assert.ok(plan.truthRules.length >= 5);
      assert.match(plan.directive, /Autonomous Security Audit Directive/);
      assert.ok(plan.executionPhases.some((p) => p.name.includes('Tool Inventory')));
    });
  });

  describe('AI Slop & Fake Test Checker Tool', () => {
    it('should detect phantom guards, empty catches, and fake assertions', async () => {
      const slopDir = path.join(tempDir, 'slop-test');
      fs.mkdirSync(slopDir);

      // Create a file with phantom guard and swallowed error
      fs.writeFileSync(
        path.join(slopDir, 'guard.js'),
        `
function sanitizeInput(data) {
  return data;
}

try {
  verifyToken();
} catch {}
        `,
        'utf-8'
      );

      // Create a test file with assertion theater
      fs.writeFileSync(
        path.join(slopDir, 'auth.test.js'),
        `
test('admin access test', () => {
  expect(true).toBe(true);
});
        `,
        'utf-8'
      );

      const result = await runSlopScan(slopDir);
      assert.ok(result.leads.length >= 3);
      assert.ok(result.leads.some((l) => l.classId === 'S01'));
      assert.ok(result.leads.some((l) => l.classId === 'S05'));
      assert.ok(result.leads.some((l) => l.classId === 'S06'));
    });
  });

  describe('Secret Redaction & Scanning', () => {
    it('should strictly redact secrets to first 4 chars', () => {
      // Construct dynamically so static regex push protection won't trip
      const awsKey = ['AKIA', 'TEST', '1234', '5678', '90AB'].join('');
      const redactedAws = redactSecret(awsKey);
      assert.strictEqual(redactedAws, 'AKIA...');
      assert.ok(!redactedAws.includes('90AB'));

      const stripeKey = ['sk', 'live', 'sampleMockToken999999999'].join('_');
      const redactedStripe = redactSecret(stripeKey);
      assert.strictEqual(redactedStripe, 'sk_l...');
      assert.ok(!redactedStripe.includes('sampleMockToken'));
    });

    it('should detect and redact secrets without writing plain secret to result', async () => {
      const testFile = path.join(tempDir, 'config.js');
      const mockKey = ['AKIA', '1234', '5678', '90AB', 'CDEF'].join('');
      fs.writeFileSync(
        testFile,
        `// Config\nconst AWS_KEY = "${mockKey}";\nconst other = 123;\n`,
        'utf-8'
      );

      const results = await scanSecrets(tempDir);
      assert.ok(results.findings.length > 0);
      const hit = results.findings[0];
      assert.strictEqual(hit.type, 'AWS Access Key');
      assert.strictEqual(hit.redacted, 'AKIA...');
      assert.ok(!hit.snippet.includes('1234567890ABCDEF'));
    });
  });

  describe('Section Mapping & Project Profiling', () => {
    it('should analyze project structure, assign teams, and detect domain', async () => {
      const mockProject = path.join(tempDir, 'proj');
      fs.mkdirSync(mockProject);
      fs.writeFileSync(
        path.join(mockProject, 'package.json'),
        JSON.stringify({
          name: 'mock-app',
          dependencies: { '@supabase/supabase-js': '^2.0.0', 'express': '^4.18.0', 'stripe': '^12.0.0' },
        })
      );
      fs.mkdirSync(path.join(mockProject, 'src'));
      fs.writeFileSync(
        path.join(mockProject, 'src', 'auth.ts'),
        'export function login() {}'
      );

      const map = await runSectionMap(mockProject);
      assert.ok(map.languages.includes('JavaScript/TypeScript'));
      assert.ok(map.backendPlatforms.includes('Supabase'));
      assert.strictEqual(map.domain, 'Payments and Fintech');
      assert.ok(map.sections.some((s) => s.ownerTeam === 'T02' && s.name.includes('Authentication')));
      assert.ok(map.sections.some((s) => s.ownerTeam === 'T05' && s.name.includes('Payments')));
      assert.ok(map.activeRoster.some((r) => r.id === 'T05'));
    });
  });

  describe('Preflight Tool Check', () => {
    it('should check tool inventory and return structured OK/MISS states', async () => {
      const inventory = await runPreflight({ runCanary: false });
      assert.ok(Array.isArray(inventory.tools));
      assert.ok(inventory.tools.some((t) => t.tool === 'semgrep'));
      assert.ok(inventory.tools.some((t) => t.tool === 'gitleaks'));
      assert.ok(['OK', 'MISS', 'BROKEN'].includes(inventory.tools[0].status));
    });
  });

  describe('Mathematical Scoring Engine', () => {
    it('should reproduce the worked example from references/scoring.md', () => {
      const result = calculateSecurityScore({
        findings: [
          {
            id: 'F-01',
            team: 'T03',
            severity: 'CRITICAL',
            evidence: 'PROVEN',
            reach: 'authenticated',
            asset: 'personal_data',
            rootCauseGroup: 'authz-root',
          },
          {
            id: 'F-02',
            team: 'T03',
            severity: 'HIGH',
            evidence: 'PROVEN',
            reach: 'authenticated',
            asset: 'personal_data',
            rootCauseGroup: 'authz-root',
          },
          {
            id: 'F-03',
            team: 'T02',
            severity: 'HIGH',
            evidence: 'TRACED',
            reach: 'anonymous',
            asset: 'money_credentials_rce_db',
          },
          {
            id: 'F-04',
            team: 'T04',
            severity: 'MEDIUM',
            evidence: 'PROVEN',
            reach: 'authenticated',
            asset: 'low_value',
          },
          {
            id: 'F-05',
            team: 'T07',
            severity: 'MEDIUM',
            evidence: 'TRACED',
            reach: 'anonymous',
            asset: 'low_value',
          },
          {
            id: 'F-06',
            team: 'T08',
            severity: 'LOW',
            evidence: 'PROVEN',
            reach: 'anonymous',
            asset: 'low_value',
          },
        ],
        coverage: {
          completedSectionsWeight: 8,
          totalSectionsWeight: 10,
          resolvedHypotheses: 3,
          totalHypotheses: 4,
          passingTools: 9,
          totalApplicableTools: 10,
          verifiedCriticalHigh: 3,
          totalCriticalHigh: 3,
        },
      });

      // Team scores: T03 6.4, T02 8.0, T04 9.6, T07 9.6, T08 9.9
      assert.strictEqual(result.teamScores['T03'], 6.4);
      assert.strictEqual(result.teamScores['T02'], 8.0);
      assert.strictEqual(result.teamScores['T04'], 9.6);
      assert.strictEqual(result.teamScores['T07'], 9.6);
      assert.strictEqual(result.teamScores['T08'], 9.9);

      // Binding cap: PROVEN Critical (F-01) caps at 4.0
      assert.strictEqual(result.overallScore, 4.0);
      assert.strictEqual(result.band, 'Weak');
      assert.strictEqual(result.assurance.level, 'High');
      assert.strictEqual(result.assurance.score, 84);
      assert.ok(result.bindingCap?.includes('PROVEN Critical (F-01)'));

      // Path to target score exists
      assert.ok(result.pathToTarget.length >= 2);
    });
  });

  describe('Report Generator', () => {
    it('should generate standardized SECURITY-AUDIT-YYYY-MM-DD.md with scorecard and update .gitignore', async () => {
      const repDir = path.join(tempDir, 'rep-proj');
      fs.mkdirSync(repDir);
      fs.writeFileSync(path.join(repDir, '.gitignore'), 'node_modules/\n');

      const reportResult = await generateAuditReport({
        targetPath: repDir,
        projectName: 'Test Project',
        depthTier: 'standard',
        verdict: 'Not safe to ship. High risk of data exposure.',
        scorecard: {
          securityScore: 4.0,
          band: 'Weak',
          assuranceLevel: 'High',
          assuranceNumber: 84,
          ceiling: 9.5,
          slopScore: 8.5,
          bindingCap: 'PROVEN Critical (F-01)',
          teamScores: { T02: 8.0, T03: 6.4 },
        },
        sectionHeatMap: [
          { id: 'S01', name: 'Identity', ownerTeam: 'T02', score: 8.0 },
          { id: 'S02', name: 'Access', ownerTeam: 'T03', score: 6.4, topFinding: 'F-01' },
        ],
        attackPaths: ['Attacker accesses unprotected Supabase table.'],
        findings: [
          {
            id: 'F-01',
            severity: 'CRITICAL',
            title: 'Missing Row Level Security on orders table',
            where: 'supabase/migrations/001.sql:10',
            team: 'T03',
            attacker: 'Anonymous client',
            evidence: 'PROVEN',
            owasp: 'A01:2025 Broken Access Control',
            what: 'Orders table has no RLS enabled, allowing public read and write.',
            exploit: 'curl https://supabase.co/rest/v1/orders returns all tenant records.',
            fix: 'ALTER TABLE orders ENABLE ROW LEVEL SECURITY;',
            regressionTest: 'tests/orders_rls.test.sql',
            siblings: 0,
            penalty: '3.2',
          },
        ],
        slopFindings: [
          {
            id: 'SLOP-01',
            classId: 'S01',
            title: 'Phantom sanitizer in auth route',
            where: 'src/auth.ts:25',
            team: 'T02',
            description: 'Function sanitizeUser returns raw input without escaping.',
          },
        ],
        notFindings: ['Reviewed JWT decoding, verification is present.'],
        notVerified: ['Rate limiting on login endpoint not proven due to no live server.'],
        coverage: {
          roster: ['T01', 'T02', 'T03', 'T09', 'T13'],
          sectionsAttacked: ['Auth', 'Database'],
          sectionsSkipped: ['Payments'],
          toolsRun: ['Semgrep (OK)', 'Gitleaks (OK)'],
        },
      });

      assert.ok(fs.existsSync(reportResult.reportPath));
      const content = fs.readFileSync(reportResult.reportPath, 'utf-8');
      assert.match(content, /# Security Audit: Test Project/);
      assert.match(content, /## Scorecard/);
      assert.match(content, /Security score: 4\.0 \/ 10/);
      assert.match(content, /## Verdict/);
      assert.match(content, /## Section heat map/);
      assert.match(content, /## Attack paths/);
      assert.match(content, /\[CRITICAL\] F-01 Missing Row Level Security/);
      assert.match(content, /## Slop findings/);
      assert.match(content, /\[S01\] SLOP-01/);
      assert.match(content, /## Limitations/);

      // Verify .gitignore was updated
      const gitignore = fs.readFileSync(path.join(repDir, '.gitignore'), 'utf-8');
      assert.match(gitignore, /SECURITY-AUDIT-\*\.md/);
    });
  });
});

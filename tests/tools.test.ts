import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { redactSecret, scanSecrets } from '../src/tools/secrets.js';
import { runSectionMap } from '../src/tools/sectionMap.js';
import { runPreflight } from '../src/tools/preflight.js';
import { generateAuditReport } from '../src/tools/reporter.js';

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

  describe('Section Mapping', () => {
    it('should analyze project structure and detect manifest & entrypoints', async () => {
      const mockProject = path.join(tempDir, 'proj');
      fs.mkdirSync(mockProject);
      fs.writeFileSync(
        path.join(mockProject, 'package.json'),
        JSON.stringify({
          name: 'mock-app',
          dependencies: { '@supabase/supabase-js': '^2.0.0', 'express': '^4.18.0' },
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
      assert.ok(map.sections.some((s) => s.name === 'Authentication & Authorization'));
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

  describe('Report Generator', () => {
    it('should generate standardized SECURITY-AUDIT-YYYY-MM-DD.md and update .gitignore', async () => {
      const repDir = path.join(tempDir, 'rep-proj');
      fs.mkdirSync(repDir);
      fs.writeFileSync(path.join(repDir, '.gitignore'), 'node_modules/\n');

      const reportResult = await generateAuditReport({
        targetPath: repDir,
        projectName: 'Test Project',
        verdict: 'Not safe to ship. High risk of data exposure.',
        attackPaths: ['Attacker accesses unprotected Supabase table.'],
        findings: [
          {
            id: 'F-01',
            severity: 'CRITICAL',
            title: 'Missing Row Level Security on orders table',
            where: 'supabase/migrations/001.sql:10',
            attacker: 'Anonymous client',
            evidence: 'PROVEN',
            owasp: 'A01:2025 Broken Access Control',
            what: 'Orders table has no RLS enabled, allowing public read and write.',
            exploit: 'curl https://supabase.co/rest/v1/orders returns all tenant records.',
            fix: 'ALTER TABLE orders ENABLE ROW LEVEL SECURITY;',
            regressionTest: 'tests/orders_rls.test.sql',
          },
        ],
        notFindings: ['Reviewed JWT decoding, verification is present.'],
        notVerified: ['Rate limiting on login endpoint not proven due to no live server.'],
        coverage: {
          sectionsAttacked: ['Auth', 'Database'],
          sectionsSkipped: ['Payments'],
          toolsRun: ['Semgrep (OK)', 'Gitleaks (OK)'],
        },
      });

      assert.ok(fs.existsSync(reportResult.reportPath));
      const content = fs.readFileSync(reportResult.reportPath, 'utf-8');
      assert.match(content, /# Security Audit: Test Project/);
      assert.match(content, /## Verdict/);
      assert.match(content, /## Attack paths/);
      assert.match(content, /\[CRITICAL\] F-01 Missing Row Level Security/);
      assert.match(content, /## Limitations/);

      // Verify .gitignore was updated
      const gitignore = fs.readFileSync(path.join(repDir, '.gitignore'), 'utf-8');
      assert.match(gitignore, /SECURITY-AUDIT-\*\.md/);
    });
  });
});

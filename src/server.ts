import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import {
  listReferences,
  getReferenceContent,
  getSkillContent,
  getAllReferenceResources,
} from './resources.js';
import {
  runPreflight,
  runSectionMap,
  scanSecrets,
  runSastScan,
  runDepsScan,
  generateAuditReport,
} from './tools/index.js';
import { generateAuditPromptContent } from './prompts.js';

/**
 * Creates and configures the Security Audit MCP server instance.
 */
export function createServer(): McpServer {
  const server = new McpServer({
    name: 'security-audit-mcp',
    version: '1.0.0',
  });

  // ==========================================
  // 1. Prompts (/security-audit)
  // ==========================================
  server.prompt(
    'security-audit',
    'Execute an evidence-based security audit following the 11-phase attacker simulation methodology',
    {
      target_path: z.string().optional().describe('Target repository or folder path (defaults to current directory)'),
      mode: z.string().optional().describe('Audit mode: full (default), quick, secrets, code, deps, config, attack, llm, dast, fix, retest'),
      compliance: z.boolean().optional().describe('Whether to generate compliance mapping appendix (SOC2, ISO 27001, HIPAA, PCI-DSS)'),
      diff: z.boolean().optional().describe('Audit only changed files against the base branch'),
    },
    (args) => generateAuditPromptContent(args)
  );

  // ==========================================
  // 2. Resources (security://...)
  // ==========================================
  server.resource(
    'security-skill',
    'security://skill',
    {
      description: 'The master security audit 11-phase workflow, truth rules, and triage guidelines',
      mimeType: 'text/markdown',
    },
    async (uri) => ({
      contents: [
        {
          uri: uri.href,
          text: getSkillContent() || '# Security Audit Skill\n(File not found)',
          mimeType: 'text/markdown',
        },
      ],
    })
  );

  for (const ref of listReferences()) {
    server.resource(
      `reference-${ref}`,
      `security://reference/${ref}`,
      {
        description: `Security audit reference guide: ${ref}`,
        mimeType: 'text/markdown',
      },
      async (uri) => ({
        contents: [
          {
            uri: uri.href,
            text: getReferenceContent(ref) || `# Reference: ${ref}\n(Content unavailable)`,
            mimeType: 'text/markdown',
          },
        ],
      })
    );
  }

  // ==========================================
  // 3. Tools
  // ==========================================

  // Tool: Preflight Check
  server.tool(
    'security_audit_preflight',
    'Checks availability of CLI security scanners (Semgrep, Gitleaks, TruffleHog, Trivy, OSV-Scanner, etc.) and tests with synthetic canaries',
    {
      runCanary: z.boolean().optional().describe('Run synthetic canary tests against present scanners (Phase 1 preflight)'),
    },
    async ({ runCanary }) => {
      const result = await runPreflight({ runCanary });
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  // Tool: Section Map (Phase 0)
  server.tool(
    'security_audit_section_map',
    'Discovers entry points, frameworks, BaaS (Supabase/Firebase), and maps codebase sections with blast-radius rankings',
    {
      targetPath: z.string().default('.').describe('Root path of the repository to map'),
    },
    async ({ targetPath }) => {
      const result = await runSectionMap(targetPath);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  // Tool: Secret Scanner (Phase 2)
  server.tool(
    'security_audit_scan_secrets',
    'Scans repository for exposed API keys, private keys, and tokens with strict mandatory redaction',
    {
      targetPath: z.string().default('.').describe('Directory path to scan for secrets'),
      scanGitHistory: z.boolean().optional().describe('Whether to scan full git history via gitleaks if available'),
      scanBundles: z.boolean().optional().describe('Whether to specifically scan compiled bundles in dist/, build/, .next/'),
    },
    async ({ targetPath, scanGitHistory, scanBundles }) => {
      const result = await scanSecrets(targetPath, { scanGitHistory, scanBundles });
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  // Tool: SAST Scanner (Phase 3)
  server.tool(
    'security_audit_sast',
    'Executes static analysis for code injection, unsafe execution, and dangerous patterns using Semgrep or built-in rules',
    {
      targetPath: z.string().default('.').describe('Path to source code folder'),
      config: z.string().optional().describe('Semgrep ruleset config (defaults to p/security-audit)'),
    },
    async ({ targetPath, config }) => {
      const result = await runSastScan(targetPath, { config });
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  // Tool: Dependency / Supply Chain Scanner (Phase 4)
  server.tool(
    'security_audit_scan_deps',
    'Audits dependencies for known vulnerabilities and CVE advisories',
    {
      targetPath: z.string().default('.').describe('Directory containing manifest files (package.json, requirements.txt, etc.)'),
    },
    async ({ targetPath }) => {
      const result = await runDepsScan(targetPath);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  // Tool: Reference Fetcher
  server.tool(
    'security_audit_get_reference',
    'Retrieves any of the 17 security playbooks and checklists (vibecoding-checklist, attacker-simulation, baas-supabase-firebase, etc.)',
    {
      name: z.string().describe('Reference playbook name without .md (e.g. vibecoding-checklist, section-playbooks)'),
    },
    async ({ name }) => {
      const content = getReferenceContent(name);
      if (!content) {
        return {
          content: [{ type: 'text', text: `Reference '${name}' not found. Available: ${listReferences().join(', ')}` }],
          isError: true,
        };
      }
      return {
        content: [{ type: 'text', text: content }],
      };
    }
  );

  // Tool: Report Generator (Phase 9)
  server.tool(
    'security_audit_generate_report',
    'Generates and saves the standardized, evidence-graded SECURITY-AUDIT-YYYY-MM-DD.md report and updates .gitignore',
    {
      targetPath: z.string().describe('Target repository folder where report will be created'),
      projectName: z.string().optional().describe('Display name of project'),
      verdict: z.string().describe('Overall verdict (safe to ship or not, and immediate priority)'),
      attackPaths: z.array(z.string()).default([]).describe('Numbered chains of steps from attacker to high-value assets'),
      findings: z.array(
        z.object({
          id: z.string().describe('e.g. F-01'),
          severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
          title: z.string(),
          where: z.string().describe('file:line path'),
          attacker: z.string().describe('Attacker profile (e.g. anonymous client, low-privilege user)'),
          evidence: z.enum(['PROVEN', 'TRACED', 'LEAD', 'DISPUTED']),
          owasp: z.string().describe('OWASP category, e.g. A01:2025 Broken Access Control'),
          what: z.string().describe('Description of the vulnerability'),
          exploit: z.string().describe('Concrete request or action and resulting impact'),
          fix: z.string().describe('Root-cause remediation step or snippet'),
          regressionTest: z.string().describe('Name or path of reproduction test'),
        })
      ).default([]),
      notFindings: z.array(z.string()).optional().describe('Leads investigated and dismissed with reasons'),
      notVerified: z.array(z.string()).optional().describe('Hypotheses with missing proof steps'),
      coverage: z.object({
        sectionsAttacked: z.array(z.string()),
        sectionsSkipped: z.array(z.string()),
        toolsRun: z.array(z.string()),
      }),
      complianceAppendix: z.string().optional().describe('Optional compliance mapping appendix text'),
    },
    async (args) => {
      const result = await generateAuditReport(args);
      return {
        content: [
          {
            type: 'text',
            text: `Report successfully written to ${result.reportPath}\n\nSummary:\n- Date: ${result.date}\n- Findings: ${args.findings.length}\n- Added to .gitignore`,
          },
        ],
      };
    }
  );

  return server;
}


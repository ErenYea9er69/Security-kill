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
  calculateSecurityScore,
  generateAuditReport,
  orchestrateAudit,
  runSlopScan,
} from './tools/index.js';
import { generateAuditPromptContent } from './prompts.js';

/**
 * Creates and configures the Security Audit MCP server instance.
 */
export function createServer(): McpServer {
  const server = new McpServer({
    name: 'security-kill-mcp',
    version: '1.0.0',
  });

  // ==========================================
  // 1. Prompts (Slash command / prompt support)
  // ==========================================
  server.prompt(
    'security-kill',
    'Execute an evidence-based security audit using 16 specialist teams, attacker simulation, and 0-10 scoring',
    {
      target_path: z.string().optional().describe('Target repository or folder path (defaults to current directory)'),
      mode: z.string().optional().describe('Audit mode: full (default), quick, secrets, code, deps, config, attack, slop, llm, dast, score-only, fix, retest'),
      depth: z.enum(['quick', 'standard', 'deep']).optional().describe('Depth tier: quick (triage), standard (default), deep (full proofs & mutation)'),
      domain: z.string().optional().describe('Domain focus (e.g. payments, health, saas, ecommerce, ai)'),
      teams: z.string().optional().describe('Specific team IDs to run, comma-separated (e.g. T02,T03,T09)'),
      compliance: z.boolean().optional().describe('Whether to generate compliance mapping appendix (SOC2, ISO 27001, HIPAA, PCI-DSS)'),
      diff: z.boolean().optional().describe('Audit only changed files against the base branch'),
    },
    (args) => generateAuditPromptContent(args)
  );

  // ==========================================
  // 2. Resources (security-kill://...)
  // ==========================================
  server.resource(
    'security-kill-skill',
    'security-kill://skill',
    {
      description: 'The master security audit 12-phase workflow, truth rules, and team cards',
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
      `security-kill://reference/${ref}`,
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

  // Tool: Orchestrate / Plan Audit (Tool-first autonomous entry point)
  server.tool(
    'security_kill_orchestrate',
    'Generates a complete, tailored 12-phase security audit execution plan, specialist team assignments, truth rules, and recommended tool sequence',
    {
      targetPath: z.string().default('.').describe('Root path of the repository to audit'),
      mode: z.string().default('full').describe('Audit mode: full, quick, secrets, code, deps, config, attack, slop, llm, dast, score-only, fix, retest'),
      depth: z.enum(['quick', 'standard', 'deep']).default('standard').describe('Depth tier: quick, standard, or deep'),
      domain: z.string().optional().describe('Optional domain override (payments, health, saas, ecommerce, ai)'),
      compliance: z.boolean().optional().describe('Enable compliance evidence mapping'),
      diff: z.boolean().optional().describe('Scope audit to git diff against base branch'),
    },
    async (args) => {
      const result = await orchestrateAudit(args);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  // Tool: Preflight Check
  server.tool(
    'security_kill_preflight',
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

  // Tool: Section Map & Project Profiling (Phase 0)
  server.tool(
    'security_kill_section_map',
    'Discovers entry points, frameworks, BaaS (Supabase/Firebase), domains, and maps sections with owner teams (T01-T13)',
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

  // Tool: Secret Scanner (Phase 2, Team T09)
  server.tool(
    'security_kill_scan_secrets',
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

  // Tool: SAST Scanner (Phase 3, Team T04)
  server.tool(
    'security_kill_sast',
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

  // Tool: Dependency / Supply Chain Scanner (Phase 4, Team T07)
  server.tool(
    'security_kill_scan_deps',
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

  // Tool: AI Slop & Fake Test Checker (Phase 6d, Team T13 Slop Hunters)
  server.tool(
    'security_kill_slop_check',
    'Sweeps codebase for the 14 AI failure classes (S01-S14) in references/slop-detection.md (phantom guards, placeholder residue, empty catches, fake assertions, weak crypto)',
    {
      targetPath: z.string().default('.').describe('Directory path of the project to scan for slop'),
    },
    async ({ targetPath }) => {
      const result = await runSlopScan(targetPath);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  // Tool: Scoring Engine (Phase 9, Team T16 Scorekeeper)
  server.tool(
    'security_kill_calculate_score',
    'Computes the mathematical 0-10 security score, binding caps, assurance ceiling, team scores, slop score, and path to target score',
    {
      findings: z.array(
        z.object({
          id: z.string().describe('Finding ID, e.g. F-01'),
          team: z.string().describe('Owning team ID, e.g. T02, T03'),
          severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
          evidence: z.enum(['PROVEN', 'TRACED', 'LEAD', 'DISPUTED']),
          reach: z.enum(['anonymous', 'authenticated', 'privileged']),
          asset: z.enum(['money_credentials_rce_db', 'personal_data', 'low_value']),
          rootCauseGroup: z.string().optional().describe('Identifier to group sibling findings with shared root cause'),
          isReachableWithoutLogin: z.boolean().optional(),
        })
      ).describe('Array of triaged findings to score'),
      slopFindings: z.array(
        z.object({
          id: z.string(),
          classId: z.string().describe('S01..S14'),
          severity: z.enum(['HIGH', 'MEDIUM', 'LOW']),
          rootCauseGroup: z.string().optional(),
        })
      ).optional().describe('Confirmed AI slop patterns'),
      activeTeams: z.array(
        z.object({
          id: z.string(),
          name: z.string(),
          weight: z.number(),
        })
      ).optional().describe('Active teams and their respective weights'),
      coverage: z.object({
        completedSectionsWeight: z.number().optional(),
        totalSectionsWeight: z.number().optional(),
        resolvedHypotheses: z.number().optional(),
        totalHypotheses: z.number().optional(),
        passingTools: z.number().optional(),
        totalApplicableTools: z.number().optional(),
        verifiedCriticalHigh: z.number().optional(),
        totalCriticalHigh: z.number().optional(),
      }).optional().describe('Coverage and assurance parameters'),
      hasLiveCredential: z.boolean().optional().describe('Whether an active, unredacted credential was found'),
    },
    async (args) => {
      const result = calculateSecurityScore(args);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  // Tool: Reference Fetcher
  server.tool(
    'security_kill_get_reference',
    'Retrieves any of the 23 security playbooks, team cards, or guides (teams, scoring, slop-detection, stack-packs, etc.)',
    {
      name: z.string().describe('Reference playbook name without .md (e.g. teams, scoring, slop-detection, project-profiling)'),
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

  // Tool: Report Generator (Phase 9, Team T16 Scorekeeper)
  server.tool(
    'security_kill_generate_report',
    'Generates and saves the standardized, evidence-graded SECURITY-KILL-YYYY-MM-DD.md report and updates .gitignore',
    {
      targetPath: z.string().describe('Target repository folder where report will be created'),
      projectName: z.string().optional().describe('Display name of project'),
      depthTier: z.enum(['quick', 'standard', 'deep']).optional().describe('Depth tier used for this audit'),
      verdict: z.string().describe('Overall verdict (safe to ship or not, and immediate priority)'),
      scorecard: z.object({
        securityScore: z.number(),
        band: z.string(),
        assuranceLevel: z.string(),
        assuranceNumber: z.number(),
        ceiling: z.number(),
        slopScore: z.number(),
        bindingCap: z.string().nullable().optional(),
        teamScores: z.record(z.string(), z.number()).optional(),
        weightsChanged: z.string().optional(),
        status: z.string().optional(),
      }).optional().describe('Scorecard computed via security_kill_calculate_score'),
      pathToBetterScore: z.array(
        z.object({
          ifYouFix: z.string(),
          scoreBecomes: z.number(),
          whyItMoves: z.string(),
        })
      ).optional().describe('Roadmap of fixes and resulting scores'),
      sectionHeatMap: z.array(
        z.object({
          id: z.string(),
          name: z.string(),
          ownerTeam: z.string(),
          score: z.number(),
          topFinding: z.string().optional(),
        })
      ).optional().describe('Section-by-section score summary'),
      attackPaths: z.array(z.string()).default([]).describe('Numbered chains of steps from attacker to high-value assets'),
      findings: z.array(
        z.object({
          id: z.string().describe('e.g. F-01'),
          severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
          title: z.string(),
          where: z.string().describe('file:line path'),
          attacker: z.string().describe('Attacker profile (e.g. anonymous client, low-privilege user)'),
          team: z.string().optional().describe('Owning team ID, e.g. T03'),
          evidence: z.enum(['PROVEN', 'TRACED', 'LEAD', 'DISPUTED']),
          owasp: z.string().describe('OWASP category, e.g. A01:2025 Broken Access Control'),
          what: z.string().describe('Description of the vulnerability'),
          exploit: z.string().describe('Concrete request or action and resulting impact'),
          fix: z.string().describe('Root-cause remediation step or snippet'),
          regressionTest: z.string().describe('Name or path of reproduction test'),
          siblings: z.number().optional().describe('Count of same flaw shape elsewhere'),
          penalty: z.union([z.string(), z.number()]).optional(),
        })
      ).default([]),
      slopFindings: z.array(
        z.object({
          id: z.string(),
          classId: z.string().describe('S01..S14'),
          title: z.string(),
          where: z.string(),
          team: z.string(),
          description: z.string(),
        })
      ).optional().describe('Confirmed AI slop patterns'),
      notFindings: z.array(z.string()).optional().describe('Leads investigated and dismissed with reasons'),
      notVerified: z.array(z.string()).optional().describe('Hypotheses with missing proof steps'),
      coverage: z.object({
        roster: z.array(z.string()).optional(),
        scopeSetByUser: z.array(z.string()).optional(),
        sectionsAttacked: z.array(z.string()),
        sectionsSkipped: z.array(z.string()),
        toolsRun: z.array(z.string()),
        instructionsIgnored: z.array(z.string()).optional(),
      }),
      complianceAppendix: z.string().optional().describe('Optional compliance mapping appendix text'),
    },
    async (args) => {
      const result = await generateAuditReport(args as any);
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

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
  parseUserIntake,
  auditToolRoster,
  formatTaskOrder,
  formatToolLaunch,
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
  COMPANY_AGENTS,
  getAgentSystemPrompt,
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

  // Tool: CEO Intake Engine
  server.tool(
    'security_kill_intake',
    'CEO intake engine: translates plain user words or options into mandate.md, flags, board decisions, and executive announcement',
    {
      userInput: z.string().describe('Plain user request words (e.g. "is this safe to ship", "quick look", "check my keys", "test the live site https://...")'),
      targetPath: z.string().default('.').describe('Root path of the repository to audit'),
      existingReportExists: z.boolean().optional().describe('Whether an existing audit report is already present'),
      cliFlags: z.object({
        mode: z.string().optional(),
        depth: z.enum(['quick', 'standard', 'deep']).optional(),
        domain: z.string().optional(),
        teams: z.string().optional(),
        compliance: z.boolean().optional(),
        diff: z.boolean().optional(),
        dastUrl: z.string().optional(),
      }).optional(),
    },
    async ({ userInput, targetPath, existingReportExists, cliFlags }) => {
      const result = parseUserIntake(userInput, { targetPath, existingReportExists, cliFlags });
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  // Tool: O02 Tool Desk Staff Roster
  server.tool(
    'security_kill_tool_roster',
    'O02 Tool Desk roster manager: returns staff roster job cards and runs synthetic canary health checks across scanners, MCP servers, and pipelines',
    {
      runHealthChecks: z.boolean().default(true).describe('Whether to execute live health checks on scanners and tools'),
    },
    async () => {
      const result = await auditToolRoster();
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  // Tool: Dispatch Task Order & Tool Launch (CEO)
  server.tool(
    'security_kill_dispatch_order',
    'CEO Task Order and Tool Launch dispatcher: validates against Gate G0 (mission, slice, budget, done test) and formats order',
    {
      orderType: z.enum(['task_order', 'tool_launch']).default('task_order').describe('Type of order to issue'),
      taskOrder: z.object({
        id: z.string().describe('Order ID, e.g. O-014'),
        phase: z.union([z.number(), z.string()]).describe('Phase number (e.g. 6 or 6d)'),
        team: z.string().describe('Target specialist team (e.g. T03 Access)'),
        mission: z.string().describe('One sentence naming the asset and attacker goal'),
        slice: z.string().describe('Sections or path scope'),
        inputs: z.array(z.string()).default([]),
        knowledge: z.array(z.string()).default([]),
        staffAllowed: z.array(z.string()).default([]),
        staffForbidden: z.array(z.string()).default([]),
        method: z.array(z.string()).default([]),
        outputFile: z.string().describe('e.g. returns/O-014.md'),
        doneTest: z.string().describe('Objective done test for CEO / script verification'),
        budget: z.object({
          maxFiles: z.number().optional(),
          maxToolCalls: z.number().optional(),
          timeoutMinutes: z.number().optional(),
        }).default({}),
        reworkNotes: z.array(z.string()).optional(),
      }).optional(),
      toolLaunch: z.object({
        id: z.string().describe('Launch ID, e.g. L-007'),
        staff: z.string().describe('Tool or staff name, e.g. gitleaks'),
        orderId: z.string().describe('Parent order ID, e.g. O-009'),
        command: z.string().describe('Exact CLI command with redaction flags'),
        workingDirectory: z.string().describe('Explicit target path'),
        outputPath: z.string().describe('Artifact path under $TMP/security-kill/scan/'),
        timeoutSeconds: z.number().default(120),
        healthState: z.string().default('OK'),
        parseRule: z.string().default('Count findings by script, never by summary line'),
        egress: z.string().default('none'),
      }).optional(),
    },
    async ({ orderType, taskOrder, toolLaunch }) => {
      if (orderType === 'task_order' && taskOrder) {
        const g0 = verifyG0Order(taskOrder as any);
        const formatted = formatTaskOrder(taskOrder as any);
        return {
          content: [{ type: 'text', text: JSON.stringify({ g0, formatted }, null, 2) }],
        };
      } else if (orderType === 'tool_launch' && toolLaunch) {
        const g0 = verifyG0Order(toolLaunch as any);
        const formatted = formatToolLaunch(toolLaunch as any);
        return {
          content: [{ type: 'text', text: JSON.stringify({ g0, formatted }, null, 2) }],
        };
      }
      return {
        content: [{ type: 'text', text: 'Error: Must provide taskOrder or toolLaunch data' }],
        isError: true,
      };
    }
  );

  // Tool: Gates G0-G7 Verification Loops
  server.tool(
    'security_kill_verify_gate',
    'Verification Loops Gatekeeper: executes mechanical Gate checks G0 through G7 with rejection codes R1-R8 and rework ladder tracking',
    {
      gate: z.enum(['G0', 'G1', 'G2', 'G3', 'G4', 'G5', 'G6', 'G7']).describe('Gate identifier to evaluate'),
      returnMarkdown: z.string().optional().describe('Raw markdown of worker return (returns/<id>.md) for G1-G4'),
      repoRoot: z.string().optional().describe('Repository root path for G2 citation verification'),
      baseScanDir: z.string().optional().describe('Base scan directory for G4 artifact verification'),
      currentReworkRound: z.number().default(0).describe('Current rework attempt count (0 = first return, 1 = first rework)'),
      g5Options: z.object({
        testedSection: z.string(),
        plantedFlawCaught: z.boolean(),
        repeatedFalsePremise: z.boolean().optional(),
      }).optional(),
      g6Options: z.object({
        findingId: z.string(),
        severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
        originalEvidence: z.string(),
        verifierVerdict: z.enum(['Confirmed', 'Refuted', 'Undecided']),
        reproducedBySecondWorker: z.boolean(),
      }).optional(),
      g7Checklist: z.object({
        allFindingsCiteOpenedFile: z.boolean(),
        allNumbersAndVersionsSourced: z.boolean(),
        scoringArithmeticRecomputed: z.boolean(),
        allCriticalHighPassedG2ToG6: z.boolean(),
        noHeldRowsInScore: z.boolean(),
        coverageListsAllSkippedTeams: z.boolean(),
        noRepoInstructionsObeyed: z.boolean(),
        reportTextScannedCleanOfSecrets: z.boolean(),
        reworkCountsRecorded: z.boolean(),
      }).optional(),
    },
    async ({ gate, returnMarkdown, repoRoot, baseScanDir, currentReworkRound, g5Options, g6Options, g7Checklist }) => {
      let result: any;
      const parsedReturn = returnMarkdown ? parseWorkerReturn(returnMarkdown) : null;

      if (gate === 'G1') {
        result = parsedReturn ? verifyG1Form(parsedReturn) : { gate: 'G1', passed: false, defects: [{ code: 'R1', description: 'Missing returnMarkdown' }], summary: 'No return provided' };
      } else if (gate === 'G2') {
        result = parsedReturn ? verifyG2Citation(parsedReturn, repoRoot || '.') : { gate: 'G2', passed: false, defects: [{ code: 'R2', description: 'Missing returnMarkdown' }], summary: 'No return provided' };
      } else if (gate === 'G3') {
        result = parsedReturn ? verifyG3Identifier(parsedReturn) : { gate: 'G3', passed: false, defects: [{ code: 'R3', description: 'Missing returnMarkdown' }], summary: 'No return provided' };
      } else if (gate === 'G4') {
        result = parsedReturn ? verifyG4Run(parsedReturn, baseScanDir) : { gate: 'G4', passed: false, defects: [{ code: 'R4', description: 'Missing returnMarkdown' }], summary: 'No return provided' };
      } else if (gate === 'G5' && g5Options) {
        result = verifyG5KnownAnswer(g5Options);
      } else if (gate === 'G6' && g6Options) {
        result = verifyG6IndependentRecheck(g6Options);
      } else if (gate === 'G7' && g7Checklist) {
        result = verifyG7CeoFinal(g7Checklist);
      } else {
        result = { gate, passed: false, defects: [{ code: 'R1', description: `Invalid or incomplete arguments for gate ${gate}` }], summary: `Gate ${gate} evaluation failed: incomplete parameters` };
      }

      const reworkDecision = result.passed ? null : evaluateReworkLadder(result.defects, currentReworkRound);

      return {
        content: [{ type: 'text', text: JSON.stringify({ gateResult: result, reworkDecision }, null, 2) }],
      };
    }
  );

  // Tool: Antigravity Agent Definitions
  server.tool(
    'security_kill_get_agent',
    'Returns the complete agent definition, mission, allowed tools, forbidden actions, return schema, and Antigravity system prompt for any company agent (CEO, O01, O02, T01..T16)',
    {
      agentId: z.string().describe('Agent ID, e.g. CEO, O01, O02, T01, T02, T03, T04, T05, T06, T07, T08, T09, T10, T11, T12, T13, T14, T15, T16'),
    },
    async ({ agentId }) => {
      const key = agentId.toUpperCase();
      const agent = COMPANY_AGENTS[key];
      if (!agent) {
        return {
          content: [{ type: 'text', text: `Agent '${agentId}' not found. Available: ${Object.keys(COMPANY_AGENTS).join(', ')}` }],
          isError: true,
        };
      }
      const systemPrompt = getAgentSystemPrompt(key);
      return {
        content: [{ type: 'text', text: JSON.stringify({ ...agent, systemPrompt }, null, 2) }],
      };
    }
  );

  return server;
}

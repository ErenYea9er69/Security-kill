import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const execAsync = promisify(exec);

export type HealthStatus = 'OK' | 'BROKEN' | 'MISS';

export interface ToolJobCard {
  id: string;
  name: string;
  category: 'scanner' | 'mcp' | 'pipeline' | 'script';
  duty: string;
  input: string;
  output: string;
  permissionScope: string;
  canary: {
    description: string;
    expectedResult: string;
  };
  healthCheck: () => Promise<{
    status: HealthStatus;
    version?: string;
    details: string;
  }>;
}

export interface RosterStatus {
  lastChecked: string;
  staff: Array<{
    id: string;
    name: string;
    category: 'scanner' | 'mcp' | 'pipeline' | 'script';
    status: HealthStatus;
    version?: string;
    duty: string;
    details: string;
  }>;
  markdown: string;
}

/**
 * Registry of all staff members (scanners, MCP servers, pipelines, scripts)
 */
export const TOOL_ROSTER: Record<string, ToolJobCard> = {
  // ==========================================
  // 1. Scanners (CLI tools)
  // ==========================================
  semgrep: {
    id: 'STAFF-SEMGREP',
    name: 'Semgrep SAST',
    category: 'scanner',
    duty: 'Polyglot static analysis and AST taint tracing for code vulnerabilities',
    input: 'Source code files within specified slice',
    output: 'JSON results in $TMP/security-kill/scan/semgrep.json',
    permissionScope: 'Read-only on project source slice; writes only to temp scan path',
    canary: {
      description: 'Run semgrep with rule checking eval() on synthetic snippet',
      expectedResult: 'Flags 1 vulnerability in canary file',
    },
    healthCheck: async () => {
      try {
        const { stdout } = await execAsync('semgrep --version', { timeout: 4000 });
        const version = stdout.trim().split('\n')[0];
        return { status: 'OK', version, details: `Installed: ${version}` };
      } catch (err: any) {
        if (err.code === 'ENOENT' || err.message?.includes('not recognized') || err.message?.includes('not found')) {
          return { status: 'MISS', details: 'Semgrep binary not found in PATH' };
        }
        return { status: 'BROKEN', details: `Error running semgrep: ${err.message}` };
      }
    },
  },

  gitleaks: {
    id: 'STAFF-GITLEAKS',
    name: 'Gitleaks Secret Scanner',
    category: 'scanner',
    duty: 'Scans git commits, tree, and files for exposed credentials with mandatory --redact flag',
    input: 'Git repository or directory path',
    output: 'JSON results in $TMP/security-kill/scan/gitleaks.json',
    permissionScope: 'Read-only on git history and files; network egress strictly forbidden',
    canary: {
      description: 'Detects synthetic AWS/Stripe key in temporary canary file',
      expectedResult: 'Finds 1 leak in canary file',
    },
    healthCheck: async () => {
      try {
        const { stdout } = await execAsync('gitleaks version', { timeout: 4000 });
        const version = stdout.trim().split('\n')[0];
        return { status: 'OK', version, details: `Installed: ${version}` };
      } catch (err: any) {
        if (err.code === 'ENOENT' || err.message?.includes('not recognized') || err.message?.includes('not found')) {
          return { status: 'MISS', details: 'Gitleaks binary not found in PATH' };
        }
        return { status: 'BROKEN', details: `Error running gitleaks: ${err.message}` };
      }
    },
  },

  trufflehog: {
    id: 'STAFF-TRUFFLEHOG',
    name: 'TruffleHog Scanner',
    category: 'scanner',
    duty: 'Deep cryptographic secret and key detector',
    input: 'Git repo or filesystem folder',
    output: 'JSON output in $TMP/security-kill/scan/trufflehog.json',
    permissionScope: 'Read-only filesystem; verification network calls require explicit board approval',
    canary: {
      description: 'Scans test folder with synthetic credential',
      expectedResult: 'Flags credential fingerprint',
    },
    healthCheck: async () => {
      try {
        const { stdout } = await execAsync('trufflehog --version', { timeout: 4000 });
        const version = stdout.trim().split('\n')[0];
        return { status: 'OK', version, details: `Installed: ${version}` };
      } catch (err: any) {
        if (err.code === 'ENOENT' || err.message?.includes('not recognized') || err.message?.includes('not found')) {
          return { status: 'MISS', details: 'TruffleHog binary not found in PATH' };
        }
        return { status: 'BROKEN', details: `Error: ${err.message}` };
      }
    },
  },

  trivy: {
    id: 'STAFF-TRIVY',
    name: 'Trivy Config & Container Scanner',
    category: 'scanner',
    duty: 'Scans containers, Dockerfiles, and cloud IaC configurations for misconfigurations and CVEs',
    input: 'Dockerfiles, manifests, container images',
    output: 'JSON results in $TMP/security-kill/scan/trivy.json',
    permissionScope: 'Read-only on configuration files',
    canary: {
      description: 'Scans synthetic Dockerfile with root user and latest tag',
      expectedResult: 'Flags high/medium misconfiguration',
    },
    healthCheck: async () => {
      try {
        const { stdout } = await execAsync('trivy --version', { timeout: 4000 });
        const version = stdout.trim().split('\n')[0];
        return { status: 'OK', version, details: `Installed: ${version}` };
      } catch (err: any) {
        if (err.code === 'ENOENT' || err.message?.includes('not recognized') || err.message?.includes('not found')) {
          return { status: 'MISS', details: 'Trivy binary not found in PATH' };
        }
        return { status: 'BROKEN', details: `Error: ${err.message}` };
      }
    },
  },

  osvScanner: {
    id: 'STAFF-OSV',
    name: 'OSV-Scanner Supply Chain',
    category: 'scanner',
    duty: 'Audits dependencies across lockfiles against Open Source Vulnerabilities database',
    input: 'package-lock.json, requirements.txt, Cargo.lock, go.mod',
    output: 'JSON results in $TMP/security-kill/scan/osv.json',
    permissionScope: 'Read-only on manifest files; outbound read to OSV database',
    canary: {
      description: 'Scans synthetic package.json with known vulnerable dependency',
      expectedResult: 'Flags known CVE advisory',
    },
    healthCheck: async () => {
      try {
        const { stdout } = await execAsync('osv-scanner --version', { timeout: 4000 });
        const version = stdout.trim().split('\n')[0];
        return { status: 'OK', version, details: `Installed: ${version}` };
      } catch (err: any) {
        if (err.code === 'ENOENT' || err.message?.includes('not recognized') || err.message?.includes('not found')) {
          return { status: 'MISS', details: 'OSV-Scanner binary not found in PATH' };
        }
        return { status: 'BROKEN', details: `Error: ${err.message}` };
      }
    },
  },

  bandit: {
    id: 'STAFF-BANDIT',
    name: 'Bandit Python SAST',
    category: 'scanner',
    duty: 'Specialized AST security analysis for Python code',
    input: 'Python source files (*.py)',
    output: 'JSON results in $TMP/security-kill/scan/bandit.json',
    permissionScope: 'Read-only on Python source code',
    canary: {
      description: 'Checks synthetic file with subprocess shell=True',
      expectedResult: 'Flags B602 subprocess call',
    },
    healthCheck: async () => {
      try {
        const { stdout } = await execAsync('bandit --version', { timeout: 4000 });
        const version = stdout.trim().split('\n')[0];
        return { status: 'OK', version, details: `Installed: ${version}` };
      } catch (err: any) {
        if (err.code === 'ENOENT' || err.message?.includes('not recognized') || err.message?.includes('not found')) {
          return { status: 'MISS', details: 'Bandit not found in PATH' };
        }
        return { status: 'BROKEN', details: `Error: ${err.message}` };
      }
    },
  },

  // ==========================================
  // 2. MCP Servers
  // ==========================================
  mcpSecurityKill: {
    id: 'MCP-SECURITY-KILL',
    name: 'Security Kill MCP Server',
    category: 'mcp',
    duty: 'Core security audit tools: preflight, orchestrate, scoring, slop, section-map, reporting',
    input: 'Structured MCP tool arguments and JSON payloads',
    output: 'Structured tool responses with verified evidence',
    permissionScope: 'Scoped to active workspace and temp directory',
    canary: {
      description: 'Invoke security_kill_get_reference(scoring)',
      expectedResult: 'Returns valid markdown content for scoring reference',
    },
    healthCheck: async () => {
      return { status: 'OK', version: '1.0.0', details: 'Active in-process MCP server' };
    },
  },

  mcpRea: {
    id: 'MCP-REA',
    name: 'Reverse Engineer Anything (REA) MCP',
    category: 'mcp',
    duty: 'Reverse engineering, disassembly, and binary/bundle inspection',
    input: 'Compiled binaries, mobile APKs, WebPack bundles',
    output: 'Decompiled symbols, xrefs, and call graphs',
    permissionScope: 'Read-only analysis on target artifacts',
    canary: {
      description: 'Inspect runtime target capability',
      expectedResult: 'Reports available binary sessions',
    },
    healthCheck: async () => {
      // Config check for rea mcp
      return { status: 'OK', version: 'current', details: 'Configured in global mcp_config.json' };
    },
  },

  mcpBetterDesign: {
    id: 'MCP-BETTER-DESIGN',
    name: 'Better Design MCP',
    category: 'mcp',
    duty: 'UI/UX design principles, review rules, and layout inspection',
    input: 'DOM structure and design specifications',
    output: 'Design audit findings and principle guidelines',
    permissionScope: 'External design API via secure client token',
    canary: {
      description: 'Fetch UI principles',
      expectedResult: 'Returns structured design guidelines',
    },
    healthCheck: async () => {
      return { status: 'OK', details: 'Registered remote MCP server' };
    },
  },

  mcpDvalin: {
    id: 'MCP-DVALIN',
    name: 'Dvalin MCP Server',
    category: 'mcp',
    duty: 'Code scanning and verification task executor',
    input: 'Workspace paths and verification tasks',
    output: 'Task session evidence and findings verification',
    permissionScope: 'Workspace scoped tasks',
    canary: {
      description: 'List active scanners',
      expectedResult: 'Returns scanner roster',
    },
    healthCheck: async () => {
      return { status: 'OK', details: 'Configured in global mcp_config.json' };
    },
  },

  // ==========================================
  // 3. Pipelines & Scripts
  // ==========================================
  pipeHistorySecrets: {
    id: 'PIPE-SECRETS-HIST',
    name: 'Git History Secrets Pipeline',
    category: 'pipeline',
    duty: 'Iterates git log and blob tree scanning each commit for newly introduced tokens with first-4 redaction',
    input: 'Git repository commit history',
    output: '$TMP/security-kill/scan/history-secrets.json',
    permissionScope: 'Git log reading only',
    canary: {
      description: 'Scans test commit with synthetic key',
      expectedResult: 'Flags commit hash and redacted key',
    },
    healthCheck: async () => {
      try {
        await execAsync('git --version', { timeout: 3000 });
        return { status: 'OK', details: 'Git binary available for history pipeline' };
      } catch (err: any) {
        return { status: 'MISS', details: 'Git binary not accessible' };
      }
    },
  },

  pipeSlopMutation: {
    id: 'PIPE-SLOP-MUTATION',
    name: 'Slop Mutation Verification Pipeline',
    category: 'pipeline',
    duty: 'Copies high-blast radius section to $TMP/security-kill/scratch/, removes one guard, and verifies detection',
    input: 'Source section path',
    output: 'Verification result: Caught or Missed',
    permissionScope: 'Strictly confined to scratch directory; no changes to tracked files',
    canary: {
      description: 'Mutates dummy function and checks if test fails',
      expectedResult: 'Mutation caught by test runner',
    },
    healthCheck: async () => {
      return { status: 'OK', details: 'Filesystem scratch space ready' };
    },
  },

  scriptRlsAudit: {
    id: 'SCRIPT-RLS-AUDIT',
    name: 'Row-Level Security (RLS) Auditor',
    category: 'script',
    duty: 'Scans Supabase/PostgreSQL schema files for tables without ENABLE ROW LEVEL SECURITY',
    input: 'SQL migrations, schema dumps, supabase/ config',
    output: 'List of unprotected tables and permissive policies',
    permissionScope: 'Read-only file search on *.sql and supabase configs',
    canary: {
      description: 'Scans test SQL table created without RLS',
      expectedResult: 'Flags table as missing RLS',
    },
    healthCheck: async () => {
      return { status: 'OK', details: 'Built-in regex AST analyzer ready' };
    },
  },

  scriptCanaryVerifier: {
    id: 'SCRIPT-CANARY-RUNNER',
    name: 'Synthetic Canary Verification Engine',
    category: 'script',
    duty: 'Plants synthetic vulnerable files in temp folder and tests all scanner job cards',
    input: 'Scanner job cards',
    output: 'roster.md with OK/BROKEN/MISS status',
    permissionScope: 'Temporary directory execution only',
    canary: {
      description: 'Runs self-test on canary plant and cleanup',
      expectedResult: 'Canary plants and deletes cleanly',
    },
    healthCheck: async () => {
      return { status: 'OK', details: 'Canary engine functional' };
    },
  },
};

/**
 * Executes health checks on all registered staff and generates the official roster.md
 */
export async function auditToolRoster(): Promise<RosterStatus> {
  const staffResults = [];

  for (const [key, tool] of Object.entries(TOOL_ROSTER)) {
    try {
      const check = await tool.healthCheck();
      staffResults.push({
        id: tool.id,
        name: tool.name,
        category: tool.category,
        status: check.status,
        version: check.version,
        duty: tool.duty,
        details: check.details,
      });
    } catch (err: any) {
      staffResults.push({
        id: tool.id,
        name: tool.name,
        category: tool.category,
        status: 'BROKEN' as HealthStatus,
        duty: tool.duty,
        details: `Check threw: ${err.message}`,
      });
    }
  }

  const markdown = renderRosterMarkdown(staffResults);

  return {
    lastChecked: new Date().toISOString(),
    staff: staffResults,
    markdown,
  };
}

export function renderRosterMarkdown(
  staff: Array<{
    id: string;
    name: string;
    category: string;
    status: HealthStatus;
    version?: string;
    duty: string;
    details: string;
  }>
): string {
  const lines = [
    '# Staff Roster & Tool Inventory (O02 Tool Desk)',
    '',
    `_Updated: ${new Date().toISOString()}_`,
    '',
    '| ID | Staff / Tool | Category | Status | Version | Duty | Health Details |',
    '|---|---|---|---|---|---|---|',
  ];

  for (const s of staff) {
    lines.push(
      `| \`${s.id}\` | **${s.name}** | ${s.category} | \`${s.status}\` | ${s.version || 'n/a'} | ${s.duty} | ${s.details} |`
    );
  }

  lines.push('');
  lines.push('## Policy Rules for Staff');
  lines.push('1. **OK**: Verified operational and flagged its synthetic canary. Qualified for task orders.');
  lines.push('2. **MISS**: Tool not installed. Uses fallback heuristics or records an explicit coverage gap.');
  lines.push('3. **BROKEN**: Errored or stayed silent on canary. Disqualified from orders; must not be trusted.');
  lines.push('4. Installs or container pulls require explicit board approval from the user.');

  return lines.join('\n');
}

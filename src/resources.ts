import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Find package root whether running from src/ or dist/
function findPackageRoot(): string {
  let current = __dirname;
  for (let i = 0; i < 4; i++) {
    if (fs.existsSync(path.join(current, 'references')) && fs.existsSync(path.join(current, 'SKILL.md'))) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return path.resolve(process.cwd());
}

const packageRoot = findPackageRoot();
const referencesDir = path.join(packageRoot, 'references');
const skillFile = path.join(packageRoot, 'SKILL.md');

export const REFERENCE_DESCRIPTIONS: Record<string, string> = {
  'evidence-and-truth': 'Truth rules, evidence grading standards (PROVEN, TRACED, LEAD, DISPUTED), and advisory verification procedures.',
  'attacker-simulation': 'Core attacker simulation methodology, blast-radius ranking, attack cards, and AI agent questions.',
  'section-playbooks': 'Detailed attack moves and verification steps for auth, payments, uploads, data layer, and admin sections.',
  'dast-and-authz': 'Proof rig execution, DAST authorization testing, two-account probing, and non-destructive proof constraints.',
  'fix-patterns': 'Root-cause remediation patterns, shared choke points, and replayable regression tests.',
  'preflight': 'Canary verification procedures, CLI tool inventory, and Docker fallback runners for broken tools.',
  'sast-secrets': 'Secret detection across git history and build artifacts, SAST scanner triage, and regex fallbacks.',
  'sca-supply-chain': 'Dependency audits, hallucinated packages, install-time script attacks, and CVE exploitability grading.',
  'agent-config-and-worms': 'Agent instruction files (CLAUDE.md, AGENTS.md), MCP server safety, hook scripts, and worm vectors.',
  'iac-cloud-config': 'Cloud infrastructure, Docker/container security, GitHub Actions workflows, and TLS/headers.',
  'baas-supabase-firebase': 'Supabase and Firebase security, mandatory Row Level Security (RLS) auditing, and storage rules.',
  'stack-checks': 'Stack-specific security checks for PostgreSQL, Redis, React, Next.js, Go, and Node.js.',
  'vibecoding-checklist': 'Top 18 failure classes in AI-generated code: missing RLS, IDOR, unauthenticated actions, rate limiting, etc.',
  'llm-app-security': 'OWASP LLM Top 10 (2026), prompt injection, insecure output handling, agentic tool authorization.',
  'compliance-mapping': 'Evidence appendix generator for SOC 2, ISO 27001, HIPAA, and PCI-DSS control mappings.',
  'credential-rotation': 'Step-by-step procedures for rotating exposed credentials across major cloud and API providers.',
  'ci-integration': 'Automating security scans in GitHub Actions, GitLab CI, and pre-commit hooks.',
};

/**
 * Returns a list of all available reference playbook names (without .md extension).
 */
export function listReferences(): string[] {
  if (!fs.existsSync(referencesDir)) {
    return Object.keys(REFERENCE_DESCRIPTIONS);
  }
  return fs
    .readdirSync(referencesDir)
    .filter((f) => f.endsWith('.md'))
    .map((f) => f.replace(/\.md$/, ''))
    .sort();
}

/**
 * Reads the content of a specific reference playbook.
 */
export function getReferenceContent(name: string): string | null {
  const sanitized = path.basename(name).replace(/\.md$/, '');
  const filePath = path.join(referencesDir, `${sanitized}.md`);
  if (!fs.existsSync(filePath)) {
    return null;
  }
  return fs.readFileSync(filePath, 'utf-8');
}

/**
 * Reads the core security audit skill guide (SKILL.md).
 */
export function getSkillContent(): string | null {
  if (!fs.existsSync(skillFile)) {
    return null;
  }
  return fs.readFileSync(skillFile, 'utf-8');
}

export interface McpResourceDescriptor {
  uri: string;
  name: string;
  description: string;
  mimeType: string;
}

/**
 * Returns MCP resource descriptors for all reference playbooks and the core skill.
 */
export function getAllReferenceResources(): McpResourceDescriptor[] {
  const resources: McpResourceDescriptor[] = [
    {
      uri: 'security://skill',
      name: 'Security Audit Core Skill',
      description: 'The master 11-phase security audit workflow, truth rules, and triage guidelines.',
      mimeType: 'text/markdown',
    },
  ];

  const refs = listReferences();
  for (const ref of refs) {
    resources.push({
      uri: `security://reference/${ref}`,
      name: ref,
      description: REFERENCE_DESCRIPTIONS[ref] || `Security audit reference guide for ${ref}`,
      mimeType: 'text/markdown',
    });
  }

  return resources;
}


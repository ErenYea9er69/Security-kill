import fs from 'node:fs';
import path from 'node:path';

export interface AuditSection {
  name: string;
  blastRadius: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  detectedFiles: string[];
  mandatoryPlaybooks: string[];
}

export interface SectionMapResult {
  targetPath: string;
  isGitRepo: boolean;
  languages: string[];
  manifests: string[];
  backendPlatforms: string[];
  llmUsage: boolean;
  agentConfigs: string[];
  sections: AuditSection[];
  summary: string;
}

const MANIFEST_PATTERNS = [
  'package.json',
  'requirements.txt',
  'pyproject.toml',
  'Pipfile',
  'go.mod',
  'Cargo.toml',
  'composer.json',
  'Gemfile',
  'pom.xml',
  'build.gradle',
  'Dockerfile',
  'docker-compose.yml',
  'docker-compose.yaml',
  'vercel.json',
  'netlify.toml',
  'fly.toml',
  'railway.json',
];

const AGENT_CONFIG_FILES = [
  'CLAUDE.md',
  '.cursorrules',
  'AGENTS.md',
  '.mcp.json',
  '.github/copilot-instructions.md',
];

export async function runSectionMap(targetPath: string): Promise<SectionMapResult> {
  const resolved = path.resolve(targetPath);
  const isGitRepo = fs.existsSync(path.join(resolved, '.git'));
  const foundManifests: string[] = [];
  const foundLanguages = new Set<string>();
  const backendPlatforms = new Set<string>();
  let llmUsage = false;
  const agentConfigs: string[] = [];

  for (const m of MANIFEST_PATTERNS) {
    if (fs.existsSync(path.join(resolved, m))) {
      foundManifests.push(m);
      if (m === 'package.json') foundLanguages.add('JavaScript/TypeScript');
      if (m === 'requirements.txt' || m === 'pyproject.toml' || m === 'Pipfile') foundLanguages.add('Python');
      if (m === 'go.mod') foundLanguages.add('Go');
      if (m === 'Cargo.toml') foundLanguages.add('Rust');
      if (m === 'composer.json') foundLanguages.add('PHP');
      if (m === 'Gemfile') foundLanguages.add('Ruby');
      if (m === 'pom.xml' || m === 'build.gradle') foundLanguages.add('Java');
    }
  }

  // Check agent config files
  for (const ac of AGENT_CONFIG_FILES) {
    if (fs.existsSync(path.join(resolved, ac))) {
      agentConfigs.push(ac);
    }
  }

  // Scan package.json or requirements.txt for BaaS and LLM dependencies
  const pkgPath = path.join(resolved, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      const depNames = Object.keys(allDeps);

      if (depNames.some((d) => d.includes('supabase'))) backendPlatforms.add('Supabase');
      if (depNames.some((d) => d.includes('firebase'))) backendPlatforms.add('Firebase');
      if (depNames.some((d) => /openai|anthropic|@langchain|ai|ollama|cohere|groq/i.test(d))) {
        llmUsage = true;
      }
    } catch {
      // parse error ignore
    }
  }

  const reqPath = path.join(resolved, 'requirements.txt');
  if (fs.existsSync(reqPath)) {
    try {
      const content = fs.readFileSync(reqPath, 'utf-8');
      if (/supabase/i.test(content)) backendPlatforms.add('Supabase');
      if (/firebase/i.test(content)) backendPlatforms.add('Firebase');
      if (/openai|anthropic|langchain|llama_index/i.test(content)) llmUsage = true;
    } catch {
      // ignore
    }
  }

  // Build section list with blast-radius rankings
  const sections: AuditSection[] = [];

  // 1. Auth & Authorization
  sections.push({
    name: 'Authentication & Authorization',
    blastRadius: 'CRITICAL',
    description: 'Login, registration, token issuance, session cookies, and object-level permissions (IDOR guards).',
    detectedFiles: [],
    mandatoryPlaybooks: ['section-playbooks', 'vibecoding-checklist', 'dast-and-authz'],
  });

  // 2. Data Layer & Database
  const dataPlaybooks = ['section-playbooks', 'stack-checks'];
  if (backendPlatforms.has('Supabase') || backendPlatforms.has('Firebase')) {
    dataPlaybooks.push('baas-supabase-firebase');
  }
  sections.push({
    name: 'Data Layer & Database Access',
    blastRadius: 'CRITICAL',
    description: 'Database models, SQL query building, migrations, and Row-Level Security (RLS) enforcement.',
    detectedFiles: [],
    mandatoryPlaybooks: dataPlaybooks,
  });

  // 3. Secrets & Client Bundles
  sections.push({
    name: 'Secrets & Client Bundles',
    blastRadius: 'CRITICAL',
    description: 'API keys, environment variables, git history, and public frontend client bundles.',
    detectedFiles: [],
    mandatoryPlaybooks: ['sast-secrets', 'vibecoding-checklist'],
  });

  // 4. File Storage & Uploads
  sections.push({
    name: 'File Upload & Media Storage',
    blastRadius: 'HIGH',
    description: 'File upload routes, bucket access policies, extension filtering, and path traversal guards.',
    detectedFiles: [],
    mandatoryPlaybooks: ['section-playbooks', 'vibecoding-checklist'],
  });

  // 5. LLM / Agent Features (if present)
  if (llmUsage || agentConfigs.length > 0) {
    sections.push({
      name: 'LLM & Autonomous Agent Layer',
      blastRadius: 'HIGH',
      description: 'Prompts, tool calls, model outputs, agent instructions, and MCP server boundary defenses.',
      detectedFiles: agentConfigs,
      mandatoryPlaybooks: ['llm-app-security', 'agent-config-and-worms'],
    });
  }

  // 6. Dependencies & Supply Chain
  sections.push({
    name: 'Dependencies & Supply Chain',
    blastRadius: 'HIGH',
    description: 'Third-party packages, lockfile integrity, install-time scripts, and known CVEs.',
    detectedFiles: foundManifests,
    mandatoryPlaybooks: ['sca-supply-chain'],
  });

  // 7. Cloud, CI/CD, & Infrastructure
  const hasDocker = fs.existsSync(path.join(resolved, 'Dockerfile')) || fs.existsSync(path.join(resolved, 'docker-compose.yml'));
  const hasWorkflows = fs.existsSync(path.join(resolved, '.github', 'workflows'));
  sections.push({
    name: 'Infrastructure & CI/CD Pipelines',
    blastRadius: 'MEDIUM',
    description: 'Dockerfiles, container privileges, GitHub Actions workflows, secrets in actions, and TLS headers.',
    detectedFiles: [
      ...(hasDocker ? ['Dockerfile / docker-compose'] : []),
      ...(hasWorkflows ? ['.github/workflows'] : []),
    ],
    mandatoryPlaybooks: ['iac-cloud-config', 'ci-integration'],
  });

  return {
    targetPath: resolved,
    isGitRepo,
    languages: Array.from(foundLanguages),
    manifests: foundManifests,
    backendPlatforms: Array.from(backendPlatforms),
    llmUsage,
    agentConfigs,
    sections,
    summary: `Found ${foundLanguages.size} language(s) (${Array.from(foundLanguages).join(', ') || 'unknown'}), ${foundManifests.length} manifest(s), ${backendPlatforms.size > 0 ? `BaaS: ${Array.from(backendPlatforms).join(', ')}` : 'standard backend'}. Mapped into ${sections.length} audit sections.`,
  };
}


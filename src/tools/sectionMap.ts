import fs from 'node:fs';
import path from 'node:path';

export interface AuditSection {
  id: string; // S01, S02, etc.
  name: string;
  ownerTeam: string; // T02, T03, etc.
  teamName: string;
  blastRadius: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
  detectedFiles: string[];
  mandatoryPlaybooks: string[];
}

export interface SectionMapResult {
  targetPath: string;
  isGitRepo: boolean;
  languages: string[];
  frameworks: string[];
  manifests: string[];
  backendPlatforms: string[];
  domain: string;
  recommendedDepthTier: 'quick' | 'standard' | 'deep';
  activeRoster: Array<{ id: string; name: string; reason: string }>;
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
  'AndroidManifest.xml',
  'Info.plist',
  'manifest.json',
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
  const foundFrameworks = new Set<string>();
  const backendPlatforms = new Set<string>();
  let hasPayments = false;
  let hasMultiTenant = false;
  let hasHealthData = false;
  let hasClientUI = false;
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
      if (m === 'AndroidManifest.xml') {
        foundLanguages.add('Android / Kotlin / Java');
        hasClientUI = true;
      }
      if (m === 'Info.plist') {
        foundLanguages.add('iOS / Swift');
        hasClientUI = true;
      }
      if (m === 'manifest.json') {
        foundFrameworks.add('Browser Extension');
      }
    }
  }

  // Check agent config files
  for (const ac of AGENT_CONFIG_FILES) {
    if (fs.existsSync(path.join(resolved, ac))) {
      agentConfigs.push(ac);
    }
  }

  // Scan package.json for libraries
  const pkgPath = path.join(resolved, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      const allDeps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      const depNames = Object.keys(allDeps);

      if (depNames.some((d) => d.includes('supabase'))) backendPlatforms.add('Supabase');
      if (depNames.some((d) => d.includes('firebase'))) backendPlatforms.add('Firebase');
      if (depNames.some((d) => /react|vue|svelte|next|nuxt|astro/i.test(d))) {
        hasClientUI = true;
        foundFrameworks.add('Web Frontend (React/Vue/Next)');
      }
      if (depNames.some((d) => /electron|tauri/i.test(d))) {
        foundFrameworks.add('Desktop (Electron/Tauri)');
        hasClientUI = true;
      }
      if (depNames.some((d) => /stripe|paypal|razorpay|braintree|square/i.test(d))) {
        hasPayments = true;
      }
      if (depNames.some((d) => /openai|anthropic|@langchain|ai|ollama|cohere|groq/i.test(d))) {
        llmUsage = true;
      }
    } catch {
      // ignore JSON parse error
    }
  }

  // Scan requirements.txt for Python libraries
  const reqPath = path.join(resolved, 'requirements.txt');
  if (fs.existsSync(reqPath)) {
    try {
      const content = fs.readFileSync(reqPath, 'utf-8');
      if (/supabase/i.test(content)) backendPlatforms.add('Supabase');
      if (/firebase/i.test(content)) backendPlatforms.add('Firebase');
      if (/django/i.test(content)) foundFrameworks.add('Django');
      if (/flask/i.test(content)) foundFrameworks.add('Flask');
      if (/fastapi/i.test(content)) foundFrameworks.add('FastAPI');
      if (/stripe|paypal|razorpay/i.test(content)) hasPayments = true;
      if (/openai|anthropic|langchain|llama_index/i.test(content)) llmUsage = true;
    } catch {
      // ignore
    }
  }

  // Determine domain
  let domain = 'General Web Application';
  if (hasPayments) {
    domain = 'Payments and Fintech';
  } else if (hasMultiTenant) {
    domain = 'Multi-tenant SaaS';
  } else if (llmUsage) {
    domain = 'AI-First / LLM Application';
  } else if (foundFrameworks.has('Browser Extension')) {
    domain = 'Browser Extension';
  }

  // Active Team Roster Recommendation (from references/project-profiling.md)
  const activeRoster: Array<{ id: string; name: string; reason: string }> = [
    { id: 'T01', name: 'Cartographer', reason: 'Architecture profiling, section mapping, blast radius ranking' },
    { id: 'T04', name: 'Input', reason: 'Taint tracing, query building, input sanitization, and SAST' },
    { id: 'T07', name: 'Supply', reason: 'Dependencies, lockfile integrity, install-time worms, CVEs' },
    { id: 'T09', name: 'Secrets', reason: 'Credential detection across tree, history, and public bundles' },
    { id: 'T13', name: 'Slop Hunters', reason: 'Sweeps for phantom security, fake tests, and vibe-coding patterns' },
    { id: 'T12', name: 'Resilience', reason: 'Rate limiting, cost caps, auth failure logs, backup verification' },
    { id: 'T02', name: 'Identity', reason: 'User authentication, sessions, tokens, SSO, password reset' },
    { id: 'T03', name: 'Access', reason: 'Object-level authorization, tenant boundaries, RLS policies' },
  ];

  if (hasPayments) {
    activeRoster.push({ id: 'T05', name: 'Abuse', reason: 'Money movement, quota limits, races, webhooks' });
  }
  if (foundManifests.some((m) => m.includes('Dockerfile') || m.includes('compose') || m.includes('.github'))) {
    activeRoster.push({ id: 'T08', name: 'Infra', reason: 'Cloud, containers, CI workflows, deployment configs' });
  }
  if (llmUsage || agentConfigs.length > 0) {
    activeRoster.push({ id: 'T10', name: 'AI', reason: 'LLM SDKs, agent loops, MCP configs, system prompt leaks' });
  }
  if (hasClientUI) {
    activeRoster.push({ id: 'T11', name: 'Client', reason: 'Browser client bundles, mobile apps, desktop apps, or extensions' });
  }
  activeRoster.push({ id: 'T06', name: 'Data', reason: 'PII, cryptographic storage, retention, log privacy' });

  // Build section list with blast-radius and owner teams
  const sections: AuditSection[] = [];

  // S01: Auth & Identity (T02)
  sections.push({
    id: 'S01',
    name: 'Authentication & Session Management',
    ownerTeam: 'T02',
    teamName: 'Identity',
    blastRadius: 'CRITICAL',
    description: 'Login, registration, token issuance, session cookies, and MFA.',
    detectedFiles: [],
    mandatoryPlaybooks: ['section-playbooks', 'vibecoding-checklist', 'dast-and-authz', 'teams'],
  });

  // S02: Authorization & Tenancy (T03)
  const dataPlaybooks = ['section-playbooks', 'stack-checks', 'stack-packs'];
  if (backendPlatforms.has('Supabase') || backendPlatforms.has('Firebase')) {
    dataPlaybooks.push('baas-supabase-firebase');
  }
  sections.push({
    id: 'S02',
    name: 'Authorization, Tenancy & Data Access',
    ownerTeam: 'T03',
    teamName: 'Access',
    blastRadius: 'CRITICAL',
    description: 'Object-level authorization (IDOR), multi-tenant isolation, database models, and RLS policies.',
    detectedFiles: [],
    mandatoryPlaybooks: dataPlaybooks,
  });

  // S03: Secrets & Credential Storage (T09)
  sections.push({
    id: 'S03',
    name: 'Secrets & Client Bundles',
    ownerTeam: 'T09',
    teamName: 'Secrets',
    blastRadius: 'CRITICAL',
    description: 'API keys, environment variables, git history, and client bundle leaks.',
    detectedFiles: [],
    mandatoryPlaybooks: ['sast-secrets', 'credential-rotation'],
  });

  // S04: File Handling & Uploads (T04)
  sections.push({
    id: 'S04',
    name: 'Input Validation, Queries & Uploads',
    ownerTeam: 'T04',
    teamName: 'Input',
    blastRadius: 'HIGH',
    description: 'SQL queries, deserialization, template rendering, file uploads, and outbound fetch (SSRF).',
    detectedFiles: [],
    mandatoryPlaybooks: ['section-playbooks', 'fix-patterns'],
  });

  // S05: Payments & Abuse (T05) if payments detected
  if (hasPayments) {
    sections.push({
      id: 'S05',
      name: 'Payments, Credits & Webhook Handlers',
      ownerTeam: 'T05',
      teamName: 'Abuse',
      blastRadius: 'CRITICAL',
      description: 'Money movement, idempotency keys, payment webhooks, and rate limit evasion.',
      detectedFiles: [],
      mandatoryPlaybooks: ['section-playbooks', 'fix-patterns', 'project-profiling'],
    });
  }

  // S06: LLM & Agent Layer (T10) if present
  if (llmUsage || agentConfigs.length > 0) {
    sections.push({
      id: 'S06',
      name: 'LLM & Autonomous Agent Layer',
      ownerTeam: 'T10',
      teamName: 'AI',
      blastRadius: 'HIGH',
      description: 'Prompts, tool schemas, agent loops, MCP configs, instruction files, and Unicode evasion.',
      detectedFiles: agentConfigs,
      mandatoryPlaybooks: ['llm-app-security', 'agent-config-and-worms'],
    });
  }

  // S07: Dependencies & Supply Chain (T07)
  sections.push({
    id: 'S07',
    name: 'Dependencies & Supply Chain',
    ownerTeam: 'T07',
    teamName: 'Supply',
    blastRadius: 'HIGH',
    description: 'Third-party packages, lockfile integrity, install-time scripts, and CVE advisories.',
    detectedFiles: foundManifests,
    mandatoryPlaybooks: ['sca-supply-chain', 'agent-config-and-worms'],
  });

  // S08: Cloud & CI/CD Infrastructure (T08)
  const hasDocker = fs.existsSync(path.join(resolved, 'Dockerfile')) || fs.existsSync(path.join(resolved, 'docker-compose.yml'));
  const hasWorkflows = fs.existsSync(path.join(resolved, '.github', 'workflows'));
  sections.push({
    id: 'S08',
    name: 'Infrastructure & CI/CD Pipelines',
    ownerTeam: 'T08',
    teamName: 'Infra',
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
    frameworks: Array.from(foundFrameworks),
    manifests: foundManifests,
    backendPlatforms: Array.from(backendPlatforms),
    domain,
    recommendedDepthTier: 'standard',
    activeRoster,
    llmUsage,
    agentConfigs,
    sections,
    summary: `Profiled ${foundLanguages.size} language(s) (${Array.from(foundLanguages).join(', ') || 'unknown'}), Domain: ${domain}, BaaS: ${Array.from(backendPlatforms).join(', ') || 'None'}. Activated ${activeRoster.length} specialist teams across ${sections.length} sections.`,
  };
}

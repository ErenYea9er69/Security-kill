import path from 'node:path';

export type DepthTier = 'quick' | 'standard' | 'deep';

export interface BoardDecision {
  type: 'authorization' | 'tool_install' | 'fix_execution' | 'credential_rotation' | 'data_egress' | 'roster_fact';
  description: string;
  blocksNextStep: boolean;
  promptForUser: string;
}

export interface IntakeResult {
  userGoal: string;
  flags: string[];
  mode: string;
  depth: DepthTier;
  targetPath: string;
  scopePaths: string[];
  teamsFilter?: string[];
  domainOverride?: string;
  compliance: boolean;
  diff: boolean;
  dastUrl?: string;
  authorizationState: 'none' | 'local_only' | 'authorized_remote';
  authorizedHost?: string;
  deliverable: string;
  assumptions: string[];
  boardDecisions: BoardDecision[];
  ceoAnnouncement: string;
  mandateMarkdown: string;
  assuranceNote?: string;
}

export interface IntakeOptions {
  targetPath?: string;
  existingReportExists?: boolean;
  cliFlags?: {
    mode?: string;
    depth?: DepthTier;
    domain?: string;
    teams?: string;
    compliance?: boolean;
    diff?: boolean;
    dastUrl?: string;
  };
}

/**
 * Maps plain user words or CLI flags into an executive Mandate following references/company-model.md
 */
export function parseUserIntake(userInput: string, options: IntakeOptions = {}): IntakeResult {
  const targetPath = options.targetPath || '.';
  const inputLower = (userInput || '').toLowerCase();
  const cli = options.cliFlags || {};

  const flags: string[] = [];
  let mode = cli.mode || 'full';
  let depth: DepthTier = cli.depth || 'standard';
  let compliance = Boolean(cli.compliance);
  let diff = Boolean(cli.diff);
  let dastUrl: string | undefined = cli.dastUrl;
  let domainOverride: string | undefined = cli.domain;
  let teamsFilter: string[] | undefined = cli.teams ? cli.teams.split(',').map((t) => t.trim().toUpperCase()) : undefined;
  const scopePaths: string[] = [targetPath];
  const assumptions: string[] = [];
  const boardDecisions: BoardDecision[] = [];
  let assuranceNote: string | undefined;

  // 1. Natural language detection based on company-model.md intake table
  if (inputLower.includes('quick look') || inputLower.includes('fast check') || inputLower.includes('quick scan') || inputLower.includes('surface scan')) {
    depth = 'quick';
    flags.push('--depth quick');
    assuranceNote = 'Score is Provisional due to quick depth tier.';
  } else if (inputLower.includes('go deep') || inputLower.includes('red team it') || inputLower.includes('deep audit') || inputLower.includes('full red team')) {
    depth = 'deep';
    flags.push('--depth deep');
  }

  if (inputLower.includes('check my keys') || inputLower.includes('check my secrets') || inputLower.includes('find secrets') || inputLower.includes('leaked credentials')) {
    mode = 'secrets';
    flags.push('--secrets');
  } else if (inputLower.includes('check my packages') || inputLower.includes('dependencies') || inputLower.includes('npm audit') || inputLower.includes('supply chain')) {
    mode = 'deps';
    flags.push('--deps');
  } else if (inputLower.includes('code scan') || inputLower.includes('sast only')) {
    mode = 'code';
    flags.push('--code');
  } else if (inputLower.includes('check config') || inputLower.includes('iac') || inputLower.includes('cloud config')) {
    mode = 'config';
    flags.push('--config');
  } else if (inputLower.includes('slop') || inputLower.includes('phantom guards') || inputLower.includes('fake tests')) {
    mode = 'slop';
    flags.push('--slop');
  } else if (inputLower.includes('llm') || inputLower.includes('prompt injection') || inputLower.includes('agent security')) {
    mode = 'llm';
    flags.push('--llm');
  } else if (inputLower.includes('test the live site') || inputLower.includes('dast') || inputLower.includes('probe live')) {
    mode = 'dast';
    // Match potential URL
    const urlMatch = userInput.match(/https?:\/\/[^\s]+/i);
    if (urlMatch) {
      dastUrl = urlMatch[0];
    }
    flags.push(`--dast ${dastUrl || '<url>'}`);
  } else if (inputLower.includes('fix it') || inputLower.includes('fix everything') || inputLower.includes('repair')) {
    mode = 'fix';
    flags.push('--fix');
  } else if (inputLower.includes('retest') || inputLower.includes('verify fixes')) {
    mode = 'retest';
    flags.push('--retest');
  }

  // PR diff check
  if (inputLower.includes('what changed in this pr') || inputLower.includes('diff against main') || inputLower.includes('pr diff') || cli.diff) {
    diff = true;
    if (!flags.includes('--diff')) flags.push('--diff');
  }

  // Compliance check
  if (inputLower.includes('soc 2') || inputLower.includes('iso 27001') || inputLower.includes('hipaa') || inputLower.includes('pci') || inputLower.includes('compliance') || cli.compliance) {
    compliance = true;
    if (!flags.includes('--compliance')) flags.push('--compliance');
  }

  // Scoped domain or payment flow checks
  if (inputLower.includes('payment flow') || inputLower.includes('only payments') || inputLower.includes('checkout')) {
    domainOverride = 'payments';
    teamsFilter = ['T05'];
    flags.push('--teams t05 --domain payments');
    assuranceNote = 'Scoped run on payments lowers overall assurance.';
  } else if (inputLower.includes('auth only') || inputLower.includes('identity only') || inputLower.includes('only login')) {
    teamsFilter = ['T02'];
    flags.push('--teams t02');
    assuranceNote = 'Scoped run on identity lowers overall assurance.';
  }

  // Anti-gaming detection for "make the score 8"
  let userGoal = 'Independent, evidence-based security audit and attacker simulation';
  if (/make the score (\d+)/i.test(userInput) || /raise (my |the )?score/i.test(userInput)) {
    userGoal = 'Security audit with strict adherence to evidence scoring (score target requests route to remediation roadmap)';
  } else if (userInput.trim().length > 0) {
    userGoal = userInput.trim().replace(/\r?\n/g, ' ');
    if (userGoal.length > 120) {
      userGoal = userGoal.slice(0, 117) + '...';
    }
  }

  // 2. Authorization state & Board Decisions
  let authorizationState: 'none' | 'local_only' | 'authorized_remote' = 'none';
  let authorizedHost: string | undefined;

  if (dastUrl) {
    try {
      const parsed = new URL(dastUrl);
      authorizedHost = parsed.hostname;
      if (['localhost', '127.0.0.1', '::1'].includes(parsed.hostname)) {
        authorizationState = 'local_only';
        boardDecisions.push({
          type: 'authorization',
          description: `Confirm localhost service on ${dastUrl} serves disposable test data (not a tunnel to production)`,
          blocksNextStep: true,
          promptForUser: `The DAST target is ${dastUrl}. Please confirm this port serves disposable local test data and is not an SSH/cloud tunnel to production.`,
        });
      } else {
        boardDecisions.push({
          type: 'authorization',
          description: `Written authorization check required for non-loopback host: ${authorizedHost}`,
          blocksNextStep: true,
          promptForUser: `Testing ${dastUrl} requires explicit written authorization. Do you own or have permission to attack ${authorizedHost}?`,
        });
      }
    } catch {
      boardDecisions.push({
        type: 'authorization',
        description: 'Invalid or missing target URL for DAST',
        blocksNextStep: true,
        promptForUser: 'Please specify the exact URL you are authorized to test.',
      });
    }
  }

  // Fix phase requires existing report or run audit first
  if (mode === 'fix') {
    if (!options.existingReportExists) {
      boardDecisions.push({
        type: 'fix_execution',
        description: 'Phase 10 fix requested without prior audit report. Must execute audit first.',
        blocksNextStep: false,
        promptForUser: 'Executing audit phases first to produce an evidence-based findings ledger before applying fixes.',
      });
      // Start with standard audit then proceed to fix
    }
    boardDecisions.push({
      type: 'fix_execution',
      description: 'Phase 10 fixes will modify files in the repository and add regression tests.',
      blocksNextStep: true,
      promptForUser: 'Phase 10 will make targeted code repairs and create regression tests. Please confirm permission to edit repository files.',
    });
  }

  // Standard static audit default
  if (flags.length === 0) {
    flags.push('standard-static-audit');
  }

  assumptions.push('Repository code and configuration are treated as untrusted input.');
  assumptions.push('No plaintext secret values will ever be written to disk, context, or report.');
  if (mode !== 'fix') {
    assumptions.push('All audit operations are strictly read-only on the repository.');
  }

  const deliverable = mode === 'fix' 
    ? 'Root-cause remediation commits with failing-then-passing regression tests and updated rescore'
    : `Standardized SECURITY-KILL-${new Date().toISOString().slice(0, 10)}.md report with 0-10 scorecard`;

  const mandateMarkdown = renderMandateMarkdown({
    userGoal,
    flags,
    mode,
    depth,
    targetPath: path.resolve(targetPath),
    scopePaths,
    teamsFilter,
    domainOverride,
    compliance,
    diff,
    dastUrl,
    authorizationState,
    authorizedHost,
    deliverable,
    assumptions,
    boardDecisions,
    assuranceNote,
  });

  // Construct CEO announcement (2-3 lines in CEO voice, one voice to user)
  let ceoAnnouncement: string;
  if (boardDecisions.some((b) => b.blocksNextStep)) {
    const blocking = boardDecisions.find((b) => b.blocksNextStep)!;
    ceoAnnouncement = `Mandate accepted: ${userGoal} (${flags.join(', ')}).\nBefore specialist teams launch, a board decision is required:\n${blocking.promptForUser}`;
  } else {
    ceoAnnouncement = `Mandate accepted: ${userGoal}.\nDepth tier: ${depth}. Active flags: ${flags.join(', ')}.\nDispatching specialist teams to profile project and execute audit pipeline.`;
  }

  return {
    userGoal,
    flags,
    mode,
    depth,
    targetPath: path.resolve(targetPath),
    scopePaths,
    teamsFilter,
    domainOverride,
    compliance,
    diff,
    dastUrl,
    authorizationState,
    authorizedHost,
    deliverable,
    assumptions,
    boardDecisions,
    ceoAnnouncement,
    mandateMarkdown,
    assuranceNote,
  };
}

export function renderMandateMarkdown(intake: Omit<IntakeResult, 'mandateMarkdown' | 'ceoAnnouncement'>): string {
  return `# Mandate: Security Audit

- **Goal:** ${intake.userGoal}
- **Target Path:** \`${intake.targetPath}\`
- **Scope Paths:** ${intake.scopePaths.map((p) => `\`${p}\``).join(', ')}
- **Flags:** ${intake.flags.join(' ') || 'none (standard static audit)'}
- **Depth Tier:** ${intake.depth}
- **Mode:** ${intake.mode}
- **Authorization State:** ${intake.authorizationState}${intake.authorizedHost ? ` (host: ${intake.authorizedHost})` : ''}
- **Deliverable:** ${intake.deliverable}
${intake.assuranceNote ? `- **Assurance Notice:** ${intake.assuranceNote}\n` : ''}
## Assumptions
${intake.assumptions.map((a, i) => `${i + 1}. ${a}`).join('\n')}

## Board Decisions Still Open
${
  intake.boardDecisions.length === 0
    ? '_No open board decisions. Autonomous execution authorized._'
    : intake.boardDecisions
        .map((b, i) => `${i + 1}. **[${b.blocksNextStep ? 'BLOCKING' : 'INFO'}] ${b.type}:** ${b.description}`)
        .join('\n')
}
`.trim();
}

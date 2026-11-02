import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { ScoreResult, calculateSecurityScore, ScorePathStep } from './scoring.js';

export interface AuditFinding {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  where: string;
  attacker: string;
  team?: string;
  evidence: 'PROVEN' | 'TRACED' | 'LEAD' | 'DISPUTED';
  owasp: string;
  what: string;
  exploit: string;
  fix: string;
  regressionTest: string;
  siblings?: number;
  penalty?: string | number;
}

export interface SlopFinding {
  id: string;
  classId: string; // S01..S14
  title: string;
  where: string;
  team: string;
  description: string;
}

export interface SectionHeatMapEntry {
  id: string;
  name: string;
  ownerTeam: string;
  score: number;
  topFinding?: string;
}

export interface ReportOptions {
  targetPath: string;
  projectName?: string;
  depthTier?: 'quick' | 'standard' | 'deep';
  verdict: string;
  scorecard?: {
    securityScore: number;
    band: string;
    assuranceLevel: string;
    assuranceNumber: number;
    ceiling: number;
    slopScore: number;
    bindingCap?: string | null;
    teamScores?: Record<string, number>;
    weightsChanged?: string;
    status?: string;
  };
  pathToBetterScore?: ScorePathStep[];
  sectionHeatMap?: SectionHeatMapEntry[];
  attackPaths: string[];
  findings: AuditFinding[];
  slopFindings?: SlopFinding[];
  notFindings?: string[];
  notVerified?: string[];
  scoringDetail?: {
    penaltyTable?: string;
    capTable?: string;
    assuranceInputs?: string;
  };
  coverage: {
    roster?: string[];
    scopeSetByUser?: string[];
    sectionsAttacked: string[];
    sectionsSkipped: string[];
    toolsRun: string[];
    instructionsIgnored?: string[];
  };
  complianceAppendix?: string;
}

export interface ReportResult {
  reportPath: string;
  reportContent: string;
  date: string;
}

function getTodayDate(): string {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function getCommitSha(targetPath: string): string {
  try {
    return execSync('git rev-parse --short HEAD', {
      cwd: targetPath,
      stdio: ['pipe', 'pipe', 'pipe'],
      encoding: 'utf-8',
    }).trim();
  } catch {
    return 'uncommitted/non-git';
  }
}

function ensureGitignoreEntry(targetPath: string): void {
  const gitignorePath = path.join(targetPath, '.gitignore');
  const entry = 'SECURITY-AUDIT-*.md';

  if (!fs.existsSync(gitignorePath)) {
    fs.writeFileSync(gitignorePath, `${entry}\n`, 'utf-8');
    return;
  }

  const content = fs.readFileSync(gitignorePath, 'utf-8');
  if (!content.includes('SECURITY-AUDIT-')) {
    const updated = content.endsWith('\n') ? `${content}${entry}\n` : `${content}\n${entry}\n`;
    fs.writeFileSync(gitignorePath, updated, 'utf-8');
  }
}

/**
 * Generates and saves a standardized, evidence-graded security audit report following references/report-template.md.
 */
export async function generateAuditReport(options: ReportOptions): Promise<ReportResult> {
  const targetDir = path.resolve(options.targetPath);
  const date = getTodayDate();
  const sha = getCommitSha(targetDir);
  const projectName = options.projectName || path.basename(targetDir);
  const depthTier = options.depthTier || 'standard';

  // Ensure gitignore rule exists so reports are never committed
  ensureGitignoreEntry(targetDir);

  const lines: string[] = [];
  lines.push(`# Security Audit: ${projectName}`);
  lines.push(`${date} | commit ${sha} | depth tier ${depthTier} | facts checked ${date}\n`);

  // Scorecard
  lines.push('## Scorecard');
  if (options.scorecard) {
    const sc = options.scorecard;
    lines.push(`Security score: ${sc.securityScore.toFixed(1)} / 10   Band: ${sc.band}`);
    lines.push(`Assurance: ${sc.assuranceLevel} (${sc.assuranceNumber})   Ceiling: ${sc.ceiling}   Slop score: ${sc.slopScore.toFixed(1)} / 10`);
    lines.push(`Binding cap: ${sc.bindingCap || 'none'}`);
    if (sc.teamScores) {
      const teamLine = Object.entries(sc.teamScores).map(([t, s]) => `${t} ${s.toFixed(1)}`).join(' | ');
      lines.push(`Team scores: ${teamLine}`);
    }
    lines.push(`Weights changed from default: ${sc.weightsChanged || 'none'}`);
    lines.push(`Status: ${sc.status || 'Final'}\n`);
  } else {
    // Generate an automatic score if not explicitly passed
    const autoScore = calculateSecurityScore({
      findings: options.findings.map((f) => ({
        id: f.id,
        team: f.team || 'T03',
        severity: f.severity,
        evidence: f.evidence,
        reach: 'authenticated',
        asset: 'personal_data',
      })),
    });
    lines.push(`Security score: ${autoScore.overallScore.toFixed(1)} / 10   Band: ${autoScore.band}`);
    lines.push(`Assurance: ${autoScore.assurance.level} (${autoScore.assurance.score})   Ceiling: ${autoScore.assurance.ceiling}   Slop score: ${autoScore.slopScore.toFixed(1)} / 10`);
    lines.push(`Binding cap: ${autoScore.bindingCap || 'none'}`);
    lines.push(`Status: ${autoScore.status}\n`);
  }

  lines.push('## Verdict');
  lines.push(`${options.verdict}\n`);

  lines.push('## Path to a better score');
  if (options.pathToBetterScore && options.pathToBetterScore.length > 0) {
    lines.push('| If you fix | Score becomes | Why it moves |');
    lines.push('|---|---|---|');
    for (const step of options.pathToBetterScore) {
      lines.push(`| ${step.ifYouFix} | ${step.scoreBecomes.toFixed(1)} | ${step.whyItMoves} |`);
    }
    lines.push('');
  } else {
    lines.push('Fix top-priority findings to remove binding score caps and improve assurance.\n');
  }

  lines.push('## Attack paths');
  if (options.attackPaths.length === 0) {
    lines.push('No viable chained attack paths identified during this review.\n');
  } else {
    options.attackPaths.forEach((ap, idx) => {
      lines.push(`${idx + 1}. ${ap}`);
    });
    lines.push('');
  }

  if (options.sectionHeatMap && options.sectionHeatMap.length > 0) {
    lines.push('## Section heat map');
    lines.push('| Section ID | Name | Owner Team | Section Score | Top Finding |');
    lines.push('|---|---|---|---|---|');
    for (const shm of options.sectionHeatMap) {
      lines.push(`| ${shm.id} | ${shm.name} | ${shm.ownerTeam} | ${shm.score.toFixed(1)} | ${shm.topFinding || 'None'} |`);
    }
    lines.push('');
  }

  lines.push('## Findings');
  if (options.findings.length === 0) {
    lines.push('Zero verified Critical or High findings identified in the tested scope.\n');
  } else {
    for (const f of options.findings) {
      lines.push(`### [${f.severity}] ${f.id} ${f.title}`);
      lines.push(`Where: ${f.where}`);
      lines.push(`Team: ${f.team || 'T03'} | Attacker: ${f.attacker}`);
      lines.push(`Evidence: ${f.evidence}`);
      lines.push(`OWASP: ${f.owasp}`);
      lines.push(`What: ${f.what}`);
      lines.push(`Exploit: ${f.exploit}`);
      lines.push(`Fix: ${f.fix}`);
      lines.push(`Regression test: ${f.regressionTest}`);
      if (f.siblings !== undefined) lines.push(`Siblings: ${f.siblings}`);
      if (f.penalty !== undefined) lines.push(`Penalty: ${f.penalty}`);
      lines.push('');
    }
  }

  lines.push('## Slop findings');
  if (!options.slopFindings || options.slopFindings.length === 0) {
    lines.push('Zero confirmed AI slop patterns identified.\n');
  } else {
    for (const sf of options.slopFindings) {
      lines.push(`- **[${sf.classId}] ${sf.id} ${sf.title}** (${sf.where}): ${sf.description} (Owner: ${sf.team})`);
    }
    lines.push('');
  }

  lines.push('## Not findings');
  if (!options.notFindings || options.notFindings.length === 0) {
    lines.push('None recorded.\n');
  } else {
    options.notFindings.forEach((nf) => lines.push(`- ${nf}`));
    lines.push('');
  }

  lines.push('## Not verified');
  if (!options.notVerified || options.notVerified.length === 0) {
    lines.push('None recorded.\n');
  } else {
    options.notVerified.forEach((nv) => lines.push(`- ${nv}`));
    lines.push('');
  }

  if (options.scoringDetail) {
    lines.push('## Scoring detail');
    if (options.scoringDetail.penaltyTable) lines.push(options.scoringDetail.penaltyTable);
    if (options.scoringDetail.capTable) lines.push(options.scoringDetail.capTable);
    if (options.scoringDetail.assuranceInputs) lines.push(options.scoringDetail.assuranceInputs);
    lines.push('');
  }

  lines.push('## Coverage');
  if (options.coverage.roster) {
    lines.push(`- Active Roster: ${options.coverage.roster.join(', ')}`);
  }
  if (options.coverage.scopeSetByUser) {
    lines.push(`- Scope set by user: ${options.coverage.scopeSetByUser.join(', ')}`);
  }
  lines.push(`- Sections Attacked: ${options.coverage.sectionsAttacked.join(', ') || 'None'}`);
  lines.push(`- Sections Skipped: ${options.coverage.sectionsSkipped.join(', ') || 'None'}`);
  lines.push(`- Tools Status: ${options.coverage.toolsRun.join(', ') || 'None'}`);
  if (options.coverage.instructionsIgnored && options.coverage.instructionsIgnored.length > 0) {
    lines.push(`- Instructions found in repo and ignored: ${options.coverage.instructionsIgnored.join(', ')}`);
  }
  lines.push('');

  lines.push('## Limitations');
  lines.push(
    `- This audit misses more than it finds. Scanners cover their own rule sets and nothing beyond. LLM review misses real bugs and returns different verdicts on the same code across runs. A clean report means the checks which ran found nothing. It is not evidence of safety, and nobody should summarize it this way.`
  );
  lines.push(`- The score is an estimate from a house method. Two runs might differ. It measures one snapshot of one commit. It is not a certification.`);
  lines.push(`- Findings skew toward low and medium. Do not imply otherwise.`);
  lines.push(`- Results are not reproducible. State this in any compliance appendix, because an auditor will ask.`);
  lines.push(`- Runtime behavior is invisible to static review. A dependency which fetches its payload at install or run time shows nothing malicious on disk.`);
  lines.push(`- This is not a penetration test. Business-logic flaws, chained exploits and creative attacker reasoning still need a human.`);
  lines.push(`- Slop detection finds patterns. It does not show who wrote the code.\n`);

  if (options.complianceAppendix) {
    lines.push('## Appendix (only with --compliance)');
    lines.push('> Caveat: This appendix provides evidence for technical controls, not regulatory certification.\n');
    lines.push(options.complianceAppendix);
    lines.push('');
  }

  const reportContent = lines.join('\n');
  let filename = `SECURITY-AUDIT-${date}.md`;
  let reportPath = path.join(targetDir, filename);

  // Suffix if already exists for today
  if (fs.existsSync(reportPath)) {
    let suffix = 1;
    while (fs.existsSync(path.join(targetDir, `SECURITY-AUDIT-${date}-${suffix}.md`))) {
      suffix++;
    }
    filename = `SECURITY-AUDIT-${date}-${suffix}.md`;
    reportPath = path.join(targetDir, filename);
  }

  fs.writeFileSync(reportPath, reportContent, 'utf-8');

  return {
    reportPath,
    reportContent,
    date,
  };
}

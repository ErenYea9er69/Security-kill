import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

export interface AuditFinding {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  where: string;
  attacker: string;
  evidence: 'PROVEN' | 'TRACED' | 'LEAD' | 'DISPUTED';
  owasp: string;
  what: string;
  exploit: string;
  fix: string;
  regressionTest: string;
}

export interface ReportOptions {
  targetPath: string;
  projectName?: string;
  verdict: string;
  attackPaths: string[];
  findings: AuditFinding[];
  notFindings?: string[];
  notVerified?: string[];
  coverage: {
    sectionsAttacked: string[];
    sectionsSkipped: string[];
    toolsRun: string[];
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
 * Generates and saves a standardized, evidence-graded security audit report.
 */
export async function generateAuditReport(options: ReportOptions): Promise<ReportResult> {
  const targetDir = path.resolve(options.targetPath);
  const date = getTodayDate();
  const sha = getCommitSha(targetDir);
  const projectName = options.projectName || path.basename(targetDir);

  // Ensure gitignore rule exists so reports are never committed
  ensureGitignoreEntry(targetDir);

  const lines: string[] = [];
  lines.push(`# Security Audit: ${projectName}`);
  lines.push(`${date} | commit ${sha} | tools run: ${options.coverage.toolsRun.join(', ') || 'native static review'} | facts checked on ${date}\n`);

  lines.push('## Verdict');
  lines.push(`${options.verdict}\n`);

  lines.push('## Attack paths');
  if (options.attackPaths.length === 0) {
    lines.push('No viable chained attack paths identified during this review.\n');
  } else {
    options.attackPaths.forEach((ap, idx) => {
      lines.push(`${idx + 1}. ${ap}`);
    });
    lines.push('');
  }

  lines.push('## Findings');
  if (options.findings.length === 0) {
    lines.push('Zero verified Critical or High findings identified in the tested scope.\n');
  } else {
    for (const f of options.findings) {
      lines.push(`### [${f.severity}] ${f.id} ${f.title}`);
      lines.push(`Where: ${f.where}`);
      lines.push(`Attacker: ${f.attacker}`);
      lines.push(`Evidence: ${f.evidence}`);
      lines.push(`OWASP: ${f.owasp}`);
      lines.push(`What: ${f.what}`);
      lines.push(`Exploit: ${f.exploit}`);
      lines.push(`Fix: ${f.fix}`);
      lines.push(`Regression test: ${f.regressionTest}\n`);
    }
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

  lines.push('## Coverage');
  lines.push(`- Sections Attacked: ${options.coverage.sectionsAttacked.join(', ') || 'None'}`);
  lines.push(`- Sections Skipped: ${options.coverage.sectionsSkipped.join(', ') || 'None'}`);
  lines.push(`- Tools Status: ${options.coverage.toolsRun.join(', ') || 'None'}\n`);

  lines.push('## Limitations');
  lines.push(
    `- This audit misses more than it finds. Scanners cover their own rule sets and nothing beyond. LLM review misses real bugs and returns different verdicts on the same code across runs. A clean report means the checks which ran found nothing. It is not evidence of safety, and nobody should summarize it this way.`
  );
  lines.push(`- Findings skew toward low and medium. Do not imply otherwise.`);
  lines.push(`- Results are not reproducible. Two runs might return two finding sets. State this in any compliance appendix, because an auditor will ask.`);
  lines.push(`- Runtime behavior is invisible to static review. A dependency which fetches its payload at install or run time shows nothing malicious on disk.`);
  lines.push(`- This is not a penetration test. Business-logic flaws, chained exploits and creative attacker reasoning still need a human.\n`);

  if (options.complianceAppendix) {
    lines.push('## Appendix: Compliance Mapping (Evidence Only)');
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


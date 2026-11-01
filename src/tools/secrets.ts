import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execSync } from 'node:child_process';

export interface SecretFinding {
  file: string;
  line: number;
  type: string;
  redacted: string;
  snippet: string;
  source: 'regex' | 'gitleaks';
}

export interface SecretScanResult {
  targetPath: string;
  findings: SecretFinding[];
  scannedFilesCount: number;
  summary: string;
}

/**
 * Strictly redacts a secret string: preserves only the first 4 characters and appends ellipsis.
 * E.g., 'AKIA1234567890ABCDEF' -> 'AKIA...'
 */
export function redactSecret(secret: string): string {
  if (!secret || secret.length === 0) return '***';
  if (secret.length <= 4) return secret.slice(0, 2) + '...';
  return secret.slice(0, 4) + '...';
}

interface SecretPattern {
  name: string;
  regex: RegExp;
}

const HIGH_RISK_PATTERNS: SecretPattern[] = [
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'Stripe Secret Key', regex: /sk_(live|test)_[0-9a-zA-Z]{24,}/g },
  { name: 'OpenAI API Key', regex: /sk-[A-Za-z0-9]{20,}/g },
  { name: 'GitHub Personal Access Token', regex: /(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})/g },
  { name: 'Supabase Secret / Service Role Key', regex: /(sb_secret_[a-zA-Z0-9_-]+|eyJhbGciOi[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)/g },
  { name: 'Private Key Block', regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { name: 'Generic API Key / Token Assignment', regex: /(?:secret|token|api_key|password)\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{20,})['"]/gi },
];

const IGNORED_DIRS = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  '.next',
  '.turbo',
  'coverage',
  '.superpowers',
]);

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.tar', '.gz', '.exe', '.dll', '.so', '.dylib', '.woff', '.woff2', '.ttf', '.eot'
]);

function shouldScanFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return !BINARY_EXTENSIONS.has(ext);
}

function walkDir(dir: string, fileList: string[] = []): string[] {
  if (!fs.existsSync(dir)) return fileList;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!IGNORED_DIRS.has(entry.name)) {
        walkDir(path.join(dir, entry.name), fileList);
      }
    } else if (entry.isFile()) {
      const fullPath = path.join(dir, entry.name);
      if (shouldScanFile(fullPath)) {
        fileList.push(fullPath);
      }
    }
  }
  return fileList;
}

/**
 * Scans a target path for exposed secrets, enforcing strict redaction on all matches.
 */
export async function scanSecrets(
  targetPath: string,
  options: { scanGitHistory?: boolean; scanBundles?: boolean } = {}
): Promise<SecretScanResult> {
  const resolvedTarget = path.resolve(targetPath);
  const findings: SecretFinding[] = [];
  const scannedFiles = walkDir(resolvedTarget);

  for (const filePath of scannedFiles) {
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > 2 * 1024 * 1024) continue; // skip files > 2MB

      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
        const line = lines[lineIndex];

        for (const pattern of HIGH_RISK_PATTERNS) {
          pattern.regex.lastIndex = 0;
          let match: RegExpExecArray | null;

          while ((match = pattern.regex.exec(line)) !== null) {
            const rawSecret = match[1] || match[0];
            if (!rawSecret || rawSecret.length < 8) continue;
            // Ignore common false positives/placeholders
            if (rawSecret.includes('YOUR_') || rawSecret.includes('EXAMPLE') || rawSecret.includes('placeholder')) {
              continue;
            }

            const redacted = redactSecret(rawSecret);
            // Replace full secret in snippet with redacted representation
            const safeSnippet = line.replace(rawSecret, redacted).trim();

            findings.push({
              file: path.relative(resolvedTarget, filePath),
              line: lineIndex + 1,
              type: pattern.name,
              redacted,
              snippet: safeSnippet,
              source: 'regex',
            });
          }
        }
      }
    } catch {
      // skip unreadable files
    }
  }

  // Try gitleaks if installed and user requested history or working tree pass
  let gitleaksOutput = '';
  try {
    const gitLeaksCheck = execSync('gitleaks version', { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' });
    if (gitLeaksCheck) {
      const tmpReport = path.join(os.tmpdir(), `gitleaks-${Date.now()}.json`);
      try {
        const gitLeaksCmd = options.scanGitHistory
          ? `gitleaks detect --source "${resolvedTarget}" --redact --report-format json --report-path "${tmpReport}"`
          : `gitleaks dir "${resolvedTarget}" --no-git --redact --report-format json --report-path "${tmpReport}"`;
        execSync(gitLeaksCmd, { stdio: ['pipe', 'pipe', 'pipe'], timeout: 30000 });
      } catch {
        // gitleaks exits with non-zero on findings
      }

      if (fs.existsSync(tmpReport)) {
        try {
          const rawReport = JSON.parse(fs.readFileSync(tmpReport, 'utf-8'));
          if (Array.isArray(rawReport)) {
            for (const item of rawReport) {
              const rawMatch = item.Match || item.Secret || '';
              findings.push({
                file: item.File || 'unknown',
                line: item.StartLine || 1,
                type: item.Description || item.RuleID || 'Gitleaks Finding',
                redacted: redactSecret(rawMatch),
                snippet: (item.Match || '').slice(0, 30) + '...',
                source: 'gitleaks',
              });
            }
          }
        } finally {
          fs.rmSync(tmpReport, { force: true });
        }
      }
    }
  } catch {
    // gitleaks not available or failed; fallback regex scan is already populated
  }

  return {
    targetPath: resolvedTarget,
    findings,
    scannedFilesCount: scannedFiles.length,
    summary: findings.length === 0
      ? `Scan clean across ${scannedFiles.length} files. Zero secrets detected.`
      : `Detected ${findings.length} potential secret(s) across ${scannedFiles.length} files. All secrets redacted.`,
  };
}

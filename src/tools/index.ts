export * from './preflight.js';
export * from './sectionMap.js';
export * from './secrets.js';
export * from './reporter.js';

import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

export interface SastFinding {
  file: string;
  line: number;
  rule: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  message: string;
  snippet?: string;
}

export interface SastScanResult {
  targetPath: string;
  engine: string;
  findings: SastFinding[];
  summary: string;
}

const COMMON_SAST_PATTERNS = [
  { rule: 'Dangerous Eval / Dynamic Execution', regex: /\b(eval|exec)\s*\(/g, severity: 'HIGH' as const, msg: 'Dynamic code execution with eval/exec' },
  { rule: 'React DangerouslySetInnerHTML', regex: /dangerouslySetInnerHTML\s*=/g, severity: 'MEDIUM' as const, msg: 'Potential XSS vector via dangerouslySetInnerHTML' },
  { rule: 'Insecure Command Execution', regex: /\b(child_process|subprocess)\.(exec|call|Popen)\s*\([^)]*shell\s*=\s*True/g, severity: 'HIGH' as const, msg: 'Shell execution with shell=True' },
  { rule: 'SQL Injection Lead (String Concatenation)', regex: /(SELECT|INSERT|UPDATE|DELETE)\s+.*(\+|%|\$)\s*[a-zA-Z0-9_]/gi, severity: 'HIGH' as const, msg: 'Possible unparameterized SQL query assembly' },
  { rule: 'Hardcoded JWT Secret', regex: /jwt\.verify\([^,]+,\s*['"][^'"]+['"]\)/g, severity: 'HIGH' as const, msg: 'Hardcoded secret in JWT verification' },
];

/**
 * Runs SAST analysis using Semgrep if available, with built-in regex fallback for common injection patterns.
 */
export async function runSastScan(targetPath: string, options: { config?: string } = {}): Promise<SastScanResult> {
  const resolved = path.resolve(targetPath);
  const findings: SastFinding[] = [];
  let engine = 'regex-fallback';

  // Check if Semgrep is installed
  let hasSemgrep = false;
  try {
    const isWindows = process.platform === 'win32';
    execSync(isWindows ? 'where semgrep' : 'command -v semgrep', { stdio: ['pipe', 'pipe', 'pipe'] });
    hasSemgrep = true;
  } catch {
    hasSemgrep = false;
  }

  if (hasSemgrep) {
    try {
      const config = options.config || 'p/security-audit';
      const output = execSync(`semgrep scan --config ${config} --json --metrics=off "${resolved}"`, {
        stdio: ['pipe', 'pipe', 'pipe'],
        encoding: 'utf-8',
        maxBuffer: 10 * 1024 * 1024,
      });
      const parsed = JSON.parse(output);
      if (parsed.results && Array.isArray(parsed.results)) {
        engine = 'semgrep';
        for (const r of parsed.results) {
          findings.push({
            file: path.relative(resolved, r.path),
            line: r.start?.line || 1,
            rule: r.check_id || 'Semgrep Rule',
            severity: r.extra?.severity === 'ERROR' ? 'HIGH' : 'MEDIUM',
            message: r.extra?.message || '',
            snippet: r.extra?.lines?.slice(0, 100),
          });
        }
      }
    } catch {
      // Semgrep failed or exited non-zero; fallback to pattern scan
    }
  }

  if (findings.length === 0 && engine === 'regex-fallback') {
    // Scan source files with common dangerous sinks
    const walk = (dir: string): string[] => {
      let results: string[] = [];
      if (!fs.existsSync(dir)) return results;
      const list = fs.readdirSync(dir, { withFileTypes: true });
      for (const file of list) {
        if (file.isDirectory()) {
          if (!['.git', 'node_modules', 'dist', 'build', '.next'].includes(file.name)) {
            results = results.concat(walk(path.join(dir, file.name)));
          }
        } else if (/\.(js|ts|jsx|tsx|py|go|rb|php)$/.test(file.name)) {
          results.push(path.join(dir, file.name));
        }
      }
      return results;
    };

    const files = walk(resolved);
    for (const f of files) {
      try {
        const text = fs.readFileSync(f, 'utf-8');
        const lines = text.split('\n');
        for (let idx = 0; idx < lines.length; idx++) {
          const line = lines[idx];
          for (const pat of COMMON_SAST_PATTERNS) {
            pat.regex.lastIndex = 0;
            if (pat.regex.test(line)) {
              findings.push({
                file: path.relative(resolved, f),
                line: idx + 1,
                rule: pat.rule,
                severity: pat.severity,
                message: pat.msg,
                snippet: line.trim().slice(0, 100),
              });
            }
          }
        }
      } catch {
        // skip unreadable
      }
    }
  }

  return {
    targetPath: resolved,
    engine,
    findings,
    summary: `SAST (${engine}): ${findings.length} potential issue(s) identified. Each finding requires manual triage against production entry points.`,
  };
}

export interface DepVulnFinding {
  package: string;
  version: string;
  cveOrId: string;
  severity: string;
  title: string;
}

export interface DepScanResult {
  targetPath: string;
  engine: string;
  findings: DepVulnFinding[];
  summary: string;
}

/**
 * Checks dependencies for known CVEs using available tools (e.g. npm audit or osv-scanner).
 */
export async function runDepsScan(targetPath: string): Promise<DepScanResult> {
  const resolved = path.resolve(targetPath);
  const findings: DepVulnFinding[] = [];
  let engine = 'none';

  // Check for package.json / npm audit
  if (fs.existsSync(path.join(resolved, 'package.json'))) {
    try {
      engine = 'npm-audit';
      const out = execSync('npm audit --json', {
        cwd: resolved,
        stdio: ['pipe', 'pipe', 'pipe'],
        encoding: 'utf-8',
      });
      const parsed = JSON.parse(out);
      if (parsed.vulnerabilities) {
        for (const [pkgName, v] of Object.entries<any>(parsed.vulnerabilities)) {
          findings.push({
            package: pkgName,
            version: v.range || 'unknown',
            cveOrId: v.via?.[0]?.url || 'Advisory',
            severity: String(v.severity || 'UNKNOWN').toUpperCase(),
            title: v.via?.[0]?.title || `Vulnerability in ${pkgName}`,
          });
        }
      }
    } catch (err: any) {
      if (err.stdout) {
        try {
          const parsed = JSON.parse(err.stdout);
          if (parsed.vulnerabilities) {
            for (const [pkgName, v] of Object.entries<any>(parsed.vulnerabilities)) {
              findings.push({
                package: pkgName,
                version: v.range || 'unknown',
                cveOrId: typeof v.via?.[0] === 'object' ? v.via[0].url || 'Advisory' : String(v.via?.[0] || 'Advisory'),
                severity: String(v.severity || 'UNKNOWN').toUpperCase(),
                title: typeof v.via?.[0] === 'object' ? v.via[0].title || `Vulnerability in ${pkgName}` : `Advisory for ${pkgName}`,
              });
            }
          }
        } catch {
          // ignore parse error
        }
      }
    }
  }

  return {
    targetPath: resolved,
    engine,
    findings,
    summary: findings.length === 0
      ? `Dependency scan (${engine}): zero vulnerabilities reported.`
      : `Dependency scan (${engine}): ${findings.length} advisory/vulnerability entries found.`,
  };
}


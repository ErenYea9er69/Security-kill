import fs from 'node:fs';
import path from 'node:path';

export interface SlopPatternLead {
  id: string;
  classId: string; // S01..S14
  title: string;
  file: string;
  line: number;
  snippet: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  ownerTeam: string;
  description: string;
}

export interface SlopScanResult {
  targetPath: string;
  scannedFilesCount: number;
  leads: SlopPatternLead[];
  summary: string;
}

interface SlopRule {
  classId: string;
  title: string;
  pattern: RegExp;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  ownerTeam: string;
  description: string;
}

const SLOP_RULES: SlopRule[] = [
  // S01: Phantom Security
  {
    classId: 'S01',
    title: 'Phantom Sanitizer / Dev Guard Bypass',
    pattern: /(?:function\s+)?(?:sanitize|validate|authorize|checkAuth|requireAuth)\w*\s*\([^)]*\)\s*\{[\s\n]*return\s+(?:true|[a-zA-Z_]\w*);?[\s\n]*\}|(?:sanitize|validate|authorize|checkAuth|requireAuth)\w*\s*=\s*(?:\([^)]*\)|[a-zA-Z_]\w*)\s*=>\s*(?:true|[a-zA-Z_]\w*)|return\s+true;?\s*\/\/\s*(?:for now|temporary|dev|skip|bypass)/gi,
    severity: 'HIGH',
    ownerTeam: 'T03',
    description: 'Security guard or sanitizer returns true or unescaped input without enforcing a check.',
  },
  {
    classId: 'S01',
    title: 'TODO / Unimplemented Security Guard',
    pattern: /(?:TODO|FIXME|HACK|XXX)[^\n]{0,60}(?:auth|permission|sanitiz|validat|csrf|rate.?limit|secur)/gi,
    severity: 'MEDIUM',
    ownerTeam: 'T03',
    description: 'Security-critical control marked as TODO, FIXME, or temporary stub.',
  },
  // S02: Placeholder Residue
  {
    classId: 'S02',
    title: 'Fallback Placeholder Credential',
    pattern: /(?:secret|token|password|passwd|api[_-]?key|jwt[_-]?secret)\w*\s*(?:=|:|\|\||\?\?)\s*['"](?:secret|changeme|password|admin|test|dev|demo|xxx|123456)/gi,
    severity: 'HIGH',
    ownerTeam: 'T09',
    description: 'Default or placeholder credential used in assignment or fallback expression.',
  },
  // S05: Fail-open and Swallowed Errors
  {
    classId: 'S05',
    title: 'Empty Catch / Silent Error Swallowing',
    pattern: /catch\s*(?:\([^)]*\))?\s*\{[\s\n]*\}|except[^:\n]*:\s*(?:pass|continue)\b|\.catch\(\s*(?:\(\s*\)|[a-zA-Z_]\w*)\s*=>\s*(?:\{[\s\n]*\}|null|true|undefined)\s*\)/gi,
    severity: 'HIGH',
    ownerTeam: 'T04',
    description: 'Empty catch block or swallowed exception that may cause authorization or validation to fail open.',
  },
  // S06: Fake Tests & Coverage Theater
  {
    classId: 'S06',
    title: 'Assertion Theater (Tautological Test)',
    pattern: /(?:assert\s+True|expect\(\s*true\s*\)\.toBe\(\s*true\s*\)|assert\(\s*true\s*\)|expect\(1\)\.toBe\(1\))/gi,
    severity: 'MEDIUM',
    ownerTeam: 'T13',
    description: 'Test contains tautological assertions (e.g. true === true) providing fake coverage without testing the guard.',
  },
  // S07: Over-Broad Defaults
  {
    classId: 'S07',
    title: 'Wildcard CORS / Security Disabled',
    pattern: /Access-Control-Allow-Origin.{0,20}\*|origin\s*:\s*(?:true|['"]\*['"])|trust proxy['"]?\s*[,:]\s*true|chmod\s+(-R\s+)?777/gi,
    severity: 'MEDIUM',
    ownerTeam: 'T08',
    description: 'Over-permissive default (e.g. wildcard CORS, trust proxy true, chmod 777).',
  },
  // S09: Weak Crypto by Habit
  {
    classId: 'S09',
    title: 'Insecure Random / Weak Crypto for Secrets',
    pattern: /Math\.random\(\)[^\n]{0,60}(?:token|secret|id|otp|code|key|password)|\b(?:md5|sha1)\b[^\n]{0,60}(?:password|passwd|hash)/gi,
    severity: 'HIGH',
    ownerTeam: 'T06',
    description: 'Math.random() or obsolete hash function used in token, password, or key generation.',
  },
  // S12: Suppression Slop
  {
    classId: 'S12',
    title: 'Build Error / Linter Security Suppression',
    pattern: /(?:ignoreBuildErrors|ignoreDuringBuilds)\s*:\s*true|(?:nosemgrep|#\s*nosec|@ts-ignore|@ts-expect-error|eslint-disable[^\n]{0,30}security)/gi,
    severity: 'LOW',
    ownerTeam: 'T08',
    description: 'Security linter, type checker, or build error suppression comment.',
  },
];

/**
 * Sweeps the target codebase for the 14 AI code failure classes (S01-S14) defined in references/slop-detection.md.
 */
export async function runSlopScan(targetPath: string): Promise<SlopScanResult> {
  const resolved = path.resolve(targetPath);
  const leads: SlopPatternLead[] = [];
  let fileCount = 0;

  const walk = (dir: string): string[] => {
    let files: string[] = [];
    if (!fs.existsSync(dir)) return files;
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const ent of entries) {
      if (ent.isDirectory()) {
        if (!['.git', 'node_modules', 'dist', 'build', '.next', '.superpowers', 'coverage'].includes(ent.name)) {
          files = files.concat(walk(path.join(dir, ent.name)));
        }
      } else if (/\.(js|ts|jsx|tsx|py|go|rb|php|java|cs|vue|svelte)$/i.test(ent.name)) {
        files.push(path.join(dir, ent.name));
      }
    }
    return files;
  };

  const candidateFiles = walk(resolved);
  fileCount = candidateFiles.length;

  let leadIndex = 1;
  for (const f of candidateFiles) {
    try {
      const content = fs.readFileSync(f, 'utf-8');
      for (const rule of SLOP_RULES) {
        // Reset regex state
        rule.pattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = rule.pattern.exec(content)) !== null) {
          const matchIndex = match.index;
          const lineNumber = content.slice(0, matchIndex).split('\n').length;
          const snippet = match[0].slice(0, 100).replace(/\r?\n/g, ' ').trim();

          leads.push({
            id: `SLOP-${String(leadIndex++).padStart(2, '0')}`,
            classId: rule.classId,
            title: rule.title,
            file: path.relative(resolved, f),
            line: lineNumber,
            snippet,
            severity: rule.severity,
            ownerTeam: rule.ownerTeam,
            description: rule.description,
          });

          // Prevent zero-length infinite loop
          if (match.index === rule.pattern.lastIndex) {
            rule.pattern.lastIndex++;
          }
        }
      }
    } catch {
      // skip unreadable
    }
  }

  return {
    targetPath: resolved,
    scannedFilesCount: fileCount,
    leads,
    summary: `Slop sweep: Scanned ${fileCount} source files. Found ${leads.length} lead(s) across AI failure patterns. Each lead requires manual trace before grading.`,
  };
}

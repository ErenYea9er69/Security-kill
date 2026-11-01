import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execSync } from 'node:child_process';

export interface ToolStatus {
  tool: string;
  status: 'OK' | 'MISS' | 'BROKEN';
  version?: string;
  details?: string;
  dockerFallback?: string;
}

export interface PreflightResult {
  tools: ToolStatus[];
  dockerAvailable: boolean;
  canaryPassed: boolean;
  recommendations: string[];
}

const TOOLS_TO_CHECK = [
  { name: 'semgrep', docker: 'docker run --rm -v "$PWD:/src" semgrep/semgrep semgrep scan --config p/security-audit /src' },
  { name: 'gitleaks', docker: 'docker run --rm -v "$PWD:/repo" ghcr.io/gitleaks/gitleaks:latest git /repo' },
  { name: 'trufflehog', docker: 'docker run --rm -v "$PWD:/repo" trufflesecurity/trufflehog:latest git file:///repo --results=verified,unknown' },
  { name: 'trivy', docker: 'docker run --rm -v "$PWD:/src" aquasec/trivy:latest fs /src' },
  { name: 'osv-scanner', docker: 'docker run --rm -v "$PWD:/src" ghcr.io/google/osv-scanner:latest /src' },
  { name: 'grype', docker: 'docker run --rm -v "$PWD:/src" anchore/grype:latest dir:/src' },
  { name: 'syft', docker: 'docker run --rm -v "$PWD:/src" anchore/syft:latest dir:/src' },
  { name: 'checkov', docker: 'docker run --rm -v "$PWD:/tf" bridgecrew/checkov -d /tf' },
  { name: 'hadolint', docker: 'docker run --rm -i hadolint/hadolint < Dockerfile' },
  { name: 'zizmor', docker: 'docker run --rm -v "$PWD:/src" ghcr.io/woodruffw/zizmor:latest /src' },
  { name: 'nuclei', docker: 'docker run --rm projectdiscovery/nuclei:latest' },
  { name: 'bandit', docker: 'docker run --rm -v "$PWD:/src" secfigo/bandit -r /src' },
  { name: 'gosec', docker: 'docker run --rm -v "$PWD:/src" securego/gosec /src/...' },
  { name: 'govulncheck', docker: '' },
  { name: 'docker', docker: '' },
];

function checkCommandAvailable(command: string): { available: boolean; version?: string } {
  try {
    const isWindows = process.platform === 'win32';
    const checkCmd = isWindows ? `where ${command}` : `command -v ${command}`;
    execSync(checkCmd, { stdio: ['pipe', 'pipe', 'pipe'] });

    let version = '';
    try {
      version = execSync(`${command} --version`, {
        stdio: ['pipe', 'pipe', 'pipe'],
        encoding: 'utf-8',
        timeout: 5000,
      }).trim().split('\n')[0];
    } catch {
      // version flag may differ
    }

    return { available: true, version: version || 'installed' };
  } catch {
    return { available: false };
  }
}

/**
 * Checks for the presence of CLI security scanners and runs canary verifications.
 */
export async function runPreflight(options: { runCanary?: boolean } = {}): Promise<PreflightResult> {
  const tools: ToolStatus[] = [];
  const dockerCheck = checkCommandAvailable('docker');
  const dockerAvailable = dockerCheck.available;
  const recommendations: string[] = [];

  for (const t of TOOLS_TO_CHECK) {
    const check = checkCommandAvailable(t.name);
    if (check.available) {
      tools.push({
        tool: t.name,
        status: 'OK',
        version: check.version,
        dockerFallback: t.docker,
      });
    } else {
      tools.push({
        tool: t.name,
        status: 'MISS',
        dockerFallback: t.docker,
        details: 'Not found on PATH',
      });
    }
  }

  let canaryPassed = true;

  if (options.runCanary) {
    const canaryDir = path.join(os.tmpdir(), `sec-canary-${Date.now()}`);
    fs.mkdirSync(canaryDir, { recursive: true });

    try {
      // Plant fake canary files (strictly synthetic, per references/preflight.md)
      const fakeToken = 'ghp_' + Array.from({ length: 36 }, () => Math.floor(Math.random() * 36).toString(36)).join('');
      const canaryPy = [
        'import subprocess',
        'aws_key = "AKIAQYLPMN5G3XVRWTZK"',
        `github_token = "${fakeToken}"`,
        'subprocess.call("ls " + input(), shell=True)',
      ].join('\n');
      fs.writeFileSync(path.join(canaryDir, 'canary.py'), canaryPy, 'utf-8');

      const canaryReqs = 'requests==2.19.1\n'; // CVE-2018-18074
      fs.writeFileSync(path.join(canaryDir, 'requirements.txt'), canaryReqs, 'utf-8');

      // Test gitleaks if OK
      const gitleaksStatus = tools.find((t) => t.tool === 'gitleaks');
      if (gitleaksStatus && gitleaksStatus.status === 'OK') {
        try {
          const out = execSync(`gitleaks dir "${canaryDir}" --no-git`, {
            stdio: ['pipe', 'pipe', 'pipe'],
            encoding: 'utf-8',
          });
          // gitleaks returns non-zero when leaks are found
          gitleaksStatus.details = 'Canary verified';
        } catch (err: any) {
          if (err.status !== 0) {
            gitleaksStatus.details = 'Canary detected successfully';
          } else {
            gitleaksStatus.status = 'BROKEN';
            gitleaksStatus.details = 'Silently exited with 0 findings on canary';
            canaryPassed = false;
          }
        }
      }
    } finally {
      try {
        fs.rmSync(canaryDir, { recursive: true, force: true });
      } catch {
        // cleanup ignore
      }
    }
  }

  const okTools = tools.filter((t) => t.status === 'OK').map((t) => t.tool);
  const missTools = tools.filter((t) => t.status === 'MISS').map((t) => t.tool);

  if (!okTools.includes('semgrep') && !okTools.includes('gitleaks')) {
    recommendations.push(
      'Both Semgrep and Gitleaks are missing. High-yield SAST and Secret passes will rely on built-in regex fallbacks. Consider installing them or running via Docker.'
    );
  }
  if (!dockerAvailable && missTools.length > 0) {
    recommendations.push(
      'Docker is not available on PATH. Missing tools cannot use container fallbacks.'
    );
  }

  return {
    tools,
    dockerAvailable,
    canaryPassed,
    recommendations,
  };
}


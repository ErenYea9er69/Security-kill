import fs from 'node:fs';
import path from 'node:path';
import { TaskOrder, ToolLaunchOrder, WorkerReturn, WorkerClaim } from './templates.js';
import { TOOL_ROSTER } from './roster.js';

export type RejectionCode = 'R1' | 'R2' | 'R3' | 'R4' | 'R5' | 'R6' | 'R7' | 'R8';

export interface GateDefect {
  code: RejectionCode;
  claimId?: string;
  description: string;
}

export interface GateResult {
  gate: 'G0' | 'G1' | 'G2' | 'G3' | 'G4' | 'G5' | 'G6' | 'G7';
  passed: boolean;
  defects: GateDefect[];
  summary: string;
  details?: Record<string, any>;
}

export interface GateLogEntry {
  returnId: string;
  gate: string;
  result: 'pass' | 'fail';
  defects: string;
  reworkRound: number;
  date: string;
}

/**
 * G0: Order Gate (Executed by CEO / O02 before dispatching)
 */
export function verifyG0Order(order: TaskOrder | ToolLaunchOrder): GateResult {
  const defects: GateDefect[] = [];

  if ('slice' in order) {
    // TaskOrder validation
    if (!order.mission || order.mission.trim().length === 0) {
      defects.push({ code: 'R1', description: 'Missing mission statement in order' });
    }
    if (!order.slice || order.slice.trim().length === 0) {
      defects.push({ code: 'R1', description: 'Missing slice definition' });
    }
    if (!order.doneTest || order.doneTest.trim().length === 0) {
      defects.push({ code: 'R1', description: 'Missing done test in order' });
    }
    if (!order.staffAllowed || order.staffAllowed.length === 0) {
      defects.push({ code: 'R1', description: 'Missing staff allowed scope' });
    }
  } else {
    // ToolLaunchOrder validation
    if (!order.command || order.command.trim().length === 0) {
      defects.push({ code: 'R1', description: 'Missing command in tool launch' });
    }
    if (!order.outputPath || order.outputPath.trim().length === 0) {
      defects.push({ code: 'R1', description: 'Missing output path in tool launch' });
    }
    if (!order.timeoutSeconds || order.timeoutSeconds <= 0) {
      defects.push({ code: 'R1', description: 'Missing or invalid timeout in tool launch' });
    }
  }

  const passed = defects.length === 0;
  return {
    gate: 'G0',
    passed,
    defects,
    summary: passed ? 'Order passed G0 order gate' : `Order failed G0: ${defects.map((d) => d.description).join('; ')}`,
  };
}

/**
 * G1: Form Gate (Executed by O01 on every worker return)
 */
export function verifyG1Form(workerReturn: WorkerReturn): GateResult {
  const defects: GateDefect[] = [];

  if (!workerReturn.id) {
    defects.push({ code: 'R1', description: 'Return missing order ID' });
  }
  if (!workerReturn.worker) {
    defects.push({ code: 'R1', description: 'Return missing worker name/ID' });
  }

  // Check claims
  for (const c of workerReturn.claims) {
    if (!c.id) {
      defects.push({ code: 'R1', description: 'Claim missing ID' });
    }
    if (!c.claim || c.claim.trim().length === 0) {
      defects.push({ code: 'R1', claimId: c.id, description: 'Claim text is empty' });
    }
    if (!['PROVEN', 'TRACED', 'LEAD', 'DISPUTED'].includes(c.grade)) {
      defects.push({ code: 'R1', claimId: c.id, description: `Invalid evidence grade '${c.grade}'` });
    }
    if (!c.evidence || c.evidence.trim().length === 0) {
      defects.push({ code: 'R1', claimId: c.id, description: 'Claim missing evidence field' });
    }
  }

  // Completeness check vs Did Not Do
  if (
    workerReturn.status === 'complete' &&
    workerReturn.didNotDo &&
    workerReturn.didNotDo.trim().toLowerCase() !== 'nothing' &&
    workerReturn.didNotDo.trim().toLowerCase() !== 'none'
  ) {
    defects.push({
      code: 'R1',
      description: `Status declared 'complete' but 'did not do' lists omitted work: '${workerReturn.didNotDo}'`,
    });
  }

  // Instruction-like text safety
  if (
    workerReturn.instructionLikeTextFound &&
    workerReturn.instructionLikeTextFound.trim().toLowerCase() !== 'none'
  ) {
    // If worker obeyed instruction, flag R7
    if (workerReturn.rawText && /obeyed|followed instruction/i.test(workerReturn.rawText)) {
      defects.push({
        code: 'R7',
        description: `Hostile text in repository was obeyed: '${workerReturn.instructionLikeTextFound}'`,
      });
    }
  }

  const passed = defects.length === 0;
  return {
    gate: 'G1',
    passed,
    defects,
    summary: passed ? 'Return passed G1 form gate' : `Return failed G1: ${defects.map((d) => d.description).join('; ')}`,
  };
}

/**
 * G2: Citation Gate (Executed by O01, opening files in repository)
 */
export function verifyG2Citation(workerReturn: WorkerReturn, repoRoot: string): GateResult {
  const defects: GateDefect[] = [];

  for (const c of workerReturn.claims) {
    // Look for file:line patterns
    const citations = c.evidence.match(/([a-zA-Z0-9_\-./\\]+\.[a-zA-Z0-9]+)(?::(\d+))?/g);
    if (!citations || citations.length === 0) {
      if (c.grade === 'PROVEN' || c.grade === 'TRACED') {
        defects.push({
          code: 'R2',
          claimId: c.id,
          description: `Evidence lacks traceable file:line citation for ${c.grade} claim: '${c.evidence}'`,
        });
      }
      continue;
    }

    for (const citation of citations) {
      const [filePath, lineStr] = citation.split(':');
      const resolved = path.resolve(repoRoot, filePath);

      if (!fs.existsSync(resolved)) {
        defects.push({
          code: 'R2',
          claimId: c.id,
          description: `Cited file does not exist: '${filePath}'`,
        });
        continue;
      }

      if (lineStr) {
        const lineNum = parseInt(lineStr, 10);
        try {
          const content = fs.readFileSync(resolved, 'utf-8');
          const lines = content.split(/\r?\n/);
          if (lineNum <= 0 || lineNum > lines.length) {
            defects.push({
              code: 'R2',
              claimId: c.id,
              description: `Line ${lineNum} out of bounds for '${filePath}' (total lines: ${lines.length})`,
            });
          }
        } catch (err: any) {
          defects.push({
            code: 'R2',
            claimId: c.id,
            description: `Could not read cited file '${filePath}': ${err.message}`,
          });
        }
      }
    }
  }

  const passed = defects.length === 0;
  return {
    gate: 'G2',
    passed,
    defects,
    summary: passed ? 'Return passed G2 citation gate' : `Return failed G2: ${defects.map((d) => d.description).join('; ')}`,
  };
}

/**
 * G3: Identifier & Fact Gate (Executed by O01)
 */
export function verifyG3Identifier(workerReturn: WorkerReturn): GateResult {
  const defects: GateDefect[] = [];

  for (const c of workerReturn.claims) {
    // Detect CVE patterns
    const cveMatches = c.claim.match(/CVE-\d{4}-\d{4,7}/gi);
    if (cveMatches) {
      for (const cve of cveMatches) {
        if (!c.evidence.toLowerCase().includes('advisory') && !c.evidence.toLowerCase().includes('http') && !c.evidence.toLowerCase().includes('osv')) {
          defects.push({
            code: 'R3',
            claimId: c.id,
            description: `CVE ID ${cve} cited without an authoritative advisory source link in evidence`,
          });
        }
      }
    }
  }

  const passed = defects.length === 0;
  return {
    gate: 'G3',
    passed,
    defects,
    summary: passed ? 'Return passed G3 identifier gate' : `Return failed G3: ${defects.map((d) => d.description).join('; ')}`,
  };
}

/**
 * G4: Run Gate (Executed by O01 with O02 for tool execution claims)
 */
export function verifyG4Run(workerReturn: WorkerReturn, baseScanDir?: string): GateResult {
  const defects: GateDefect[] = [];

  for (const c of workerReturn.claims) {
    if (c.artifact && c.artifact.toLowerCase() !== 'none') {
      const artifactPath = baseScanDir ? path.resolve(baseScanDir, c.artifact) : path.resolve(c.artifact);
      if (!fs.existsSync(artifactPath)) {
        defects.push({
          code: 'R4',
          claimId: c.id,
          description: `Claimed tool artifact does not exist: '${c.artifact}'`,
        });
      }
    }
  }

  const passed = defects.length === 0;
  return {
    gate: 'G4',
    passed,
    defects,
    summary: passed ? 'Return passed G4 run gate' : `Return failed G4: ${defects.map((d) => d.description).join('; ')}`,
  };
}

/**
 * G5: Known-Answer Gate (Sample mutation verification)
 */
export function verifyG5KnownAnswer(options: {
  testedSection: string;
  plantedFlawCaught: boolean;
  repeatedFalsePremise?: boolean;
}): GateResult {
  const defects: GateDefect[] = [];

  if (!options.plantedFlawCaught) {
    defects.push({
      code: 'R5',
      description: `Worker failed to detect planted canary mutation in section '${options.testedSection}'`,
    });
  }

  if (options.repeatedFalsePremise) {
    defects.push({
      code: 'R5',
      description: 'Worker repeated planted false premise (sycophancy test failed)',
    });
  }

  const passed = defects.length === 0;
  return {
    gate: 'G5',
    passed,
    defects,
    summary: passed ? 'Section passed G5 known-answer gate' : `Section failed G5: ${defects.map((d) => d.description).join('; ')}`,
  };
}

/**
 * G6: Independent Recheck Gate (Two-key rule executed by T14 Red for Critical and High)
 */
export function verifyG6IndependentRecheck(options: {
  findingId: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  originalEvidence: string;
  verifierVerdict: 'Confirmed' | 'Refuted' | 'Undecided';
  reproducedBySecondWorker: boolean;
}): GateResult {
  const defects: GateDefect[] = [];

  if (['CRITICAL', 'HIGH'].includes(options.severity)) {
    if (!options.reproducedBySecondWorker) {
      defects.push({
        code: 'R8',
        description: `Finding ${options.findingId} (${options.severity}) failed two-key rule: not reproduced by independent verifier`,
      });
    }

    if (options.verifierVerdict === 'Refuted') {
      defects.push({
        code: 'R8',
        description: `Independent verifier refuted finding ${options.findingId}`,
      });
    }
  }

  const passed = defects.length === 0;
  return {
    gate: 'G6',
    passed,
    defects,
    summary: passed
      ? `Finding ${options.findingId} passed G6 independent recheck`
      : `Finding ${options.findingId} failed G6: ${defects.map((d) => d.description).join('; ')}`,
  };
}

export interface G7ChecklistInput {
  allFindingsCiteOpenedFile: boolean;
  allNumbersAndVersionsSourced: boolean;
  scoringArithmeticRecomputed: boolean;
  allCriticalHighPassedG2ToG6: boolean;
  noHeldRowsInScore: boolean;
  coverageListsAllSkippedTeams: boolean;
  noRepoInstructionsObeyed: boolean;
  reportTextScannedCleanOfSecrets: boolean;
  reworkCountsRecorded: boolean;
}

/**
 * G7: CEO Final Gate (9-item checklist before report generation)
 */
export function verifyG7CeoFinal(checklist: G7ChecklistInput): GateResult {
  const defects: GateDefect[] = [];

  if (!checklist.allFindingsCiteOpenedFile) {
    defects.push({ code: 'R2', description: 'G7 Check 1 failed: Not all findings cite an opened file:line in this run' });
  }
  if (!checklist.allNumbersAndVersionsSourced) {
    defects.push({ code: 'R3', description: 'G7 Check 2 failed: Unverified numbers, CVEs, or versions without source' });
  }
  if (!checklist.scoringArithmeticRecomputed) {
    defects.push({ code: 'R1', description: 'G7 Check 3 failed: Scoring arithmetic not recomputed by script' });
  }
  if (!checklist.allCriticalHighPassedG2ToG6) {
    defects.push({ code: 'R8', description: 'G7 Check 4 failed: Critical or High findings missing G2-G6 verification' });
  }
  if (!checklist.noHeldRowsInScore) {
    defects.push({ code: 'R1', description: 'G7 Check 5 failed: HELD rows are included in the score' });
  }
  if (!checklist.coverageListsAllSkippedTeams) {
    defects.push({ code: 'R1', description: 'G7 Check 6 failed: Coverage section missing skipped teams or tools' });
  }
  if (!checklist.noRepoInstructionsObeyed) {
    defects.push({ code: 'R7', description: 'G7 Check 7 failed: Hostile repository instructions were obeyed' });
  }
  if (!checklist.reportTextScannedCleanOfSecrets) {
    defects.push({ code: 'R6', description: 'G7 Check 8 failed: Plaintext secrets found in report text' });
  }
  if (!checklist.reworkCountsRecorded) {
    defects.push({ code: 'R1', description: 'G7 Check 9 failed: Company record missing rework counts' });
  }

  const passed = defects.length === 0;
  return {
    gate: 'G7',
    passed,
    defects,
    summary: passed ? 'All 9 items of G7 CEO final gate passed' : `G7 final gate failed: ${defects.length} defects`,
  };
}

/**
 * State machine for the Rework Ladder (references/verification-loops.md)
 */
export function evaluateReworkLadder(
  defects: GateDefect[],
  currentRound: number
): {
  action: 'rework' | 'replace' | 'coverage_gap';
  nextRound: number;
  reworkDirectives?: string[];
  rejectionCodes: RejectionCode[];
} {
  const rejectionCodes = Array.from(new Set(defects.map((d) => d.code)));

  // R6 (Scope breach) and R7 (Hostile text obeyed) immediately replace worker
  if (rejectionCodes.includes('R6') || rejectionCodes.includes('R7')) {
    return {
      action: 'replace',
      nextRound: currentRound,
      rejectionCodes,
    };
  }

  if (currentRound === 0) {
    return {
      action: 'rework',
      nextRound: 1,
      reworkDirectives: defects.map((d) => `[${d.code}] ${d.claimId ? `${d.claimId}: ` : ''}${d.description}`),
      rejectionCodes,
    };
  }

  if (currentRound === 1) {
    return {
      action: 'rework',
      nextRound: 2,
      reworkDirectives: defects.map((d) => `[${d.code}] SECOND REWORK: ${d.claimId ? `${d.claimId}: ` : ''}${d.description}`),
      rejectionCodes,
    };
  }

  if (currentRound === 2) {
    return {
      action: 'replace',
      nextRound: currentRound + 1,
      rejectionCodes,
    };
  }

  return {
    action: 'coverage_gap',
    nextRound: currentRound + 1,
    rejectionCodes,
  };
}

/**
 * Formats gate logs into standardized gates.md markdown table
 */
export function formatGateLogMarkdown(entries: GateLogEntry[]): string {
  const lines = [
    '# Gates Log (O01 Fact Checker & CEO)',
    '',
    '| Return | Gate | Result | Defects (code, claim id) | Rework round | Date |',
    '|---|---|---|---|---|---|',
  ];

  for (const e of entries) {
    lines.push(`| ${e.returnId} | ${e.gate} | ${e.result} | ${e.defects || 'none'} | ${e.reworkRound} | ${e.date} |`);
  }

  return lines.join('\n');
}

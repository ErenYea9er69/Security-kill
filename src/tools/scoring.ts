export interface FindingScoreInput {
  id: string;
  team: string; // e.g. T02, T03
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  evidence: 'PROVEN' | 'TRACED' | 'LEAD' | 'DISPUTED';
  reach: 'anonymous' | 'authenticated' | 'privileged';
  asset: 'money_credentials_rce_db' | 'personal_data' | 'low_value';
  rootCauseGroup?: string;
  isReachableWithoutLogin?: boolean;
}

export interface SlopScoreInput {
  id: string;
  classId: string; // S01..S14
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  rootCauseGroup?: string;
}

export interface TeamWeight {
  id: string;
  name: string;
  weight: number;
}

export interface CoverageInput {
  completedSectionsWeight?: number;
  totalSectionsWeight?: number;
  resolvedHypotheses?: number;
  totalHypotheses?: number;
  passingTools?: number;
  totalApplicableTools?: number;
  verifiedCriticalHigh?: number;
  totalCriticalHigh?: number;
}

export interface ScoreCalculationOptions {
  findings: FindingScoreInput[];
  slopFindings?: SlopScoreInput[];
  activeTeams?: TeamWeight[];
  coverage?: CoverageInput;
  hasLiveCredential?: boolean;
}

export interface ScorePathStep {
  ifYouFix: string;
  scoreBecomes: number;
  whyItMoves: string;
}

export interface ScoreResult {
  overallScore: number;
  band: 'Hardened' | 'Solid' | 'Fair' | 'Weak' | 'Critical';
  status: 'Final' | 'Provisional' | 'Not rated';
  assurance: {
    score: number;
    level: 'High' | 'Medium' | 'Low' | 'Minimal';
    ceiling: number;
  };
  bindingCap: string | null;
  teamScores: Record<string, number>;
  penalties: Array<{
    id: string;
    team: string;
    base: number;
    evidence: number;
    reach: number;
    asset: number;
    penalty: number;
  }>;
  slopScore: number;
  pathToTarget: ScorePathStep[];
}

export const DEFAULT_TEAM_ROSTER: TeamWeight[] = [
  { id: 'T02', name: 'Identity', weight: 10 },
  { id: 'T03', name: 'Access', weight: 15 },
  { id: 'T04', name: 'Input', weight: 12 },
  { id: 'T05', name: 'Abuse', weight: 10 },
  { id: 'T06', name: 'Data', weight: 8 },
  { id: 'T07', name: 'Supply', weight: 8 },
  { id: 'T08', name: 'Infra', weight: 8 },
  { id: 'T09', name: 'Secrets', weight: 10 },
  { id: 'T10', name: 'AI', weight: 8 },
  { id: 'T11', name: 'Client', weight: 6 },
  { id: 'T12', name: 'Resilience', weight: 5 },
];

const SEVERITY_BASE: Record<string, number> = {
  CRITICAL: 5.0,
  HIGH: 2.5,
  MEDIUM: 1.0,
  LOW: 0.25,
};

const EVIDENCE_FACTORS: Record<string, number> = {
  PROVEN: 1.0,
  TRACED: 0.8,
  DISPUTED: 0.5,
  LEAD: 0.0,
};

const REACH_FACTORS: Record<string, number> = {
  anonymous: 1.0,
  authenticated: 0.8,
  privileged: 0.5,
};

const ASSET_FACTORS: Record<string, number> = {
  money_credentials_rce_db: 1.0,
  personal_data: 0.8,
  low_value: 0.5,
};

export function calculateFindingPenalty(f: FindingScoreInput): {
  base: number;
  evidence: number;
  reach: number;
  asset: number;
  penalty: number;
} {
  const base = SEVERITY_BASE[f.severity] || 0.25;
  const evidence = EVIDENCE_FACTORS[f.evidence] ?? 0.0;
  if (evidence === 0.0) {
    return { base, evidence, reach: 0, asset: 0, penalty: 0 };
  }
  const reach = REACH_FACTORS[f.reach] || 0.8;
  const asset = ASSET_FACTORS[f.asset] || 0.8;

  const raw = base * evidence * reach * asset;
  const penalty = Math.max(0.4 * base, raw);
  return { base, evidence, reach, asset, penalty };
}

/**
 * Calculates the security audit score out of 10 according to references/scoring.md.
 */
export function calculateSecurityScore(options: ScoreCalculationOptions): ScoreResult {
  const teams = options.activeTeams && options.activeTeams.length > 0 ? options.activeTeams : DEFAULT_TEAM_ROSTER;
  const teamMap = new Map<string, TeamWeight>(teams.map((t) => [t.id, t]));

  // Step 1: Penalty for each finding (ignore LEAD rows)
  const scoredFindings = options.findings.filter((f) => f.evidence !== 'LEAD');
  const penaltyDetails = scoredFindings.map((f) => ({
    id: f.id,
    team: f.team,
    ...calculateFindingPenalty(f),
  }));

  // Step 2: Team scores with root cause grouping
  const teamScores: Record<string, number> = {};
  for (const t of teams) {
    const teamFindings = scoredFindings.filter((f) => f.team === t.id);
    if (teamFindings.length === 0) {
      teamScores[t.id] = 10.0;
      continue;
    }

    // Group by root cause
    const groups: Record<string, number[]> = {};
    for (const f of teamFindings) {
      const gId = f.rootCauseGroup || f.id;
      if (!groups[gId]) groups[gId] = [];
      const pen = calculateFindingPenalty(f).penalty;
      groups[gId].push(pen);
    }

    let teamSum = 0;
    for (const groupPenalties of Object.values(groups)) {
      groupPenalties.sort((a, b) => b - a);
      const largest = groupPenalties[0];
      const siblings = groupPenalties.slice(1);
      teamSum += largest + siblings.reduce((sum, p) => sum + p * 0.25, 0);
    }

    const tScore = Math.max(0, 10.0 - teamSum);
    teamScores[t.id] = Math.round(tScore * 10) / 10;
  }

  // Step 3: Overall score blend
  let totalWeight = 0;
  let weightedSum = 0;
  for (const t of teams) {
    const s = teamScores[t.id] ?? 10.0;
    weightedSum += s * t.weight;
    totalWeight += t.weight;
  }
  const weighted = totalWeight > 0 ? weightedSum / totalWeight : 10.0;

  const sortedScores = Object.values(teamScores).sort((a, b) => a - b);
  const weak1 = sortedScores[0] ?? 10.0;
  const weak2 = sortedScores[1] ?? weak1;
  const weakLinks = (weak1 + weak2) / 2.0;

  const blended = 0.5 * weighted + 0.5 * weakLinks;

  // Step 4: Caps
  const caps: Array<{ cap: number; reason: string }> = [];
  if (options.hasLiveCredential) {
    caps.push({ cap: 3.0, reason: 'Live credential exposed in tree, history, or public bundle' });
  }

  for (const f of scoredFindings) {
    const reachAnon = f.reach === 'anonymous' || f.isReachableWithoutLogin === true;
    if (f.severity === 'CRITICAL' && f.evidence === 'PROVEN') {
      caps.push({ cap: 4.0, reason: `PROVEN Critical (${f.id})` });
    } else if (f.severity === 'CRITICAL' && f.evidence === 'TRACED') {
      caps.push({ cap: 5.0, reason: `TRACED Critical (${f.id})` });
    } else if (f.severity === 'HIGH' && reachAnon && (f.evidence === 'PROVEN' || f.evidence === 'TRACED')) {
      caps.push({ cap: 5.5, reason: `High reachable without login (${f.id})` });
    } else if (f.severity === 'HIGH' && !reachAnon && f.evidence === 'PROVEN') {
      caps.push({ cap: 6.5, reason: `PROVEN High reachable only after login (${f.id})` });
    } else if (f.severity === 'HIGH' && !reachAnon && f.evidence === 'TRACED') {
      caps.push({ cap: 7.5, reason: `TRACED High reachable only after login (${f.id})` });
    } else if (f.severity === 'MEDIUM') {
      caps.push({ cap: 8.9, reason: `Open Medium (${f.id})` });
    }
  }

  caps.push({ cap: 9.5, reason: 'Static analysis ceiling (never above 9.5)' });

  caps.sort((a, b) => a.cap - b.cap);
  const bindingCapObj = caps.length > 0 ? caps[0] : null;
  const bindingCapValue = bindingCapObj ? bindingCapObj.cap : 9.5;
  const bindingCapName = bindingCapObj && bindingCapObj.cap < 9.5 ? bindingCapObj.reason : null;

  // Step 5: Assurance and the ceiling
  const cov = options.coverage || {};
  const C = cov.totalSectionsWeight ? (cov.completedSectionsWeight ?? cov.totalSectionsWeight) / cov.totalSectionsWeight : 1.0;
  const P = cov.totalHypotheses ? (cov.resolvedHypotheses ?? cov.totalHypotheses) / cov.totalHypotheses : 1.0;
  const T = cov.totalApplicableTools ? (cov.passingTools ?? cov.totalApplicableTools) / cov.totalApplicableTools : 1.0;
  const V = cov.totalCriticalHigh ? (cov.verifiedCriticalHigh ?? cov.totalCriticalHigh) / cov.totalCriticalHigh : 1.0;

  const assuranceNumber = Math.round(100 * (0.5 * C + 0.2 * P + 0.15 * T + 0.15 * V));

  let assuranceLevel: 'High' | 'Medium' | 'Low' | 'Minimal' = 'High';
  let assuranceCeiling = 9.5;
  let status: 'Final' | 'Provisional' | 'Not rated' = 'Final';

  if (assuranceNumber >= 80) {
    assuranceLevel = 'High';
    assuranceCeiling = 9.5;
    status = 'Final';
  } else if (assuranceNumber >= 55) {
    assuranceLevel = 'Medium';
    assuranceCeiling = 8.5;
    status = 'Final';
  } else if (assuranceNumber >= 30) {
    assuranceLevel = 'Low';
    assuranceCeiling = 7.0;
    status = 'Provisional';
  } else {
    assuranceLevel = 'Minimal';
    assuranceCeiling = 0.0;
    status = 'Not rated';
  }

  // Final overall score is the lowest of blended, caps, and ceiling
  let finalScore = Math.min(blended, bindingCapValue, assuranceCeiling);
  finalScore = Math.round(finalScore * 10) / 10;
  if (status === 'Not rated') {
    finalScore = 0.0;
  }

  // Step 6: Grade bands
  let band: 'Hardened' | 'Solid' | 'Fair' | 'Weak' | 'Critical' = 'Critical';
  if (finalScore >= 9.0 && assuranceLevel === 'High') {
    band = 'Hardened';
  } else if (finalScore >= 7.5) {
    band = 'Solid';
  } else if (finalScore >= 6.0) {
    band = 'Fair';
  } else if (finalScore >= 4.0) {
    band = 'Weak';
  } else {
    band = 'Critical';
  }

  // Slop Score
  let slopScore = 10.0;
  if (options.slopFindings && options.slopFindings.length > 0) {
    const slopGroups: Record<string, number[]> = {};
    for (const sf of options.slopFindings) {
      const g = sf.rootCauseGroup || sf.id;
      if (!slopGroups[g]) slopGroups[g] = [];
      const pen = sf.severity === 'HIGH' ? 1.0 : sf.severity === 'MEDIUM' ? 0.4 : 0.1;
      slopGroups[g].push(pen);
    }
    let slopPenSum = 0;
    for (const pList of Object.values(slopGroups)) {
      pList.sort((a, b) => b - a);
      slopPenSum += pList[0] + pList.slice(1).reduce((s, p) => s + p * 0.25, 0);
    }
    slopScore = Math.max(0, Math.round((10.0 - slopPenSum) * 10) / 10);
  }

  // Path to Target Score
  const pathToTarget: ScorePathStep[] = [];
  pathToTarget.push({
    ifYouFix: 'Nothing (Current status)',
    scoreBecomes: finalScore,
    whyItMoves: bindingCapName || 'Blended team scores and assurance ceiling',
  });

  if (scoredFindings.length > 0) {
    // Sort findings by severity order
    const severityOrder: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
    const sorted = [...scoredFindings].sort((a, b) => (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0));

    // Fix criticals
    const criticals = sorted.filter((f) => f.severity === 'CRITICAL');
    if (criticals.length > 0) {
      const remaining = sorted.filter((f) => f.severity !== 'CRITICAL');
      const sim = calculateSecurityScore({
        ...options,
        findings: remaining,
        hasLiveCredential: false,
      });
      pathToTarget.push({
        ifYouFix: `All Criticals (${criticals.map((c) => c.id).join(', ')})`,
        scoreBecomes: sim.overallScore,
        whyItMoves: sim.bindingCap || 'Next highest severity cap',
      });
    }

    // Fix Highs & Criticals
    const highs = sorted.filter((f) => f.severity === 'HIGH');
    if (highs.length > 0) {
      const remaining = sorted.filter((f) => f.severity !== 'CRITICAL' && f.severity !== 'HIGH');
      const sim = calculateSecurityScore({
        ...options,
        findings: remaining,
        hasLiveCredential: false,
      });
      pathToTarget.push({
        ifYouFix: 'All Critical and High findings',
        scoreBecomes: sim.overallScore,
        whyItMoves: sim.bindingCap || 'Open Medium findings cap',
      });
    }

    // Fix Mediums and above
    const meds = sorted.filter((f) => f.severity === 'MEDIUM');
    if (meds.length > 0) {
      const remaining = sorted.filter((f) => f.severity === 'LOW');
      const sim = calculateSecurityScore({
        ...options,
        findings: remaining,
        hasLiveCredential: false,
      });
      pathToTarget.push({
        ifYouFix: 'All Medium and above findings',
        scoreBecomes: sim.overallScore,
        whyItMoves: 'Assurance ceiling',
      });
    }
  }

  return {
    overallScore: finalScore,
    band,
    status,
    assurance: {
      score: assuranceNumber,
      level: assuranceLevel,
      ceiling: assuranceCeiling,
    },
    bindingCap: bindingCapName,
    teamScores,
    penalties: penaltyDetails,
    slopScore,
    pathToTarget,
  };
}

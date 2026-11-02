import { orchestrateAudit, AuditOrchestrateOptions } from './tools/orchestrator.js';

export interface AuditPromptArgs {
  target_path?: string;
  mode?: string;
  compliance?: boolean;
  diff?: boolean;
  depth?: 'quick' | 'standard' | 'deep';
  domain?: string;
  teams?: string;
}

export async function generateAuditPromptContent(args: AuditPromptArgs) {
  const options: AuditOrchestrateOptions = {
    targetPath: args.target_path || '.',
    mode: args.mode || 'full',
    depth: args.depth || 'standard',
    domain: args.domain,
    teams: args.teams,
    compliance: args.compliance,
    diff: args.diff,
  };

  const plan = await orchestrateAudit(options);

  return {
    messages: [
      {
        role: 'user' as const,
        content: {
          type: 'text' as const,
          text: plan.directive,
        },
      },
    ],
  };
}

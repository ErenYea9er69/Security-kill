import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  listReferences,
  getReferenceContent,
  getSkillContent,
  getAllReferenceResources,
} from '../src/resources.js';

describe('MCP Resources & References Loader', () => {
  it('should list all 23 reference names', () => {
    const refs = listReferences();
    assert.strictEqual(refs.length, 23);
    assert.ok(refs.includes('preflight'));
    assert.ok(refs.includes('sast-secrets'));
    assert.ok(refs.includes('vibecoding-checklist'));
    assert.ok(refs.includes('attacker-simulation'));
    assert.ok(refs.includes('baas-supabase-firebase'));
    assert.ok(refs.includes('llm-app-security'));
    assert.ok(refs.includes('teams'));
    assert.ok(refs.includes('scoring'));
    assert.ok(refs.includes('slop-detection'));
    assert.ok(refs.includes('project-profiling'));
    assert.ok(refs.includes('stack-packs'));
    assert.ok(refs.includes('report-template'));
  });

  it('should load content for an existing reference', () => {
    const content = getReferenceContent('preflight');
    assert.ok(content !== null);
    assert.match(content!, /Preflight: Canary Verification/);
  });

  it('should return null for non-existent reference', () => {
    const content = getReferenceContent('does-not-exist');
    assert.strictEqual(content, null);
  });

  it('should load SKILL.md content', () => {
    const skill = getSkillContent();
    assert.ok(skill !== null);
    assert.match(skill!, /# Security Kill/);
  });

  it('should produce valid MCP resource descriptors', () => {
    const resources = getAllReferenceResources();
    assert.strictEqual(resources.length, 24); // 23 references + 1 core skill

    const skillRes = resources.find((r) => r.uri === 'security-kill://skill');
    assert.ok(skillRes);
    assert.strictEqual(skillRes.mimeType, 'text/markdown');

    const teamsRes = resources.find((r) => r.uri === 'security-kill://reference/teams');
    assert.ok(teamsRes);
    assert.strictEqual(teamsRes.name, 'teams');
    assert.strictEqual(teamsRes.mimeType, 'text/markdown');

    const scoringRes = resources.find((r) => r.uri === 'security-kill://reference/scoring');
    assert.ok(scoringRes);
    assert.strictEqual(scoringRes.name, 'scoring');
    assert.strictEqual(scoringRes.mimeType, 'text/markdown');
  });
});

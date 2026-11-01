import { describe, it } from 'node:test';
import assert from 'node:assert';
import {
  listReferences,
  getReferenceContent,
  getSkillContent,
  getAllReferenceResources,
} from '../src/resources.js';

describe('MCP Resources & References Loader', () => {
  it('should list all 17 reference names', () => {
    const refs = listReferences();
    assert.strictEqual(refs.length, 17);
    assert.ok(refs.includes('preflight'));
    assert.ok(refs.includes('sast-secrets'));
    assert.ok(refs.includes('vibecoding-checklist'));
    assert.ok(refs.includes('attacker-simulation'));
    assert.ok(refs.includes('baas-supabase-firebase'));
    assert.ok(refs.includes('llm-app-security'));
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
    assert.match(skill!, /# Security Audit/);
  });

  it('should produce valid MCP resource descriptors', () => {
    const resources = getAllReferenceResources();
    assert.strictEqual(resources.length, 18); // 17 references + 1 core skill

    const skillRes = resources.find((r) => r.uri === 'security://skill');
    assert.ok(skillRes);
    assert.strictEqual(skillRes.mimeType, 'text/markdown');

    const preflightRes = resources.find((r) => r.uri === 'security://reference/preflight');
    assert.ok(preflightRes);
    assert.strictEqual(preflightRes.name, 'preflight');
    assert.strictEqual(preflightRes.mimeType, 'text/markdown');
  });
});

